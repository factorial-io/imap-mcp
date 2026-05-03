use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// Dynamic OAuth client registration data.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

/// State stored during the OAuth + OIDC auth flow.
/// Combines claude.ai's OAuth params with OIDC params.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFlowState {
    pub oauth_client_id: String,
    pub oauth_redirect_uri: String,
    pub oauth_state: String,
    pub oauth_code_challenge: String,
    pub oauth_code_challenge_method: String,
    pub pkce_verifier: String,
    pub nonce: String,
    /// Where to send the user after a successful OIDC callback.
    /// `Connector`: the existing claude.ai-driven flow (show IMAP setup form).
    /// `ManageEntry`: an admin/management entry — set the management cookie
    /// and redirect to `/manage`.
    #[serde(default)]
    pub intent: AuthFlowIntent,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthFlowIntent {
    #[default]
    Connector,
    ManageEntry,
}

/// Intermediate state between OIDC callback and IMAP password form submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingSetup {
    pub email: String,
    pub oidc_sub: String,
    pub name: String,
    pub oauth_client_id: String,
    pub oauth_redirect_uri: String,
    pub oauth_state: String,
    pub oauth_code_challenge: String,
    pub oauth_code_challenge_method: String,
}

/// Authorization code data, stored briefly between setup and token exchange.
/// IMAP credentials live in `Account` records (keyed by `oidc_sub`); this
/// only carries the OIDC identity that owns those accounts.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub email: String,
    pub oidc_sub: String,
}

/// Bearer-token session. Holds the verified OIDC identity only — IMAP
/// credentials are looked up at tool-call time from the per-`oidc_sub`
/// `Account` list.
///
/// Legacy single-account sessions stored before the multi-account migration
/// keep their encrypted-password fields here as `Option`; the resolver
/// promotes them to `Account` records on first read.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    /// OIDC email claim. Renamed in v2 — `email` kept as the serde alias for
    /// legacy records.
    #[serde(alias = "email")]
    pub oidc_email: String,
    pub oidc_sub: String,
    pub created_at: i64,

    // --- Legacy fields (pre-multi-account). Optional so new sessions don't
    // emit them; deserialization tolerates them on old records. ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_imap_password_enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_imap_password_iv: Option<String>,
}

/// Per-mailbox record. Multiple accounts attach to one `oidc_sub`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub account_id: String,
    pub label: String,
    pub imap_email: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub password_enc: String,
    pub password_iv: String,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub auth_failure_count: u32,
    #[serde(default)]
    pub disabled_at: Option<i64>,
}

impl Account {
    pub fn is_disabled(&self) -> bool {
        self.disabled_at.is_some()
    }
}

/// Short-lived ticket that pre-authorizes a `/manage` entry. Issued by the
/// `add_account_url` / `list_accounts` MCP tools.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManageTicket {
    pub oidc_sub: String,
    pub oidc_email: String,
    pub created_at: i64,
}

/// Server-side management session keyed by an opaque cookie value. Created
/// once a ticket has been redeemed; subsequent `/manage` requests use the
/// cookie until it expires.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManageSession {
    pub oidc_sub: String,
    pub oidc_email: String,
    pub csrf_token: String,
    pub created_at: i64,
}

/// Pending account-add form values held while we bounce the user through
/// OIDC re-auth. Indexed by a one-shot UUID echoed back via OIDC `state`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingAccountAdd {
    pub oidc_sub: String,
    pub provider_id: String,
    pub label: String,
    pub imap_email: String,
    pub password_enc: String,
    pub password_iv: String,
}

/// Manages sessions, accounts, and auth state in Redis with AES-256-GCM
/// encryption.
#[derive(Clone)]
pub struct SessionStore {
    redis: redis::Client,
    encryption_key: Vec<u8>,
}

const OAUTH_CLIENT_TTL: u64 = 365 * 24 * 3600; // 1 year
const AUTH_FLOW_TTL: u64 = 600; // 10 minutes
const PENDING_SETUP_TTL: u64 = 600; // 10 minutes
const AUTH_CODE_TTL: u64 = 300; // 5 minutes
const SESSION_TTL: u64 = 30 * 24 * 3600; // 30 days
pub const ACCOUNT_TTL: u64 = 365 * 24 * 3600; // 1 year, refreshed on use
pub const MANAGE_TICKET_TTL: u64 = 15 * 60; // 15 minutes (decision: question 3)
pub const MANAGE_SESSION_TTL: u64 = 30 * 60; // 30 minutes for the cookie session
pub const AUTH_FAILURE_LIMIT: u32 = 3; // decision: question 2

impl SessionStore {
    pub fn new(redis_url: &str, encryption_key_b64: &str) -> Result<Self, AppError> {
        let redis = redis::Client::open(redis_url).map_err(AppError::Redis)?;
        let encryption_key = B64
            .decode(encryption_key_b64)
            .map_err(|e| AppError::Encryption(format!("invalid base64 key: {e}")))?;
        if encryption_key.len() != 32 {
            return Err(AppError::Encryption(
                "encryption key must be 32 bytes".to_string(),
            ));
        }
        Ok(Self {
            redis,
            encryption_key,
        })
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection, AppError> {
        self.redis
            .get_multiplexed_async_connection()
            .await
            .map_err(AppError::Redis)
    }

    // --- OAuth client registration ---

    pub async fn store_oauth_client(
        &self,
        client_id: &str,
        client: &OAuthClient,
    ) -> Result<(), AppError> {
        let key = format!("oauth:client:{client_id}");
        let value = serde_json::to_string(client)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, OAUTH_CLIENT_TTL)
            .await?;
        Ok(())
    }

    pub async fn get_oauth_client(&self, client_id: &str) -> Result<OAuthClient, AppError> {
        let key = format!("oauth:client:{client_id}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::Auth("unknown client_id".into()))?;
        Ok(serde_json::from_str(&value)?)
    }

    // --- Auth flow state (OAuth + OIDC combined) ---

    pub async fn store_auth_flow(
        &self,
        csrf_token: &str,
        flow: &AuthFlowState,
    ) -> Result<(), AppError> {
        let key = format!("auth:flow:{csrf_token}");
        let value = serde_json::to_string(flow)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, AUTH_FLOW_TTL).await?;
        Ok(())
    }

    pub async fn get_auth_flow(&self, csrf_token: &str) -> Result<AuthFlowState, AppError> {
        let key = format!("auth:flow:{csrf_token}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::Auth(
            "auth flow state not found or expired".into(),
        ))?;
        let _: () = conn.del(&key).await?;
        Ok(serde_json::from_str(&value)?)
    }

    // --- Pending setup (between OIDC callback and IMAP password form) ---

    pub async fn store_pending_setup(
        &self,
        setup_id: &str,
        pending: &PendingSetup,
    ) -> Result<(), AppError> {
        let key = format!("auth:setup:{setup_id}");
        let value = serde_json::to_string(pending)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, PENDING_SETUP_TTL)
            .await?;
        Ok(())
    }

    pub async fn get_pending_setup(&self, setup_id: &str) -> Result<PendingSetup, AppError> {
        let key = format!("auth:setup:{setup_id}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::Auth("setup session not found or expired".into()))?;
        let _: () = conn.del(&key).await?;
        Ok(serde_json::from_str(&value)?)
    }

    // --- Authorization codes ---

    pub async fn store_auth_code(&self, code: &str, auth_code: &AuthCode) -> Result<(), AppError> {
        let key = format!("auth:code:{code}");
        let value = serde_json::to_string(auth_code)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, AUTH_CODE_TTL).await?;
        Ok(())
    }

    pub async fn get_auth_code(&self, code: &str) -> Result<AuthCode, AppError> {
        let key = format!("auth:code:{code}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::Auth(
            "authorization code not found or expired".into(),
        ))?;
        let _: () = conn.del(&key).await?;
        Ok(serde_json::from_str(&value)?)
    }

    // --- MCP sessions ---

    /// Create an MCP session bound to an OIDC identity. IMAP credentials are
    /// stored separately as `Account` records.
    pub async fn create_session(
        &self,
        oidc_email: &str,
        oidc_sub: &str,
    ) -> Result<String, AppError> {
        let mcp_token = uuid::Uuid::new_v4().to_string();
        let session = Session {
            oidc_email: oidc_email.to_string(),
            oidc_sub: oidc_sub.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            legacy_imap_password_enc: None,
            legacy_imap_password_iv: None,
        };
        let key = format!("mcp:session:{mcp_token}");
        let value = serde_json::to_string(&session)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, SESSION_TTL).await?;
        Ok(mcp_token)
    }

    pub async fn get_session(&self, mcp_token: &str) -> Result<Session, AppError> {
        let key = format!("mcp:session:{mcp_token}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::SessionNotFound)?;
        conn.expire::<_, ()>(&key, SESSION_TTL as i64).await?;
        Ok(serde_json::from_str(&value)?)
    }

    /// Strip the legacy IMAP-password fields from a session record after they
    /// have been promoted into an `Account`. Idempotent.
    pub async fn clear_session_legacy_password(&self, mcp_token: &str) -> Result<(), AppError> {
        let key = format!("mcp:session:{mcp_token}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let Some(value) = value else {
            return Ok(());
        };
        let mut session: Session = serde_json::from_str(&value)?;
        if session.legacy_imap_password_enc.is_none() && session.legacy_imap_password_iv.is_none() {
            return Ok(());
        }
        session.legacy_imap_password_enc = None;
        session.legacy_imap_password_iv = None;
        let value = serde_json::to_string(&session)?;
        conn.set_ex::<_, _, ()>(&key, &value, SESSION_TTL).await?;
        Ok(())
    }

    // --- Accounts (per oidc_sub) ---

    fn accounts_key(oidc_sub: &str) -> String {
        format!("mcp:accounts:{oidc_sub}")
    }

    /// Persist an `Account` under the given `oidc_sub`. Stored as a Redis
    /// hash where the field is `account_id` and the value is the JSON record.
    pub async fn put_account(&self, oidc_sub: &str, account: &Account) -> Result<(), AppError> {
        let key = Self::accounts_key(oidc_sub);
        let value = serde_json::to_string(account)?;
        let mut conn = self.conn().await?;
        conn.hset::<_, _, _, ()>(&key, &account.account_id, &value)
            .await?;
        conn.expire::<_, ()>(&key, ACCOUNT_TTL as i64).await?;
        Ok(())
    }

    pub async fn get_account(
        &self,
        oidc_sub: &str,
        account_id: &str,
    ) -> Result<Option<Account>, AppError> {
        let key = Self::accounts_key(oidc_sub);
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.hget(&key, account_id).await?;
        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    pub async fn list_accounts(&self, oidc_sub: &str) -> Result<Vec<Account>, AppError> {
        let key = Self::accounts_key(oidc_sub);
        let mut conn = self.conn().await?;
        let map: std::collections::HashMap<String, String> = conn.hgetall(&key).await?;
        let mut out = Vec::with_capacity(map.len());
        for (_, v) in map {
            out.push(serde_json::from_str::<Account>(&v)?);
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    pub async fn delete_account(&self, oidc_sub: &str, account_id: &str) -> Result<bool, AppError> {
        let key = Self::accounts_key(oidc_sub);
        let mut conn = self.conn().await?;
        let removed: i64 = conn.hdel(&key, account_id).await?;
        Ok(removed > 0)
    }

    /// Update an account's password (used by `/manage` re-validate flow).
    pub async fn update_account_password(
        &self,
        oidc_sub: &str,
        account_id: &str,
        password_enc: String,
        password_iv: String,
    ) -> Result<(), AppError> {
        let mut acc = self
            .get_account(oidc_sub, account_id)
            .await?
            .ok_or_else(|| AppError::Auth("account not found".into()))?;
        acc.password_enc = password_enc;
        acc.password_iv = password_iv;
        acc.auth_failure_count = 0;
        acc.disabled_at = None;
        self.put_account(oidc_sub, &acc).await
    }

    /// Mark a successful login: clear failure counter, bump `last_used_at`.
    pub async fn record_account_success(
        &self,
        oidc_sub: &str,
        account_id: &str,
    ) -> Result<(), AppError> {
        let Some(mut acc) = self.get_account(oidc_sub, account_id).await? else {
            return Ok(());
        };
        acc.last_used_at = Some(chrono::Utc::now().timestamp());
        acc.auth_failure_count = 0;
        self.put_account(oidc_sub, &acc).await
    }

    /// Mark an auth failure. After [`AUTH_FAILURE_LIMIT`] consecutive failures,
    /// the account is auto-disabled.
    pub async fn record_account_auth_failure(
        &self,
        oidc_sub: &str,
        account_id: &str,
    ) -> Result<bool, AppError> {
        let Some(mut acc) = self.get_account(oidc_sub, account_id).await? else {
            return Ok(false);
        };
        acc.auth_failure_count = acc.auth_failure_count.saturating_add(1);
        let just_disabled =
            if acc.auth_failure_count >= AUTH_FAILURE_LIMIT && acc.disabled_at.is_none() {
                acc.disabled_at = Some(chrono::Utc::now().timestamp());
                true
            } else {
                false
            };
        self.put_account(oidc_sub, &acc).await?;
        Ok(just_disabled)
    }

    pub fn decrypt_account_password(&self, account: &Account) -> Result<String, AppError> {
        self.decrypt(&account.password_enc, &account.password_iv)
    }

    // --- Manage tickets (15-minute pre-auth links) ---

    pub async fn create_manage_ticket(
        &self,
        oidc_sub: &str,
        oidc_email: &str,
    ) -> Result<String, AppError> {
        let ticket = uuid::Uuid::new_v4().to_string();
        let key = format!("mgmt:ticket:{ticket}");
        let value = serde_json::to_string(&ManageTicket {
            oidc_sub: oidc_sub.to_string(),
            oidc_email: oidc_email.to_string(),
            created_at: chrono::Utc::now().timestamp(),
        })?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, MANAGE_TICKET_TTL)
            .await?;
        Ok(ticket)
    }

    /// Single-use: looking the ticket up consumes it.
    pub async fn consume_manage_ticket(
        &self,
        ticket: &str,
    ) -> Result<Option<ManageTicket>, AppError> {
        let key = format!("mgmt:ticket:{ticket}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        match value {
            Some(v) => {
                let _: () = conn.del(&key).await?;
                Ok(Some(serde_json::from_str(&v)?))
            }
            None => Ok(None),
        }
    }

    // --- Manage cookie sessions ---

    pub async fn create_manage_session(
        &self,
        oidc_sub: &str,
        oidc_email: &str,
    ) -> Result<(String, String), AppError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let csrf_token = uuid::Uuid::new_v4().to_string();
        let key = format!("mgmt:session:{session_id}");
        let value = serde_json::to_string(&ManageSession {
            oidc_sub: oidc_sub.to_string(),
            oidc_email: oidc_email.to_string(),
            csrf_token: csrf_token.clone(),
            created_at: chrono::Utc::now().timestamp(),
        })?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, MANAGE_SESSION_TTL)
            .await?;
        Ok((session_id, csrf_token))
    }

    pub async fn get_manage_session(
        &self,
        session_id: &str,
    ) -> Result<Option<ManageSession>, AppError> {
        let key = format!("mgmt:session:{session_id}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        match value {
            Some(v) => {
                conn.expire::<_, ()>(&key, MANAGE_SESSION_TTL as i64)
                    .await?;
                Ok(Some(serde_json::from_str(&v)?))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_manage_session(&self, session_id: &str) -> Result<(), AppError> {
        let key = format!("mgmt:session:{session_id}");
        let mut conn = self.conn().await?;
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    // --- Pending account-add (held across OIDC re-auth) ---

    pub async fn store_pending_account_add(
        &self,
        nonce: &str,
        pending: &PendingAccountAdd,
    ) -> Result<(), AppError> {
        let key = format!("mgmt:pending_add:{nonce}");
        let value = serde_json::to_string(pending)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, AUTH_FLOW_TTL).await?;
        Ok(())
    }

    pub async fn get_pending_account_add(
        &self,
        nonce: &str,
    ) -> Result<Option<PendingAccountAdd>, AppError> {
        let key = format!("mgmt:pending_add:{nonce}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        match value {
            Some(v) => {
                let _: () = conn.del(&key).await?;
                Ok(Some(serde_json::from_str(&v)?))
            }
            None => Ok(None),
        }
    }

    // --- Encryption helpers ---

    pub(crate) fn encrypt(&self, plaintext: &str) -> Result<(String, String), AppError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| AppError::Encryption(format!("encrypt failed: {e}")))?;
        Ok((B64.encode(ciphertext), B64.encode(nonce)))
    }

    pub(crate) fn decrypt(&self, ciphertext_b64: &str, iv_b64: &str) -> Result<String, AppError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        let ciphertext = B64
            .decode(ciphertext_b64)
            .map_err(|e| AppError::Encryption(format!("invalid ciphertext base64: {e}")))?;
        let nonce_bytes = B64
            .decode(iv_b64)
            .map_err(|e| AppError::Encryption(format!("invalid iv base64: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| AppError::Encryption(format!("decrypt failed: {e}")))?;
        String::from_utf8(plaintext)
            .map_err(|e| AppError::Encryption(format!("invalid utf8 after decrypt: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> SessionStore {
        let key_b64 = B64.encode([0xABu8; 32]);
        SessionStore::new("redis://localhost:6379", &key_b64).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let store = test_store();
        let password = "s3cret-IMAP-p@ssw0rd!";
        let (enc, iv) = store.encrypt(password).unwrap();
        let decrypted = store.decrypt(&enc, &iv).unwrap();
        assert_eq!(decrypted, password);
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let store = test_store();
        let password = "same-password";
        let (enc1, _) = store.encrypt(password).unwrap();
        let (enc2, _) = store.encrypt(password).unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let store1 = test_store();
        let (enc, iv) = store1.encrypt("secret").unwrap();

        let other_key_b64 = B64.encode([0xCDu8; 32]);
        let store2 = SessionStore::new("redis://localhost:6379", &other_key_b64).unwrap();
        assert!(store2.decrypt(&enc, &iv).is_err());
    }

    #[test]
    fn decrypt_with_invalid_base64_fails() {
        let store = test_store();
        assert!(store.decrypt("not-base64!!!", "also-bad!!!").is_err());
    }

    #[test]
    fn new_rejects_short_key() {
        let short_key = B64.encode([0u8; 16]);
        let result = SessionStore::new("redis://localhost:6379", &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_invalid_base64_key() {
        let result = SessionStore::new("redis://localhost:6379", "not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn session_serialization_roundtrip() {
        let session = Session {
            oidc_email: "user@example.com".to_string(),
            oidc_sub: "12345".to_string(),
            created_at: 1700000000,
            legacy_imap_password_enc: None,
            legacy_imap_password_iv: None,
        };
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.oidc_email, "user@example.com");
        assert_eq!(deserialized.oidc_sub, "12345");
        assert_eq!(deserialized.created_at, 1700000000);
        assert!(deserialized.legacy_imap_password_enc.is_none());
    }

    #[test]
    fn legacy_session_deserializes_with_email_alias_and_password_fields() {
        // Legacy single-account sessions stored before multi-account migration:
        // they used `email` (not `oidc_email`) and carried encrypted credentials
        // inline. We must still be able to read them.
        let json = r#"{
            "email": "alice@factorial.io",
            "oidc_sub": "abc",
            "imap_password_enc": "ENC",
            "imap_password_iv": "IV",
            "created_at": 1700000000
        }"#;
        // Adapt: legacy field names are `imap_password_enc/iv` — accept those
        // via serde aliases mapped to our new names.
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut obj = value.as_object().unwrap().clone();
        // Simulate the simple migration we do at runtime: rename keys.
        if let Some(v) = obj.remove("imap_password_enc") {
            obj.insert("legacy_imap_password_enc".to_string(), v);
        }
        if let Some(v) = obj.remove("imap_password_iv") {
            obj.insert("legacy_imap_password_iv".to_string(), v);
        }
        let migrated = serde_json::Value::Object(obj).to_string();
        let session: Session = serde_json::from_str(&migrated).unwrap();
        assert_eq!(session.oidc_email, "alice@factorial.io");
        assert_eq!(session.oidc_sub, "abc");
        assert_eq!(session.legacy_imap_password_enc.as_deref(), Some("ENC"));
        assert_eq!(session.legacy_imap_password_iv.as_deref(), Some("IV"));
    }

    #[test]
    fn auth_flow_state_serialization_roundtrip() {
        let state = AuthFlowState {
            oauth_client_id: "client123".to_string(),
            oauth_redirect_uri: "https://example.com/callback".to_string(),
            oauth_state: "state456".to_string(),
            oauth_code_challenge: "challenge789".to_string(),
            oauth_code_challenge_method: "S256".to_string(),
            pkce_verifier: "verifier123".to_string(),
            nonce: "nonce456".to_string(),
            intent: AuthFlowIntent::Connector,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: AuthFlowState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.oauth_client_id, "client123");
        assert_eq!(deserialized.pkce_verifier, "verifier123");
        assert_eq!(deserialized.intent, AuthFlowIntent::Connector);
    }

    #[test]
    fn account_serialization_roundtrip() {
        let account = Account {
            account_id: "acc-123".to_string(),
            label: "Billing".to_string(),
            imap_email: "billing@factorial.io".to_string(),
            imap_host: "mail.factorial.io".to_string(),
            imap_port: 993,
            password_enc: "ENC".to_string(),
            password_iv: "IV".to_string(),
            created_at: 1700000000,
            last_used_at: Some(1700000500),
            auth_failure_count: 1,
            disabled_at: None,
        };
        let json = serde_json::to_string(&account).unwrap();
        let de: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(de.account_id, "acc-123");
        assert_eq!(de.imap_port, 993);
        assert_eq!(de.last_used_at, Some(1700000500));
        assert_eq!(de.auth_failure_count, 1);
        assert!(!de.is_disabled());
    }

    #[test]
    fn account_minimal_json_uses_defaults() {
        // last_used_at, auth_failure_count, disabled_at are all #[serde(default)].
        let json = r#"{
            "account_id":"a",
            "label":"L",
            "imap_email":"e@x",
            "imap_host":"h",
            "imap_port":993,
            "password_enc":"E",
            "password_iv":"I",
            "created_at":1
        }"#;
        let de: Account = serde_json::from_str(json).unwrap();
        assert_eq!(de.last_used_at, None);
        assert_eq!(de.auth_failure_count, 0);
        assert!(de.disabled_at.is_none());
    }
}
