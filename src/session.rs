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
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub email: String,
    pub oidc_sub: String,
    pub imap_password_enc: String,
    pub imap_password_iv: String,
}

/// Session data stored in Redis, keyed by mcp_token.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub email: String,
    pub oidc_sub: String,
    pub imap_password_enc: String,
    pub imap_password_iv: String,
    pub created_at: i64,
}

/// Manages sessions and auth state in Redis with AES-256-GCM encryption.
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

    pub async fn create_session(
        &self,
        email: &str,
        oidc_sub: &str,
        imap_password: &str,
    ) -> Result<String, AppError> {
        let (enc, iv) = self.encrypt(imap_password)?;
        let mcp_token = uuid::Uuid::new_v4().to_string();
        let session = Session {
            email: email.to_string(),
            oidc_sub: oidc_sub.to_string(),
            imap_password_enc: enc,
            imap_password_iv: iv,
            created_at: chrono::Utc::now().timestamp(),
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

    pub fn decrypt_imap_password(&self, session: &Session) -> Result<String, AppError> {
        self.decrypt(&session.imap_password_enc, &session.imap_password_iv)
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
            email: "user@example.com".to_string(),
            oidc_sub: "12345".to_string(),
            imap_password_enc: "encrypted".to_string(),
            imap_password_iv: "nonce".to_string(),
            created_at: 1700000000,
        };
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.email, "user@example.com");
        assert_eq!(deserialized.oidc_sub, "12345");
        assert_eq!(deserialized.created_at, 1700000000);
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
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: AuthFlowState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.oauth_client_id, "client123");
        assert_eq!(deserialized.pkce_verifier, "verifier123");
    }

    #[test]
    fn decrypt_imap_password_works() {
        let store = test_store();
        let (enc, iv) = store.encrypt("my-imap-password").unwrap();
        let session = Session {
            email: "test@example.com".to_string(),
            oidc_sub: "sub".to_string(),
            imap_password_enc: enc,
            imap_password_iv: iv,
            created_at: 0,
        };
        let decrypted = store.decrypt_imap_password(&session).unwrap();
        assert_eq!(decrypted, "my-imap-password");
    }
}
