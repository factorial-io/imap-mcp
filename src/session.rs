use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// OIDC state stored temporarily during the auth flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcState {
    pub pkce_verifier: String,
    pub nonce: String,
}

/// Session data stored in Redis, keyed by mcp_token.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub email: String,
    pub gitlab_sub: String,
    pub imap_password_enc: String,
    pub imap_password_iv: String,
    pub created_at: i64,
}

/// Manages sessions and OIDC state in Redis with AES-256-GCM encryption.
#[derive(Clone)]
pub struct SessionStore {
    redis: redis::Client,
    encryption_key: Vec<u8>,
}

const OIDC_STATE_TTL: u64 = 600; // 10 minutes
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

    // --- OIDC state ---

    pub async fn store_oidc_state(
        &self,
        state_token: &str,
        oidc_state: &OidcState,
    ) -> Result<(), AppError> {
        let key = format!("oidc:state:{state_token}");
        let value = serde_json::to_string(oidc_state)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(&key, &value, OIDC_STATE_TTL).await?;
        Ok(())
    }

    pub async fn get_oidc_state(&self, state_token: &str) -> Result<OidcState, AppError> {
        let key = format!("oidc:state:{state_token}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::Auth("OIDC state not found or expired".into()))?;
        // Delete after retrieval to prevent replay
        let _: () = conn.del(&key).await?;
        Ok(serde_json::from_str(&value)?)
    }

    // --- MCP sessions ---

    /// Encrypt the IMAP password and store a new session. Returns the mcp_token.
    pub async fn create_session(
        &self,
        email: &str,
        gitlab_sub: &str,
        imap_password: &str,
    ) -> Result<String, AppError> {
        let (enc, iv) = self.encrypt(imap_password)?;
        let mcp_token = uuid::Uuid::new_v4().to_string();
        let session = Session {
            email: email.to_string(),
            gitlab_sub: gitlab_sub.to_string(),
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

    /// Look up a session by mcp_token, refresh TTL on access.
    pub async fn get_session(&self, mcp_token: &str) -> Result<Session, AppError> {
        let key = format!("mcp:session:{mcp_token}");
        let mut conn = self.conn().await?;
        let value: Option<String> = conn.get(&key).await?;
        let value = value.ok_or(AppError::SessionNotFound)?;
        // Refresh TTL on each access
        conn.expire::<_, ()>(&key, SESSION_TTL as i64).await?;
        Ok(serde_json::from_str(&value)?)
    }

    /// Decrypt the IMAP password from a session.
    pub fn decrypt_imap_password(&self, session: &Session) -> Result<String, AppError> {
        self.decrypt(&session.imap_password_enc, &session.imap_password_iv)
    }

    // --- Encryption helpers ---

    fn encrypt(&self, plaintext: &str) -> Result<(String, String), AppError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| AppError::Encryption(format!("encrypt failed: {e}")))?;
        Ok((B64.encode(ciphertext), B64.encode(nonce)))
    }

    fn decrypt(&self, ciphertext_b64: &str, iv_b64: &str) -> Result<String, AppError> {
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
