use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Unified error type for the application.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("IMAP error: {0}")]
    Imap(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("OIDC error: {0}")]
    Oidc(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::SessionNotFound => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Oidc(_) => (StatusCode::BAD_GATEWAY, "OIDC provider error".to_string()),
            AppError::Imap(_) => {
                tracing::error!("IMAP error: {self}");
                (StatusCode::BAD_GATEWAY, "IMAP error".to_string())
            }
            AppError::Redis(_) => {
                tracing::error!("Redis error: {self}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::Encryption(_) => {
                tracing::error!("Encryption error: {self}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::Serialization(_) => {
                tracing::error!("Serialization error: {self}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
        };

        (status, message).into_response()
    }
}
