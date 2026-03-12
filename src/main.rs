mod auth;
mod error;
mod imap;
mod mcp;
mod session;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http::Request;
use openidconnect::core::CoreClient;
use session::SessionStore;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Shared application state.
pub struct AppState {
    pub sessions: SessionStore,
    pub oidc_client: CoreClient,
    pub imap_host: String,
    pub imap_port: u16,
    pub base_url: String,
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} environment variable is required"))
}

fn env_var_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let gitlab_url = env_var("GITLAB_URL");
    let gitlab_client_id = env_var("GITLAB_CLIENT_ID");
    let gitlab_client_secret = env_var("GITLAB_CLIENT_SECRET");
    let imap_host = env_var("IMAP_HOST");
    let imap_port: u16 = env_var_or("IMAP_PORT", "993").parse()?;
    let base_url = env_var("BASE_URL");
    let redis_url = env_var("REDIS_URL");
    let encryption_key = env_var("ENCRYPTION_KEY");

    let sessions = SessionStore::new(&redis_url, &encryption_key)?;

    tracing::info!("Discovering OIDC configuration from {gitlab_url}");
    let oidc_client = auth::build_oidc_client(
        &gitlab_url,
        &gitlab_client_id,
        &gitlab_client_secret,
        &base_url,
    )
    .await?;

    let state = Arc::new(AppState {
        sessions,
        oidc_client,
        imap_host,
        imap_port,
        base_url,
    });

    let app = Router::new()
        // OAuth well-known endpoints
        .route(
            "/.well-known/oauth-protected-resource",
            get(auth::oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth::oauth_authorization_server),
        )
        // Auth flow
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/setup", post(auth::setup))
        // MCP endpoint — handles GET (SSE stream) and POST (messages) with bearer auth
        .route("/mcp", axum::routing::any(mcp_handler))
        .route("/mcp/{path}", axum::routing::any(mcp_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_addr = env_var_or("BIND_ADDR", "0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server listening on {bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// MCP endpoint handler with bearer token authentication.
///
/// Validates the Bearer token against Redis, decrypts IMAP credentials,
/// then delegates to rmcp's StreamableHttpService for MCP protocol handling.
async fn mcp_handler(
    headers: HeaderMap,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request<axum::body::Body>,
) -> Response {
    // Extract bearer token
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            let www_auth = format!(
                r#"Bearer resource_metadata="{}/.well-known/oauth-protected-resource""#,
                state.base_url
            );
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", www_auth)],
                "Bearer token required",
            )
                .into_response();
        }
    };

    // Look up session in Redis
    let session = match state.sessions.get_session(&token).await {
        Ok(s) => s,
        Err(_) => {
            let www_auth = format!(
                r#"Bearer resource_metadata="{}/.well-known/oauth-protected-resource""#,
                state.base_url
            );
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", www_auth)],
                "Invalid or expired token",
            )
                .into_response();
        }
    };

    // Decrypt IMAP password
    let imap_password = match state.sessions.decrypt_imap_password(&session) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to decrypt IMAP password: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Build per-request MCP service and delegate
    let email = session.email.clone();
    let imap_host = state.imap_host.clone();
    let imap_port = state.imap_port;

    let config =
        rmcp::transport::streamable_http_server::tower::StreamableHttpServerConfig::default();
    let session_manager: Arc<
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    > = Arc::new(Default::default());

    let service = rmcp::transport::streamable_http_server::tower::StreamableHttpService::new(
        move || {
            Ok(mcp::ImapMcpServer::new(
                email.clone(),
                imap_password.clone(),
                imap_host.clone(),
                imap_port,
            ))
        },
        session_manager,
        config,
    );

    let resp = service.handle(req).await;
    resp.map(axum::body::Body::new)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    Some(token.to_string())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-token-123".parse().unwrap());
        assert_eq!(
            extract_bearer_token(&headers),
            Some("my-token-123".to_string())
        );
    }

    #[test]
    fn extract_bearer_token_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_empty_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some(String::new()));
    }

    #[test]
    fn extract_bearer_token_no_space_after_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "BearerNOSPACE".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }
}
