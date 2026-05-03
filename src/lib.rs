pub mod auth;
pub mod error;
pub mod extract;
pub mod imap;
pub mod mcp;
pub mod session;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http::Request;
use openidconnect::core::CoreClient;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use session::SessionStore;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Shared application state.
pub struct AppState {
    pub sessions: SessionStore,
    pub oidc_client: CoreClient,
    pub imap_host: String,
    pub imap_port: u16,
    pub base_url: String,
}

impl AppState {
    pub fn new(
        sessions: SessionStore,
        oidc_client: CoreClient,
        imap_host: String,
        imap_port: u16,
        base_url: String,
    ) -> Self {
        Self {
            sessions,
            oidc_client,
            imap_host,
            imap_port,
            base_url,
        }
    }
}

/// Build the axum Router from shared state. Used by main and integration tests.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(auth::oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth::oauth_authorization_server),
        )
        .route("/register", post(auth::register))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/setup", post(auth::setup))
        .route("/auth/token", post(auth::token))
        .route("/mcp", axum::routing::any(mcp_handler))
        .route("/mcp/{path}", axum::routing::any(mcp_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::DELETE,
                    http::Method::OPTIONS,
                ])
                .allow_headers([
                    http::header::AUTHORIZATION,
                    http::header::CONTENT_TYPE,
                    http::header::ACCEPT,
                ]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// MCP endpoint handler with bearer token authentication.
async fn mcp_handler(
    headers: HeaderMap,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request<axum::body::Body>,
) -> Response {
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

    let imap_password = match state.sessions.decrypt_imap_password(&session) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to decrypt IMAP password: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let email = session.email;
    let imap_host = state.imap_host.clone();
    let imap_port = state.imap_port;

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true);

    let service = StreamableHttpService::new(
        move || {
            Ok(mcp::ImapMcpServer::new(
                email.clone(),
                imap_password.clone(),
                imap_host.clone(),
                imap_port,
            ))
        },
        LocalSessionManager::default().into(),
        config,
    );

    let resp: http::Response<_> = service.handle(req).await;
    resp.map(axum::body::Body::new)
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    Some(token.to_string())
}
