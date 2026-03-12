use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use http::StatusCode;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::error::AppError;
use crate::imap::ImapConnection;
use crate::session::OidcState;
use crate::AppState;

/// Build the OIDC client using auto-discovery.
pub async fn build_oidc_client(
    gitlab_url: &str,
    client_id: &str,
    client_secret: &str,
    base_url: &str,
) -> Result<CoreClient, AppError> {
    let issuer_url = IssuerUrl::new(gitlab_url.to_string())
        .map_err(|e| AppError::Oidc(format!("invalid issuer URL: {e}")))?;
    let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
        .await
        .map_err(|e| AppError::Oidc(format!("OIDC discovery failed: {e}")))?;

    let redirect_url = RedirectUrl::new(format!("{base_url}/auth/callback"))
        .map_err(|e| AppError::Oidc(format!("invalid redirect URL: {e}")))?;

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
    )
    .set_redirect_uri(redirect_url);

    Ok(client)
}

/// GET /auth/login — Start the OIDC flow with PKCE.
pub async fn login(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = state
        .oidc_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store PKCE verifier and nonce in Redis keyed by CSRF state token
    let oidc_state = OidcState {
        pkce_verifier: pkce_verifier.secret().clone(),
        nonce: nonce.secret().clone(),
    };
    state
        .sessions
        .store_oidc_state(csrf_token.secret(), &oidc_state)
        .await?;

    tracing::info!("OIDC login started, redirecting to GitLab");
    Ok(Redirect::temporary(auth_url.as_str()).into_response())
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

/// GET /auth/callback — Handle GitLab redirect, exchange code for ID token.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AppError> {
    // Retrieve and validate OIDC state from Redis
    let oidc_state = state.sessions.get_oidc_state(&params.state).await?;

    let pkce_verifier = PkceCodeVerifier::new(oidc_state.pkce_verifier);
    let nonce = Nonce::new(oidc_state.nonce);

    // Exchange authorization code for tokens
    let token_response = state
        .oidc_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::Oidc(format!("token exchange failed: {e}")))?;

    // Extract and verify ID token
    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::Oidc("missing ID token".to_string()))?;

    let verifier = state.oidc_client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &nonce)
        .map_err(|e| AppError::Oidc(format!("ID token verification failed: {e}")))?;

    let email = claims
        .email()
        .map(|e| e.to_string())
        .ok_or_else(|| AppError::Oidc("email claim missing from ID token".to_string()))?;

    let sub = claims.subject().to_string();
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .unwrap_or_else(|| email.clone());

    tracing::info!(email = %email, "OIDC callback successful, showing setup form");

    // Render the IMAP password form
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IMAP Setup</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; }}
        h1 {{ font-size: 1.4em; }}
        label {{ display: block; margin-top: 16px; font-weight: 600; }}
        input {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
        button {{ margin-top: 20px; padding: 10px 24px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }}
        button:hover {{ background: #1d4ed8; }}
        .error {{ color: #dc2626; margin-top: 12px; }}
    </style>
</head>
<body>
    <h1>Hello {name}!</h1>
    <p>Enter your IMAP password to connect your email to the MCP server.</p>
    <form method="POST" action="/auth/setup">
        <input type="hidden" name="email" value="{email}">
        <input type="hidden" name="gitlab_sub" value="{sub}">
        <label>Email: <strong>{email}</strong></label>
        <label for="imap_password">IMAP Password</label>
        <input type="password" id="imap_password" name="imap_password" required autocomplete="off">
        <button type="submit">Connect</button>
    </form>
</body>
</html>"#,
    );

    Ok(Html(html).into_response())
}

#[derive(Deserialize)]
pub struct SetupForm {
    email: String,
    gitlab_sub: String,
    imap_password: String,
}

/// POST /auth/setup — Validate IMAP credentials and create session.
pub async fn setup(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SetupForm>,
) -> Result<Response, AppError> {
    // Validate IMAP credentials with a real connection attempt
    tracing::info!(email = %form.email, "Validating IMAP credentials");
    let conn = ImapConnection::connect(
        &state.imap_host,
        state.imap_port,
        &form.email,
        &form.imap_password,
    )
    .await
    .map_err(|_| AppError::InvalidCredentials)?;

    // Logout from the validation connection
    conn.logout().await.ok();

    // Create session with encrypted password
    let mcp_token = state
        .sessions
        .create_session(&form.email, &form.gitlab_sub, &form.imap_password)
        .await?;

    tracing::info!(email = %form.email, "Session created, redirecting with token");

    // Redirect back to claude.ai with the token
    // The MCP spec expects the token to be passed back; render a page that provides it
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Setup Complete</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; }}
        .token {{ background: #f3f4f6; padding: 12px; border-radius: 4px; word-break: break-all; font-family: monospace; }}
        .success {{ color: #16a34a; font-weight: 600; }}
    </style>
</head>
<body>
    <h1 class="success">Connected!</h1>
    <p>Your IMAP account has been verified and connected.</p>
    <p>Your MCP access token:</p>
    <div class="token">{mcp_token}</div>
    <p>Use this token as a Bearer token when configuring the MCP server in claude.ai.</p>
    <p>You can close this window.</p>
</body>
</html>"#,
    );

    Ok(Html(html).into_response())
}

/// GET /.well-known/oauth-protected-resource
/// MCP spec: tells the client where the authorization server is.
pub async fn oauth_protected_resource(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let body = serde_json::json!({
        "resource": state.base_url,
        "authorization_servers": [state.base_url],
        "bearer_methods_supported": ["header"],
    });
    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        serde_json::to_string(&body).unwrap_or_default(),
    )
}

/// GET /.well-known/oauth-authorization-server
/// MCP spec: OAuth metadata for the authorization server.
pub async fn oauth_authorization_server(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let body = serde_json::json!({
        "issuer": state.base_url,
        "authorization_endpoint": format!("{}/auth/login", state.base_url),
        "token_endpoint": format!("{}/auth/setup", state.base_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    });
    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        serde_json::to_string(&body).unwrap_or_default(),
    )
}
