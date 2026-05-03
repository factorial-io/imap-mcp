use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::StatusCode;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::error::AppError;
use crate::imap::ImapConnection;
use crate::manage::set_manage_cookie_response;
use crate::session::{Account, AuthCode, AuthFlowIntent, AuthFlowState, OAuthClient, PendingSetup};
use crate::AppState;

/// Build the OIDC client using auto-discovery.
pub async fn build_oidc_client(
    oidc_issuer_url: &str,
    client_id: &str,
    client_secret: &str,
    base_url: &str,
) -> Result<CoreClient, AppError> {
    let issuer_url = IssuerUrl::new(oidc_issuer_url.to_string())
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

// --- Dynamic Client Registration (RFC 7591) ---

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    // Accept and ignore additional fields from the MCP client
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

/// POST /register — Dynamic OAuth client registration.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegistrationRequest>,
) -> Result<Response, AppError> {
    if req.redirect_uris.is_empty() {
        return Err(AppError::Auth("redirect_uris is required".into()));
    }

    // Validate all redirect URIs use HTTPS
    for uri in &req.redirect_uris {
        if !uri.starts_with("https://") {
            return Err(AppError::Auth("redirect_uris must use https".into()));
        }
    }

    let client_id = uuid::Uuid::new_v4().to_string();
    let client = OAuthClient {
        client_id: client_id.clone(),
        redirect_uris: req.redirect_uris.clone(),
        client_name: req.client_name.clone(),
    };
    state
        .sessions
        .store_oauth_client(&client_id, &client)
        .await?;

    tracing::info!(client_id = %client_id, "OAuth client registered");

    let resp = RegistrationResponse {
        client_id,
        redirect_uris: req.redirect_uris,
        client_name: req.client_name,
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
    };

    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

// --- Authorization Endpoint ---

#[derive(Debug, Deserialize)]
pub struct AuthorizationParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    #[serde(default = "default_s256")]
    pub code_challenge_method: String,
    #[serde(default)]
    pub scope: Option<String>,
}

fn default_s256() -> String {
    "S256".to_string()
}

/// GET /auth/login — Accept OAuth params from claude.ai, start OIDC flow.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizationParams>,
) -> Result<Response, AppError> {
    if params.response_type != "code" {
        return Err(AppError::Auth("unsupported response_type".into()));
    }

    // Validate client_id and redirect_uri
    let client = state.sessions.get_oauth_client(&params.client_id).await?;
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err(AppError::Auth("invalid redirect_uri".into()));
    }

    // Start OIDC flow with PKCE
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

    // Store combined state: claude.ai's OAuth params + OIDC params
    let flow = AuthFlowState {
        oauth_client_id: params.client_id,
        oauth_redirect_uri: params.redirect_uri,
        oauth_state: params.state,
        oauth_code_challenge: params.code_challenge,
        oauth_code_challenge_method: params.code_challenge_method,
        pkce_verifier: pkce_verifier.secret().clone(),
        nonce: nonce.secret().clone(),
        intent: AuthFlowIntent::Connector,
    };
    state
        .sessions
        .store_auth_flow(csrf_token.secret(), &flow)
        .await?;

    tracing::info!("OAuth login started, redirecting to OIDC provider");
    Ok(Redirect::temporary(auth_url.as_str()).into_response())
}

/// GET /auth/manage_login — Start an OIDC flow whose callback drops the user
/// onto `/manage` instead of the IMAP setup form. Used by direct visits to
/// `/manage` without a ticket and without a valid management cookie.
pub async fn manage_login(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
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

    let flow = AuthFlowState {
        oauth_client_id: String::new(),
        oauth_redirect_uri: String::new(),
        oauth_state: String::new(),
        oauth_code_challenge: String::new(),
        oauth_code_challenge_method: "S256".to_string(),
        pkce_verifier: pkce_verifier.secret().clone(),
        nonce: nonce.secret().clone(),
        intent: AuthFlowIntent::ManageEntry,
    };
    state
        .sessions
        .store_auth_flow(csrf_token.secret(), &flow)
        .await?;

    Ok(Redirect::temporary(auth_url.as_str()).into_response())
}

// --- OIDC Callback ---

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

/// GET /auth/callback — Handle OIDC provider redirect.
///
/// Branches on the stored `AuthFlowState.intent`:
/// - `Connector` (default, claude.ai-driven): show IMAP setup form.
/// - `ManageEntry`: set the management cookie and redirect to `/manage`.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AppError> {
    // Retrieve combined auth flow state
    let flow = state.sessions.get_auth_flow(&params.state).await?;

    let pkce_verifier = PkceCodeVerifier::new(flow.pkce_verifier);
    let nonce = Nonce::new(flow.nonce);

    // Exchange OIDC authorization code for tokens
    let token_response = state
        .oidc_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::Oidc(format!("token exchange failed: {e}")))?;

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

    // Branch on intent.
    if flow.intent == AuthFlowIntent::ManageEntry {
        tracing::info!(oidc_sub = %sub, "OIDC re-auth for /manage successful");
        let (session_id, _csrf) = state.sessions.create_manage_session(&sub, &email).await?;
        let dest = format!("{}/manage", state.base_url);
        return Ok(set_manage_cookie_response(&session_id, &dest));
    }

    tracing::info!("OIDC auth successful, showing IMAP setup form");

    // HTML-escape user-controlled values to prevent XSS
    let name_escaped = html_escape(&name);
    let email_display = html_escape(&email);

    // Store pending setup in Redis
    let setup_id = uuid::Uuid::new_v4().to_string();
    let pending = PendingSetup {
        email: email.clone(),
        oidc_sub: sub,
        name: name.clone(),
        oauth_client_id: flow.oauth_client_id,
        oauth_redirect_uri: flow.oauth_redirect_uri,
        oauth_state: flow.oauth_state,
        oauth_code_challenge: flow.oauth_code_challenge,
        oauth_code_challenge_method: flow.oauth_code_challenge_method,
    };
    state
        .sessions
        .store_pending_setup(&setup_id, &pending)
        .await?;

    // Render IMAP password form with provider dropdown + editable IMAP email + label.
    let provider_options = render_provider_options(&state, None);
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
        input, select {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
        button {{ margin-top: 20px; padding: 10px 24px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }}
        button:hover {{ background: #1d4ed8; }}
        .hint {{ color: #6b7280; font-size: 0.9em; margin-top: 4px; }}
    </style>
</head>
<body>
    <h1>Hello {name_escaped}!</h1>
    <p>Connect a mailbox to the MCP server. You'll be able to add more later.</p>
    <form method="POST" action="/auth/setup">
        <input type="hidden" name="setup_id" value="{setup_id}">
        <p>Signed in as <strong>{email_display}</strong></p>
        <label for="provider_id">Mail provider</label>
        <select id="provider_id" name="provider_id" required>
            {provider_options}
        </select>
        <label for="label">Nickname</label>
        <input type="text" id="label" name="label" required maxlength="64" value="{email_display}">
        <p class="hint">A short name to distinguish this mailbox if you connect more than one.</p>
        <label for="imap_email">IMAP login email</label>
        <input type="email" id="imap_email" name="imap_email" required value="{email_display}">
        <p class="hint">May differ from your sign-in email (e.g. shared mailboxes).</p>
        <label for="imap_password">IMAP password</label>
        <input type="password" id="imap_password" name="imap_password" required autocomplete="off">
        <button type="submit">Connect</button>
    </form>
</body>
</html>"#,
    );

    Ok(Html(html).into_response())
}

/// Render `<option>` tags for the provider dropdown.
pub(crate) fn render_provider_options(state: &AppState, selected_id: Option<&str>) -> String {
    state
        .providers
        .iter()
        .map(|p| {
            let selected = if Some(p.id.as_str()) == selected_id {
                " selected"
            } else {
                ""
            };
            let label = html_escape(&p.label);
            let host = html_escape(&p.host);
            let id = html_escape(&p.id);
            format!(
                r#"<option value="{id}"{selected}>{label} ({host}:{port})</option>"#,
                port = p.port
            )
        })
        .collect::<Vec<_>>()
        .join("\n            ")
}

// --- IMAP Setup + Authorization Code Generation ---

#[derive(Deserialize)]
pub struct SetupForm {
    setup_id: String,
    provider_id: String,
    label: String,
    imap_email: String,
    imap_password: String,
}

/// POST /auth/setup — Validate IMAP credentials, create the user's first
/// `Account`, generate auth code, redirect to claude.ai.
pub async fn setup(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SetupForm>,
) -> Result<Response, AppError> {
    let pending = state.sessions.get_pending_setup(&form.setup_id).await?;

    let provider = state
        .providers
        .get(&form.provider_id)
        .ok_or_else(|| AppError::Auth("unknown provider".into()))?;

    if form.label.trim().is_empty() {
        return Err(AppError::Auth("label is required".into()));
    }
    if form.imap_email.trim().is_empty() {
        return Err(AppError::Auth("IMAP email is required".into()));
    }

    // Rate-limit credential validations per oidc_sub so the server can't be
    // used as a brute-force oracle against the allowlisted IMAP host.
    state
        .sessions
        .check_imap_validate_rate_limit(&pending.oidc_sub)
        .await?;

    // Validate IMAP credentials against the chosen provider.
    tracing::info!(
        oidc_sub = %pending.oidc_sub,
        provider = %provider.id,
        imap_email = %form.imap_email,
        "Validating IMAP credentials for first account"
    );
    let conn = ImapConnection::connect(
        &provider.host,
        provider.port,
        &form.imap_email,
        &form.imap_password,
    )
    .await
    .map_err(|_| AppError::InvalidCredentials)?;
    conn.logout().await.ok();

    // Create the user's first Account record.
    let (enc, iv) = state.sessions.encrypt(&form.imap_password)?;
    let account = Account {
        account_id: uuid::Uuid::new_v4().to_string(),
        label: form.label.trim().to_string(),
        imap_email: form.imap_email.trim().to_string(),
        imap_host: provider.host.clone(),
        imap_port: provider.port,
        password_enc: enc,
        password_iv: iv,
        created_at: chrono::Utc::now().timestamp(),
        last_used_at: None,
        auth_failure_count: 0,
        disabled_at: None,
    };
    state
        .sessions
        .put_account(&pending.oidc_sub, &account)
        .await?;

    // Generate authorization code (no IMAP password — Account holds it).
    let code = uuid::Uuid::new_v4().to_string();
    let auth_code = AuthCode {
        client_id: pending.oauth_client_id,
        redirect_uri: pending.oauth_redirect_uri.clone(),
        code_challenge: pending.oauth_code_challenge,
        code_challenge_method: pending.oauth_code_challenge_method,
        email: pending.email.clone(),
        oidc_sub: pending.oidc_sub.clone(),
    };
    state.sessions.store_auth_code(&code, &auth_code).await?;

    tracing::info!(
        oidc_sub = %pending.oidc_sub,
        account_id = %account.account_id,
        "First account created, redirecting with authorization code"
    );

    // Redirect back to claude.ai's redirect_uri with the authorization code
    let redirect_url = format!(
        "{}?code={}&state={}",
        pending.oauth_redirect_uri, code, pending.oauth_state
    );
    // 303 See Other to change POST to GET for claude.ai's callback
    Ok((StatusCode::SEE_OTHER, [("location", redirect_url)]).into_response())
}

// --- Token Endpoint ---

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub client_id: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse2 {
    pub access_token: String,
    pub token_type: String,
}

/// POST /auth/token — Exchange authorization code for access token.
pub async fn token(
    State(state): State<Arc<AppState>>,
    Form(req): Form<TokenRequest>,
) -> Result<Response, AppError> {
    if req.grant_type != "authorization_code" {
        return Err(AppError::Auth("unsupported grant_type".into()));
    }

    let auth_code = state.sessions.get_auth_code(&req.code).await?;

    // Validate client_id and redirect_uri match
    if auth_code.client_id != req.client_id {
        return Err(AppError::Auth("client_id mismatch".into()));
    }
    if auth_code.redirect_uri != req.redirect_uri {
        return Err(AppError::Auth("redirect_uri mismatch".into()));
    }

    // Verify PKCE: SHA256(code_verifier) must match code_challenge
    if !verify_pkce_s256(&req.code_verifier, &auth_code.code_challenge) {
        return Err(AppError::Auth("PKCE verification failed".into()));
    }

    // Issue a session bound to the OIDC identity. Account credentials are
    // already stored under `oidc_sub`.
    let access_token = state
        .sessions
        .create_session(&auth_code.email, &auth_code.oidc_sub)
        .await?;

    tracing::info!(
        oidc_sub = %auth_code.oidc_sub,
        oidc_email = %auth_code.email,
        "Token exchange successful, MCP session created"
    );

    let resp = TokenResponse2 {
        access_token,
        token_type: "bearer".to_string(),
    };
    Ok(Json(resp).into_response())
}

/// Verify PKCE S256: BASE64URL(SHA256(code_verifier)) == code_challenge
fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == code_challenge
}

// --- Well-known endpoints ---

/// GET /.well-known/oauth-protected-resource
pub async fn oauth_protected_resource(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
pub async fn oauth_authorization_server(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = serde_json::json!({
        "issuer": state.base_url,
        "authorization_endpoint": format!("{}/auth/login", state.base_url),
        "token_endpoint": format!("{}/auth/token", state.base_url),
        "registration_endpoint": format!("{}/register", state.base_url),
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

/// Escape HTML special characters to prevent XSS.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_pkce_s256_valid() {
        // Known test vector: code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);
        assert!(verify_pkce_s256(verifier, &challenge));
    }

    #[test]
    fn verify_pkce_s256_invalid() {
        assert!(!verify_pkce_s256("wrong-verifier", "wrong-challenge"));
    }
}
