use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use grantry::server::ApproveError;
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
use crate::manage::set_manage_cookie_response;
use crate::oauth::Identity;
use crate::session::{Account, AuthFlowIntent, AuthFlowState, PendingSetup};
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

// --- Consent entry point ---

#[derive(Debug, Deserialize)]
pub struct ConnectParams {
    pending: uuid::Uuid,
}

/// GET /auth/connect?pending={id} — grantry has validated the client's
/// authorization request (client, redirect URI, PKCE, resource, scope) and
/// stored it as pending. Sign the user in with OIDC; the callback binds the
/// pending request to them and shows the mailbox setup form.
pub async fn connect(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ConnectParams>,
) -> Result<Response, AppError> {
    let redirect = start_oidc_flow(
        &state,
        AuthFlowState {
            pending_id: Some(params.pending),
            pkce_verifier: String::new(),
            nonce: String::new(),
            intent: AuthFlowIntent::Connector,
        },
    )
    .await?;
    tracing::info!("OAuth authorization pending, redirecting to OIDC provider");
    Ok(redirect)
}

/// Redirect to the OIDC provider, remembering `flow` (with its PKCE verifier
/// and nonce filled in) under the CSRF state.
async fn start_oidc_flow(state: &AppState, mut flow: AuthFlowState) -> Result<Response, AppError> {
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
    flow.pkce_verifier = pkce_verifier.secret().clone();
    flow.nonce = nonce.secret().clone();
    state
        .sessions
        .store_auth_flow(csrf_token.secret(), &flow)
        .await?;
    Ok(Redirect::temporary(auth_url.as_str()).into_response())
}

/// GET /auth/manage_login — Start an OIDC flow whose callback drops the user
/// onto `/manage` instead of the IMAP setup form. Used by direct visits to
/// `/manage` without a ticket and without a valid management cookie.
pub async fn manage_login(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    start_oidc_flow(
        &state,
        AuthFlowState {
            pending_id: None,
            pkce_verifier: String::new(),
            nonce: String::new(),
            intent: AuthFlowIntent::ManageEntry,
        },
    )
    .await
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

    let pending_id = flow
        .pending_id
        .ok_or_else(|| AppError::Auth("no authorization request in this login flow".into()))?;
    let identity = Identity {
        sub: sub.clone(),
        email: email.clone(),
    };
    // Bind the pending authorization to this user: from now on no other
    // identity can see or approve it.
    let authorization = state
        .oauth
        .pending(pending_id, &identity)
        .await
        .map_err(|e| AppError::Internal(format!("pending authorization lookup failed: {e}")))?
        .ok_or_else(|| AppError::Auth("authorization request not found or expired".into()))?;

    tracing::info!("OIDC auth successful, showing IMAP setup form");

    // HTML-escape user-controlled values to prevent XSS
    let name_escaped = html_escape(&name);
    let email_display = html_escape(&email);
    let client_name = html_escape(&authorization.client_name);

    // Store pending setup in Redis
    let setup_id = uuid::Uuid::new_v4().to_string();
    let pending = PendingSetup {
        email: email.clone(),
        oidc_sub: sub,
        name: name.clone(),
        pending_id,
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
    <p><strong>{client_name}</strong> is asking to read your email.
    Connect a mailbox to allow it. You'll be able to add more later.</p>
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
    conn.logout_or_warn().await;

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
    // First account becomes the default. `_if_unset` keeps a later explicit
    // user choice (set via /manage) intact across re-onboarding flows.
    state
        .sessions
        .set_default_account_id_if_unset(&pending.oidc_sub, &account.account_id)
        .await?;

    // Approve the pending authorization: grantry creates the grant and a
    // one-time code bound to the client's PKCE challenge and redirect URI.
    let identity = Identity {
        sub: pending.oidc_sub.clone(),
        email: pending.email.clone(),
    };
    let approved = state
        .oauth
        .approve(pending.pending_id, &identity, None)
        .await
        .map_err(|e| match e {
            ApproveError::NotFound => {
                AppError::Auth("authorization request not found or expired".into())
            }
            ApproveError::InvalidScope => AppError::Auth("invalid scope".into()),
            ApproveError::Backend(e) => AppError::Internal(format!("approve failed: {e}")),
        })?;

    tracing::info!(
        oidc_sub = %pending.oidc_sub,
        account_id = %account.account_id,
        "First account created, redirecting with authorization code"
    );

    // 303 See Other to change POST to GET for the client's callback
    Ok((StatusCode::SEE_OTHER, [("location", approved.redirect)]).into_response())
}

/// Escape HTML special characters to prevent XSS.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
