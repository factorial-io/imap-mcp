//! `/manage` HTML page — list/add/remove a user's IMAP accounts.
//!
//! Auth model:
//! - A 15-minute single-use ticket gets the user to `/manage` and seeds a
//!   server-side `mgmt_session` Redis record + cookie.
//! - Direct visits without a ticket are bounced through OIDC re-auth via
//!   `/auth/manage_login` to establish the same cookie.
//! - Mutations require the cookie **and** a CSRF token embedded in the form.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use chrono::Utc;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{html_escape, render_provider_options};
use crate::error::AppError;
use crate::imap::ImapConnection;
use crate::session::{Account, ManageSession};
use crate::AppState;

const COOKIE_NAME: &str = "mgmt_session";

/// Build the `Set-Cookie` value for the management session cookie.
///
/// HttpOnly + SameSite=Lax + Path=/manage. Marked `Secure` because the
/// service is served over HTTPS in real deployments; tests over HTTP still
/// work because axum doesn't reject Set-Cookie based on scheme.
fn build_cookie(value: &str) -> String {
    format!(
        "{COOKIE_NAME}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; \
         Max-Age={ttl}",
        ttl = crate::session::MANAGE_SESSION_TTL,
    )
}

fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

fn read_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(http::header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// 303-redirect to `dest` while setting the management cookie. Used by
/// the OIDC-callback path when `intent = ManageEntry`.
pub fn set_manage_cookie_response(session_id: &str, dest: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            ("location", dest.to_string()),
            ("set-cookie", build_cookie(session_id)),
        ],
        "",
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ManageQuery {
    /// Optional management ticket. Single-use; consumed on first hit.
    #[serde(default)]
    pub t: Option<String>,
    /// Optional flash message id for after a successful mutation.
    #[serde(default)]
    pub msg: Option<String>,
}

/// GET /manage — render the account-management page.
pub async fn manage_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ManageQuery>,
) -> Result<Response, AppError> {
    // 1. If a ticket is present, redeem it and set the management cookie.
    if let Some(ticket) = q.t.as_deref() {
        if let Some(t) = state.sessions.consume_manage_ticket(ticket).await? {
            let (session_id, _csrf) = state
                .sessions
                .create_manage_session(&t.oidc_sub, &t.oidc_email)
                .await?;
            // Drop the `t` query param to avoid replays from browser history.
            let dest = format!("{}/manage", state.base_url);
            return Ok(set_manage_cookie_response(&session_id, &dest));
        }
        // Ticket invalid or expired — fall through to the OIDC bounce path.
    }

    // 2. Otherwise require a valid management cookie.
    let session = match cookie_session(&state, &headers).await? {
        Some(s) => s,
        None => {
            // Bounce through OIDC re-auth.
            let dest = format!("{}/auth/manage_login", state.base_url);
            return Ok(Redirect::temporary(&dest).into_response());
        }
    };

    // 3. Render the page.
    let accounts = state.sessions.list_accounts(&session.oidc_sub).await?;
    let html = render_manage_page(&state, &session, &accounts, q.msg.as_deref());
    Ok((
        StatusCode::OK,
        [("Content-Type", "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

/// Look up the management session from the cookie. Returns `None` if missing
/// or expired.
async fn cookie_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Option<ManageSession>, AppError> {
    let Some(session_id) = read_cookie(headers) else {
        return Ok(None);
    };
    state.sessions.get_manage_session(&session_id).await
}

#[derive(Deserialize)]
pub struct AddAccountForm {
    pub csrf_token: String,
    pub provider_id: String,
    pub label: String,
    pub imap_email: String,
    pub imap_password: String,
}

/// POST /manage/accounts — add a new mailbox.
pub async fn add_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AddAccountForm>,
) -> Result<Response, AppError> {
    let session = require_session(&state, &headers).await?;
    if !constant_time_eq(&form.csrf_token, &session.csrf_token) {
        return Err(AppError::Auth("invalid CSRF token".into()));
    }

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

    state
        .sessions
        .check_imap_validate_rate_limit(&session.oidc_sub)
        .await?;

    tracing::info!(
        oidc_sub = %session.oidc_sub,
        provider = %provider.id,
        imap_email = %form.imap_email,
        "Validating IMAP credentials for new account"
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

    let (enc, iv) = state.sessions.encrypt(&form.imap_password)?;
    let account = Account {
        account_id: uuid::Uuid::new_v4().to_string(),
        label: form.label.trim().to_string(),
        imap_email: form.imap_email.trim().to_string(),
        imap_host: provider.host.clone(),
        imap_port: provider.port,
        password_enc: enc,
        password_iv: iv,
        created_at: Utc::now().timestamp(),
        last_used_at: None,
        auth_failure_count: 0,
        disabled_at: None,
    };
    state
        .sessions
        .put_account(&session.oidc_sub, &account)
        .await?;

    tracing::info!(
        oidc_sub = %session.oidc_sub,
        account_id = %account.account_id,
        "Account added via /manage"
    );
    Ok(Redirect::to(&format!("{}/manage?msg=added", state.base_url)).into_response())
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct RevalidateForm {
    pub csrf_token: String,
    pub imap_password: String,
}

/// POST /manage/accounts/{id}/delete — remove a mailbox.
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let session = require_session(&state, &headers).await?;
    if !constant_time_eq(&form.csrf_token, &session.csrf_token) {
        return Err(AppError::Auth("invalid CSRF token".into()));
    }

    let removed = state
        .sessions
        .delete_account(&session.oidc_sub, &account_id)
        .await?;
    tracing::info!(
        oidc_sub = %session.oidc_sub,
        account_id = %account_id,
        removed,
        "Account delete via /manage"
    );
    Ok(Redirect::to(&format!("{}/manage?msg=removed", state.base_url)).into_response())
}

/// POST /manage/accounts/{id}/revalidate — re-enter the IMAP password for an
/// account whose stored credentials have stopped working. Resets
/// `auth_failure_count`, clears `disabled_at`, and updates the encrypted
/// password — but only after a successful IMAP login with the new password.
pub async fn revalidate_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Form(form): Form<RevalidateForm>,
) -> Result<Response, AppError> {
    let session = require_session(&state, &headers).await?;
    if !constant_time_eq(&form.csrf_token, &session.csrf_token) {
        return Err(AppError::Auth("invalid CSRF token".into()));
    }

    let account = state
        .sessions
        .get_account(&session.oidc_sub, &account_id)
        .await?
        .ok_or_else(|| AppError::Auth("account not found".into()))?;

    // Allowlist enforcement on use: if the operator removed this provider
    // after the user connected the mailbox, refuse to revalidate. The
    // resolver in lib.rs does the same on every tool call; we mirror it
    // here so /manage doesn't become a sneaky way to keep using a
    // de-allowlisted host.
    if state
        .providers
        .get_by_host(&account.imap_host, account.imap_port)
        .is_none()
    {
        return Err(AppError::Auth(format!(
            "provider {}:{} is no longer in the allowlist; remove this account and reconnect",
            account.imap_host, account.imap_port
        )));
    }

    state
        .sessions
        .check_imap_validate_rate_limit(&session.oidc_sub)
        .await?;

    tracing::info!(
        oidc_sub = %session.oidc_sub,
        account_id = %account.account_id,
        imap_email = %account.imap_email,
        "Re-validating IMAP credentials"
    );
    let conn = ImapConnection::connect(
        &account.imap_host,
        account.imap_port,
        &account.imap_email,
        &form.imap_password,
    )
    .await
    .map_err(|_| AppError::InvalidCredentials)?;
    conn.logout().await.ok();

    let (enc, iv) = state.sessions.encrypt(&form.imap_password)?;
    state
        .sessions
        .update_account_password(&session.oidc_sub, &account.account_id, enc, iv)
        .await?;

    tracing::info!(
        oidc_sub = %session.oidc_sub,
        account_id = %account.account_id,
        "Account re-validated"
    );
    Ok(Redirect::to(&format!("{}/manage?msg=revalidated", state.base_url)).into_response())
}

/// POST /manage/logout — clear the management session.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if let Some(session_id) = read_cookie(&headers) {
        // CSRF check: an attacker who can POST cross-origin (same-site +
        // SameSite=Lax doesn't fully block this) shouldn't be able to log
        // the user out and force repeated OIDC re-auth.
        if let Some(sess) = state.sessions.get_manage_session(&session_id).await? {
            if !constant_time_eq(&form.csrf_token, &sess.csrf_token) {
                return Err(AppError::Auth("invalid CSRF token".into()));
            }
        }
        state.sessions.delete_manage_session(&session_id).await?;
    }
    Ok((
        StatusCode::SEE_OTHER,
        [
            ("location", format!("{}/manage", state.base_url)),
            ("set-cookie", clear_cookie()),
        ],
        "",
    )
        .into_response())
}

async fn require_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<ManageSession, AppError> {
    cookie_session(state, headers)
        .await?
        .ok_or_else(|| AppError::Auth("no management session".into()))
}

/// Constant-time string equality for equal-length secrets (e.g. UUID CSRF
/// tokens).
///
/// Uses [`subtle::ConstantTimeEq`] which is constant-time in the *content*
/// of the slices but **not** in their *length*: a length mismatch returns
/// `Choice(0)` without doing the byte-by-byte comparison work, so length
/// can leak via timing. That's fine in this codebase because every CSRF
/// token compared here is `uuid::Uuid::new_v4().to_string()` — always
/// 36 bytes — so the slow path always runs. Future callers must keep
/// inputs the same length, or accept that unequal lengths short-circuit.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn render_manage_page(
    state: &AppState,
    session: &ManageSession,
    accounts: &[Account],
    msg: Option<&str>,
) -> String {
    let csrf = html_escape(&session.csrf_token);
    let oidc_email = html_escape(&session.oidc_email);
    let provider_options = render_provider_options(state, None);

    let banner = match msg {
        Some("added") => r#"<div class="banner ok">Account added.</div>"#.to_string(),
        Some("removed") => r#"<div class="banner ok">Account removed.</div>"#.to_string(),
        Some("revalidated") => r#"<div class="banner ok">Account re-validated.</div>"#.to_string(),
        _ => String::new(),
    };

    let rows = if accounts.is_empty() {
        r#"<p class="empty">No mailboxes connected yet. Add one below.</p>"#.to_string()
    } else {
        let mut rows = String::from(
            r#"<table><thead><tr>
            <th>Nickname</th><th>IMAP login</th><th>Provider</th>
            <th>Last used</th><th>Status</th><th></th>
        </tr></thead><tbody>"#,
        );
        for a in accounts {
            let status = if a.is_disabled() {
                r#"<span class="bad">disabled</span>"#.to_string()
            } else if a.auth_failure_count > 0 {
                format!(
                    r#"<span class="warn">{} failed login(s)</span>"#,
                    a.auth_failure_count
                )
            } else {
                r#"<span class="ok">ok</span>"#.to_string()
            };
            let last_used = match a.last_used_at {
                Some(ts) => chrono::DateTime::from_timestamp(ts, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_else(|| "—".to_string()),
                None => "—".to_string(),
            };
            // Re-validate form rendered only for disabled accounts: a small
            // password input + button that POSTs to .../revalidate. Hidden
            // for healthy accounts to keep the table tidy.
            let revalidate_cell = if a.is_disabled() {
                format!(
                    r#"<form method="POST" action="/manage/accounts/{id}/revalidate" style="display:inline-block;margin-right:8px;">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <input type="password" name="imap_password" placeholder="New password" required style="width:auto;display:inline-block;">
                            <button type="submit">Re-validate</button>
                        </form>"#,
                    id = html_escape(&a.account_id),
                    csrf = csrf,
                )
            } else {
                String::new()
            };
            rows.push_str(&format!(
                r#"<tr>
                    <td>{label}</td>
                    <td>{email}</td>
                    <td>{host}</td>
                    <td>{last_used}</td>
                    <td>{status}</td>
                    <td>
                        {revalidate_cell}
                        <form method="POST" action="/manage/accounts/{id}/delete" data-confirm-label="{label}" onsubmit="return confirm('Remove ' + this.dataset.confirmLabel + '?');" style="display:inline-block;">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <button type="submit" class="danger">Remove</button>
                        </form>
                    </td>
                </tr>"#,
                // `label` lands in a `data-` attribute (HTML-escaped); the
                // inline JS reads it via `this.dataset.confirmLabel`, so user
                // input never enters a JS string literal — quote-injection
                // (`O'Brien`) and HTML-decoding tricks both fail safely.
                label = html_escape(&a.label),
                email = html_escape(&a.imap_email),
                host = html_escape(&a.imap_host),
                id = html_escape(&a.account_id),
                csrf = csrf,
            ));
        }
        rows.push_str("</tbody></table>");
        rows
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage IMAP accounts</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; color: #1f2937; }}
        h1 {{ font-size: 1.4em; }}
        h2 {{ font-size: 1.1em; margin-top: 32px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #e5e7eb; font-size: 0.92em; }}
        th {{ font-weight: 600; color: #4b5563; }}
        label {{ display: block; margin-top: 12px; font-weight: 600; }}
        input, select {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
        button {{ padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.95em; }}
        button:hover {{ background: #1d4ed8; }}
        button.danger {{ background: #dc2626; }}
        button.danger:hover {{ background: #b91c1c; }}
        .ok {{ color: #15803d; }}
        .warn {{ color: #b45309; }}
        .bad {{ color: #b91c1c; }}
        .banner {{ padding: 10px 12px; border-radius: 4px; margin-top: 12px; }}
        .banner.ok {{ background: #ecfdf5; color: #065f46; }}
        .empty {{ color: #6b7280; }}
        .hint {{ color: #6b7280; font-size: 0.85em; margin-top: 4px; }}
        .logout {{ float: right; }}
    </style>
</head>
<body>
    <form method="POST" action="/manage/logout" class="logout">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <button type="submit" style="background:#6b7280;">Sign out</button>
    </form>
    <h1>IMAP accounts</h1>
    <p>Signed in as <strong>{oidc_email}</strong>.</p>
    {banner}
    <h2>Connected mailboxes</h2>
    {rows}
    <h2>Add a mailbox</h2>
    <form method="POST" action="/manage/accounts">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <label for="provider_id">Mail provider</label>
        <select id="provider_id" name="provider_id" required>
            {provider_options}
        </select>
        <label for="label">Nickname</label>
        <input type="text" id="label" name="label" required maxlength="64" placeholder="e.g. Billing or Personal">
        <p class="hint">Used to distinguish this mailbox from your others.</p>
        <label for="imap_email">IMAP login email</label>
        <input type="email" id="imap_email" name="imap_email" required>
        <label for="imap_password">IMAP password</label>
        <input type="password" id="imap_password" name="imap_password" required autocomplete="off">
        <p style="margin-top: 16px;"><button type="submit">Add mailbox</button></p>
    </form>
</body>
</html>"#,
    )
}

// --- list_accounts / add_account_url helpers (used by MCP tools) ---

#[derive(Debug, Serialize)]
pub struct AccountSummary {
    pub account_id: String,
    pub label: String,
    pub imap_email: String,
    pub imap_host: String,
    pub last_used_at: Option<i64>,
    pub disabled: bool,
}

impl From<&Account> for AccountSummary {
    fn from(a: &Account) -> Self {
        AccountSummary {
            account_id: a.account_id.clone(),
            label: a.label.clone(),
            imap_email: a.imap_email.clone(),
            imap_host: a.imap_host.clone(),
            last_used_at: a.last_used_at,
            disabled: a.is_disabled(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ManageUrl {
    pub url: String,
    pub expires_in_seconds: u64,
}

/// Issue a fresh management ticket and return the corresponding `manage_url`.
pub async fn issue_manage_url(
    store: &crate::session::SessionStore,
    base_url: &str,
    oidc_sub: &str,
    oidc_email: &str,
) -> Result<ManageUrl, AppError> {
    let ticket = store.create_manage_ticket(oidc_sub, oidc_email).await?;
    Ok(ManageUrl {
        url: format!("{base_url}/manage?t={ticket}"),
        expires_in_seconds: crate::session::MANAGE_TICKET_TTL,
    })
}

/// Convenience JSON wrapper for the `list_accounts` MCP tool result.
#[derive(Debug, Serialize)]
pub struct ListAccountsResult {
    pub accounts: Vec<AccountSummary>,
    pub manage_url: ManageUrl,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trips() {
        let raw = build_cookie("abc-123");
        assert!(raw.contains("mgmt_session=abc-123"));
        assert!(raw.contains("HttpOnly"));
        assert!(raw.contains("SameSite=Lax"));
    }

    #[test]
    fn read_cookie_extracts_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "foo=bar; mgmt_session=xyz; baz=qux".parse().unwrap(),
        );
        assert_eq!(read_cookie(&headers).as_deref(), Some("xyz"));
    }

    #[test]
    fn read_cookie_returns_none_when_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "foo=bar".parse().unwrap());
        assert!(read_cookie(&headers).is_none());
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }
}
