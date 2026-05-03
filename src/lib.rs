pub mod auth;
pub mod error;
pub mod extract;
pub mod imap;
pub mod manage;
pub mod mcp;
pub mod providers;
pub(crate) mod sanitize;
pub mod session;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http::Request;
use openidconnect::core::CoreClient;
use providers::ProviderList;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use session::{Account, SessionStore};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Shared application state.
pub struct AppState {
    pub sessions: SessionStore,
    pub oidc_client: CoreClient,
    /// Allowlist of IMAP providers users may connect to. Always non-empty.
    pub providers: ProviderList,
    pub base_url: String,
    /// Hosts the rmcp Streamable-HTTP transport will accept in the `Host`
    /// header. Without our public hostname here, every MCP request is dropped
    /// as a DNS-rebinding attempt (rmcp >= 1.6 defaults to localhost only).
    pub mcp_allowed_hosts: Vec<String>,
}

impl AppState {
    pub fn new(
        sessions: SessionStore,
        oidc_client: CoreClient,
        providers: ProviderList,
        base_url: String,
    ) -> anyhow::Result<Self> {
        let mcp_allowed_hosts = derive_mcp_allowed_hosts(&base_url)?;
        Ok(Self {
            sessions,
            oidc_client,
            providers,
            base_url,
            mcp_allowed_hosts,
        })
    }

    /// Convenience: the first provider in the allowlist. Used by the legacy
    /// single-account migration shim.
    pub fn default_provider(&self) -> &providers::ImapProvider {
        self.providers.first()
    }
}

/// Build the rmcp allowed-hosts list from `base_url`. We always keep the
/// loopback defaults so local dev keeps working when `BASE_URL` is set to a
/// public hostname.
fn derive_mcp_allowed_hosts(base_url: &str) -> anyhow::Result<Vec<String>> {
    let parsed = url::Url::parse(base_url)
        .map_err(|e| anyhow::anyhow!("BASE_URL is not a valid URL ({base_url}): {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("BASE_URL has no host component: {base_url}"))?;
    Ok(vec![
        host.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
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
        .route("/auth/manage_login", get(auth::manage_login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/setup", post(auth::setup))
        .route("/auth/token", post(auth::token))
        .route("/manage", get(manage::manage_page))
        .route("/manage/accounts", post(manage::add_account))
        .route(
            "/manage/accounts/{account_id}/delete",
            post(manage::delete_account),
        )
        .route(
            "/manage/accounts/{account_id}/revalidate",
            post(manage::revalidate_account),
        )
        .route(
            "/manage/accounts/{account_id}/set_default",
            post(manage::set_default_account),
        )
        .route("/manage/logout", post(manage::logout))
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

/// Resolves the IMAP account a tool call should target, given the verified
/// OIDC identity and an optional caller-supplied selector (`account_id` or
/// `label`).
///
/// Implements the 0/1/N rules:
/// - 0 accounts: returns [`ResolveError::NoAccounts`] with a manage URL.
/// - 1 account: defaults to it when no selector given.
/// - 2+ accounts: requires explicit selector; ambiguous labels error.
///
/// Also handles legacy single-account migration: if the bearer-token session
/// still has the old encrypted-password fields and no `Account` records exist
/// yet for the user, we promote the legacy credentials into an `Account` on
/// first read and clear them from the session.
#[derive(Clone)]
pub struct AccountResolver {
    pub store: SessionStore,
    pub providers: ProviderList,
    pub oidc_sub: String,
    pub oidc_email: String,
    pub base_url: String,
    pub mcp_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no mailboxes connected — open {manage_url} to add one")]
    NoAccounts { manage_url: String },
    #[error(
        "multiple mailboxes connected — pass `account` (account_id or label). Try list_accounts."
    )]
    AccountRequired,
    #[error("account '{0}' not found")]
    NotFound(String),
    #[error("label '{0}' is ambiguous — pass account_id instead")]
    Ambiguous(String),
    #[error("account is disabled — re-validate at {manage_url}")]
    Disabled { manage_url: String },
    #[error(
        "account uses provider {host}:{port} which is no longer in the allowlist; remove and re-add at {manage_url}"
    )]
    ProviderRemoved {
        host: String,
        port: u16,
        manage_url: String,
    },
    #[error("internal: {0}")]
    Internal(String),
}

impl AccountResolver {
    pub async fn resolve(&self, selector: Option<&str>) -> Result<Account, ResolveError> {
        // Single round-trip: list current accounts, doing the legacy
        // migration if needed. Previously this was two separate calls
        // (`maybe_migrate_legacy` + `list_accounts`), which doubled Redis
        // traffic on every MCP tool call once a user had any accounts.
        let accounts = self.accounts_with_migration().await?;

        if accounts.is_empty() {
            let url = self.fresh_manage_url().await?;
            return Err(ResolveError::NoAccounts { manage_url: url });
        }

        let account = match selector {
            None => {
                if accounts.len() == 1 {
                    // The `len == 1` guard makes `next()` non-empty in
                    // practice; `ok_or_else` keeps the no-`unwrap` rule
                    // intact in case an upstream change ever invalidates
                    // the invariant.
                    accounts.into_iter().next().ok_or_else(|| {
                        ResolveError::Internal("account list shrank between checks".into())
                    })?
                } else {
                    // 2+ accounts and no selector: fall back to the user's
                    // designated default. The first account a user creates
                    // (or migrates) is auto-set as default; they can change
                    // it from /manage. This keeps existing single-account
                    // workflows intact when the user adds a second mailbox —
                    // tool calls that omit `account` continue to target the
                    // account they were already using.
                    let default_id = self
                        .store
                        .get_default_account_id(&self.oidc_sub)
                        .await
                        .map_err(|e| ResolveError::Internal(e.to_string()))?;
                    match default_id
                        .as_deref()
                        .and_then(|id| accounts.iter().find(|a| a.account_id == id))
                    {
                        Some(a) => a.clone(),
                        // No default set, or default points at an account
                        // that no longer exists. Force an explicit selector.
                        None => return Err(ResolveError::AccountRequired),
                    }
                }
            }
            Some(selector) => {
                // Prefer exact account_id match.
                if let Some(a) = accounts.iter().find(|a| a.account_id == selector) {
                    a.clone()
                } else {
                    let by_label: Vec<&Account> =
                        accounts.iter().filter(|a| a.label == selector).collect();
                    match by_label.len() {
                        0 => return Err(ResolveError::NotFound(selector.to_string())),
                        1 => by_label[0].clone(),
                        _ => return Err(ResolveError::Ambiguous(selector.to_string())),
                    }
                }
            }
        };

        if account.is_disabled() {
            let url = self.fresh_manage_url().await?;
            return Err(ResolveError::Disabled { manage_url: url });
        }

        // Allowlist enforcement on use: reject accounts whose provider has
        // since been removed from the allowlist. The check is an in-memory
        // lookup; the operator can revoke a provider by editing config and
        // restarting, and existing accounts on that host stop working
        // immediately. Users see a clear error pointing at /manage.
        if self
            .providers
            .get_by_host(&account.imap_host, account.imap_port)
            .is_none()
        {
            let url = self.fresh_manage_url().await?;
            return Err(ResolveError::ProviderRemoved {
                host: account.imap_host.clone(),
                port: account.imap_port,
                manage_url: url,
            });
        }

        Ok(account)
    }

    pub async fn list(&self) -> Result<Vec<Account>, ResolveError> {
        self.accounts_with_migration().await
    }

    pub async fn fresh_manage_url(&self) -> Result<String, ResolveError> {
        let ticket = self
            .store
            .create_manage_ticket(&self.oidc_sub, &self.oidc_email)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        Ok(format!("{}/manage?t={}", self.base_url, ticket))
    }

    /// List current accounts for this user, performing the legacy
    /// single-account migration on the way if the session still carries
    /// pre-multi-account encrypted credentials.
    ///
    /// On the hot path (user already has accounts), this is a single
    /// `list_accounts` round-trip — no extra calls. On the cold path
    /// (legacy session, no Account records yet), it migrates and returns
    /// the resulting one-element list directly.
    async fn accounts_with_migration(&self) -> Result<Vec<Account>, ResolveError> {
        let existing = self
            .store
            .list_accounts(&self.oidc_sub)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        if !existing.is_empty() {
            return Ok(existing);
        }

        // No accounts yet — see if the session still carries legacy creds.
        let session = self
            .store
            .get_session(&self.mcp_token)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        let (Some(enc), Some(iv)) = (
            session.legacy_imap_password_enc.as_deref(),
            session.legacy_imap_password_iv.as_deref(),
        ) else {
            // Genuinely empty (e.g. brand-new session with no first account
            // yet). Return the empty list; resolve() will surface NoAccounts.
            return Ok(existing);
        };

        let provider = self.providers.first();
        let now = chrono::Utc::now().timestamp();
        // Deterministic account_id derived from oidc_sub + imap_email so that
        // concurrent migrations for the same legacy session converge on the
        // same record (HSET overwrites in-place) rather than producing
        // duplicate accounts under different UUIDs.
        let account_id = legacy_migrated_account_id(&self.oidc_sub, &session.oidc_email);
        let migrated = Account {
            account_id,
            // Lock-in decision: legacy migration uses imap_email as the label
            // so it's immediately distinguishable if the user later adds another.
            label: session.oidc_email.clone(),
            imap_email: session.oidc_email.clone(),
            imap_host: provider.host.clone(),
            imap_port: provider.port,
            password_enc: enc.to_string(),
            password_iv: iv.to_string(),
            created_at: now,
            last_used_at: None,
            auth_failure_count: 0,
            disabled_at: None,
        };

        self.store
            .put_account(&self.oidc_sub, &migrated)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        // The migrated account is the user's only account, so it is the
        // default. `_if_unset` so we don't clobber a default a parallel
        // request might have just set.
        self.store
            .set_default_account_id_if_unset(&self.oidc_sub, &migrated.account_id)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        self.store
            .clear_session_legacy_password(&self.mcp_token)
            .await
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        tracing::info!(
            oidc_sub = %self.oidc_sub,
            account_id = %migrated.account_id,
            "Migrated legacy single-account session to Account record"
        );
        // Return the freshly-migrated single-account list directly. Saves a
        // second `list_accounts` round-trip on the migration path too.
        Ok(vec![migrated])
    }
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

    let resolver = AccountResolver {
        store: state.sessions.clone(),
        providers: state.providers.clone(),
        oidc_sub: session.oidc_sub.clone(),
        oidc_email: session.oidc_email.clone(),
        base_url: state.base_url.clone(),
        mcp_token: token.clone(),
    };

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(state.mcp_allowed_hosts.iter().cloned());

    let service = StreamableHttpService::new(
        move || Ok(mcp::ImapMcpServer::new(resolver.clone())),
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

/// Stable account_id used by the legacy single-account migration shim.
/// Deterministic over `(oidc_sub, imap_email)` so concurrent migrations for
/// the same legacy session converge on the same record. The `mig-` prefix
/// keeps these visually distinct from UUIDs minted for newly-added accounts.
fn legacy_migrated_account_id(oidc_sub: &str, imap_email: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(oidc_sub.as_bytes());
    h.update(b"\x00");
    h.update(imap_email.as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("mig-{}", &hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_migrated_account_id_is_deterministic() {
        let a = legacy_migrated_account_id("sub-1", "alice@x");
        let b = legacy_migrated_account_id("sub-1", "alice@x");
        assert_eq!(a, b);
        assert!(a.starts_with("mig-"));
        assert_eq!(a.len(), "mig-".len() + 32);
    }

    #[test]
    fn legacy_migrated_account_id_differs_per_user() {
        assert_ne!(
            legacy_migrated_account_id("sub-1", "alice@x"),
            legacy_migrated_account_id("sub-2", "alice@x"),
        );
        assert_ne!(
            legacy_migrated_account_id("sub-1", "alice@x"),
            legacy_migrated_account_id("sub-1", "bob@x"),
        );
    }

    #[test]
    fn legacy_migrated_account_id_distinguishes_separator_collisions() {
        // Without a separator, ("a", "b") and ("ab", "") would collide.
        // The NUL byte separator prevents that.
        assert_ne!(
            legacy_migrated_account_id("a", "b"),
            legacy_migrated_account_id("ab", ""),
        );
    }
}
