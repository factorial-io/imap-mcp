//! The OAuth 2.1 authorization server claude.ai talks to, built on `grantry`.
//!
//! grantry owns the protocol: dynamic client registration, the authorization
//! request, PKCE, codes, the token endpoint, refresh-token rotation and the
//! discovery documents. This module wires it to the app: the subject type
//! ([`Identity`]), the paths, the scopes, the signing key and the audit hooks.
//!
//! Login and consent stay in [`crate::auth`]: grantry stores a valid
//! authorization request as *pending* and sends the browser to
//! [`CONSENT_PATH`], where the user signs in with OIDC and connects a mailbox;
//! `auth::setup` then approves the pending request.

use std::sync::Arc;

use async_trait::async_trait;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use grantry::metadata::{AuthorizationServerMetadata, ProtectedResourceMetadata};
use grantry::routes::Routes;
use grantry::store::{BackendError, Events, Grant, OAuthStore, Recheck, Subjects};
use grantry::{Algorithm, Config, NoFetch, ScopeSpec, Server, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// The authorization server, over [`Identity`] subjects.
pub type OAuthServer = Server<Identity>;

/// Whom a grant is for: the verified OIDC identity that owns the mailboxes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub sub: String,
    pub email: String,
}

/// The authorization endpoint. Kept at the pre-grantry path so clients that
/// cached the old metadata keep working.
pub const AUTHORIZE_PATH: &str = "/auth/login";
pub const TOKEN_PATH: &str = "/auth/token";
pub const REGISTER_PATH: &str = "/register";
/// Where grantry sends the browser with a pending authorization: our OIDC
/// login, then the mailbox setup form.
pub const CONSENT_PATH: &str = "/auth/connect";

/// The scope that grants mailbox access.
pub const MAIL_SCOPE: &str = "mail";
const OFFLINE_SCOPE: &str = "offline_access";

/// The `kind` claim of our access tokens.
const TOKEN_KIND: &str = "imap-mcp";

/// Refresh tokens unused this long stop working; matches the 30-day sliding
/// lifetime of the pre-grantry sessions.
const REFRESH_IDLE_DAYS: i64 = 30;

/// Long enough for an OIDC login plus typing an IMAP password.
const PENDING_TTL_MINUTES: i64 = 20;

/// The protected resource (RFC 8707): the MCP endpoint, as users enter it in
/// claude.ai. Authorization requests must name it as `resource`, and it is the
/// `aud` of every access token.
pub fn resource_url(base_url: &str) -> String {
    format!("{base_url}/mcp")
}

/// Both scopes by default, so a client that asks for none still gets a
/// refresh token.
pub fn scopes() -> ScopeSpec {
    ScopeSpec::new(
        &[MAIL_SCOPE, OFFLINE_SCOPE],
        &[MAIL_SCOPE, OFFLINE_SCOPE],
        OFFLINE_SCOPE,
    )
}

/// The access-token signer: HS256 over `TOKEN_SIGNING_KEY` (base64) when set,
/// otherwise over a key derived from `ENCRYPTION_KEY`, so existing
/// deployments need no new secret. The derivation is a domain-separated
/// SHA-256, so the signing key never equals the encryption key.
pub fn signer(
    token_signing_key_b64: Option<&str>,
    encryption_key_b64: &str,
) -> Result<Signer, AppError> {
    if let Some(key) = token_signing_key_b64 {
        let decoded = B64
            .decode(key)
            .map_err(|e| AppError::Encryption(format!("invalid TOKEN_SIGNING_KEY base64: {e}")))?;
        if decoded.len() < 32 {
            return Err(AppError::Encryption(
                "TOKEN_SIGNING_KEY must be at least 32 bytes".to_string(),
            ));
        }
        return Ok(Signer::hmac(Algorithm::HS256, &decoded));
    }
    let encryption_key = B64
        .decode(encryption_key_b64)
        .map_err(|e| AppError::Encryption(format!("invalid base64 key: {e}")))?;
    let mut h = Sha256::new();
    h.update(b"imap-mcp/access-token-signing/v1\x00");
    h.update(&encryption_key);
    Ok(Signer::hmac(Algorithm::HS256, &h.finalize()))
}

/// Build the authorization server over `store`.
pub fn build_server(
    base_url: &str,
    signer: Signer,
    store: Arc<dyn OAuthStore<Subject = Identity>>,
) -> OAuthServer {
    let config = Config {
        pending_ttl: chrono::Duration::minutes(PENDING_TTL_MINUTES),
        ..Config::new(resource_url(base_url), TOKEN_KIND, scopes(), signer)
    };
    Server::new(
        config,
        store,
        Arc::new(AllowAll),
        Arc::new(LogEvents),
        // Clients register dynamically; we do not fetch Client ID Metadata
        // Documents (that would need an egress policy against SSRF).
        Arc::new(NoFetch),
    )
    .with_refresh_idle(chrono::Duration::days(REFRESH_IDLE_DAYS))
}

/// grantry's protocol routes: authorization server metadata, authorize, token
/// and register.
pub fn router(server: OAuthServer, base_url: &str) -> axum::Router {
    let mut metadata = AuthorizationServerMetadata::new(
        base_url,
        AUTHORIZE_PATH,
        TOKEN_PATH,
        Some(REGISTER_PATH),
        &scopes().known,
    );
    metadata.client_id_metadata_document_supported = false;
    let consent_base = format!("{base_url}{CONSENT_PATH}");
    let routes = Routes {
        metadata,
        authorize_path: AUTHORIZE_PATH.to_string(),
        token_path: TOKEN_PATH.to_string(),
        register_path: Some(REGISTER_PATH.to_string()),
        consent_url: Arc::new(move |id| format!("{consent_base}?pending={id}")),
        other_grant: None,
    };
    grantry::routes::router(server, routes)
}

/// The RFC 9728 document for the MCP endpoint.
pub fn protected_resource_metadata(base_url: &str) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata::new(
        &resource_url(base_url),
        base_url,
        &scopes().known,
        Some("IMAP MCP"),
    )
}

/// Where the protected resource metadata is served (and what 401s point at).
pub fn protected_resource_metadata_url(base_url: &str) -> String {
    format!("{base_url}/.well-known/oauth-protected-resource")
}

/// GET /.well-known/oauth-protected-resource (and its `/mcp` suffix form).
pub async fn oauth_protected_resource(
    axum::extract::State(state): axum::extract::State<Arc<crate::AppState>>,
) -> Response {
    Json(protected_resource_metadata(&state.base_url)).into_response()
}

/// Every grant's subject may keep its tokens: mailbox access is checked per
/// tool call against the user's `Account` records, not here.
struct AllowAll;

#[async_trait]
impl Subjects<Identity> for AllowAll {
    async fn recheck(&self, _grant: &Grant<Identity>) -> Result<Recheck, BackendError> {
        Ok(Recheck::Allow(serde_json::Map::new()))
    }
}

/// Audit log of grant lifecycle events.
struct LogEvents;

#[async_trait]
impl Events<Identity> for LogEvents {
    async fn grant_created(&self, grant: &Grant<Identity>) {
        tracing::info!(
            oidc_sub = %grant.subject.sub,
            grant_id = %grant.id,
            client_id = %grant.client_id,
            client_name = %grant.client_name,
            scope = %grant.scope,
            "OAuth grant created"
        );
    }

    async fn grant_revoked(&self, grant: &Grant<Identity>, reason: &str, _client_ip: Option<&str>) {
        tracing::warn!(
            oidc_sub = %grant.subject.sub,
            grant_id = %grant.id,
            client_id = %grant.client_id,
            reason = %reason,
            "OAuth grant revoked"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_signer_differs_from_explicit_key() {
        let enc = B64.encode([0xABu8; 32]);
        let derived = signer(None, &enc).unwrap();
        let explicit = signer(Some(&enc), &enc).unwrap();
        let store = Arc::new(grantry::memory::MemoryStore::<Identity>::default());
        let a = build_server("https://x", derived, store.clone());
        let b = build_server("https://x", explicit, store);
        let claims = grantry::token::AccessClaims {
            resource: "https://x/mcp",
            kind: TOKEN_KIND,
            scope: MAIL_SCOPE,
            client_id: "c",
            grant_id: "00000000-0000-0000-0000-000000000000",
        };
        let token = grantry::token::mint(
            &a.config.signer,
            chrono::Utc::now(),
            60,
            &claims,
            serde_json::Map::new(),
        )
        .unwrap();
        assert!(a.verify(&token).is_ok());
        assert!(b.verify(&token).is_err());
    }

    #[test]
    fn short_signing_key_is_refused() {
        let enc = B64.encode([0xABu8; 32]);
        assert!(signer(Some(&B64.encode([1u8; 16])), &enc).is_err());
    }

    #[test]
    fn resource_is_the_mcp_endpoint() {
        let doc = protected_resource_metadata("https://imap.example");
        assert_eq!(doc.resource, "https://imap.example/mcp");
        assert_eq!(doc.authorization_servers, ["https://imap.example"]);
    }
}
