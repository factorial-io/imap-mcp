use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use imap_mcp::oauth::{self, Identity};
use imap_mcp::providers::ProviderList;
use imap_mcp::{build_router, session::SessionStore, AppState};
use openidconnect::core::{
    CoreClient, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, ClientId, ClientSecret, IssuerUrl, JsonWebKeySetUrl, RedirectUrl, ResponseTypes,
    TokenUrl,
};
use std::sync::Arc;
use tower::ServiceExt;

/// Build a fake OIDC client for testing (no real provider needed).
fn fake_oidc_client() -> CoreClient {
    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new("https://gitlab.example.com".to_string()).unwrap(),
        AuthUrl::new("https://gitlab.example.com/oauth/authorize".to_string()).unwrap(),
        JsonWebKeySetUrl::new("https://gitlab.example.com/oauth/discovery/keys".to_string())
            .unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        Default::default(),
    )
    .set_token_endpoint(Some(
        TokenUrl::new("https://gitlab.example.com/oauth/token".to_string()).unwrap(),
    ));

    CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new("test_client_id".to_string()),
        Some(ClientSecret::new("test_client_secret".to_string())),
    )
    .set_redirect_uri(
        RedirectUrl::new("https://imap-mcp.example.com/auth/callback".to_string()).unwrap(),
    )
}

const BASE_URL: &str = "https://imap-mcp.example.com";

/// Build a test AppState with a fake OIDC client, dummy Redis URL and an
/// in-memory OAuth store.
fn test_state() -> Arc<AppState> {
    let encryption_key = B64.encode([0xABu8; 32]);
    let sessions = SessionStore::new("redis://localhost:6379", &encryption_key).unwrap();
    let providers = ProviderList::factorial_default("imap.example.com", 993).unwrap();
    let signer = oauth::signer(None, &encryption_key).unwrap();
    let store = Arc::new(grantry::memory::MemoryStore::<Identity>::default());
    let oauth_server = oauth::build_server(BASE_URL, signer, store);
    Arc::new(
        AppState::new(
            sessions,
            fake_oidc_client(),
            oauth_server,
            providers,
            BASE_URL.to_string(),
        )
        .unwrap(),
    )
}

/// Helper: send a request to the test router and get response.
async fn send_request(req: Request<Body>) -> axum::response::Response {
    send_request_to(test_state(), req).await
}

async fn send_request_to(state: Arc<AppState>, req: Request<Body>) -> axum::response::Response {
    build_router(state).oneshot(req).await.unwrap()
}

fn alice() -> Identity {
    Identity {
        sub: "alice-sub".to_string(),
        email: "alice@example.com".to_string(),
    }
}

fn mcp_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "imap-mcp.example.com")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        ))
        .unwrap()
}

/// Helper: read response body as string.
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// --- OAuth well-known endpoint tests ---

#[tokio::test]
async fn well_known_oauth_protected_resource_returns_correct_json() {
    let req = Request::builder()
        .uri("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["resource"], "https://imap-mcp.example.com/mcp");
    assert!(json["authorization_servers"].is_array());
    assert_eq!(
        json["authorization_servers"][0],
        "https://imap-mcp.example.com"
    );
    assert!(json["bearer_methods_supported"].is_array());
}

#[tokio::test]
async fn well_known_oauth_protected_resource_with_resource_path() {
    let req = Request::builder()
        .uri("/.well-known/oauth-protected-resource/mcp")
        .body(Body::empty())
        .unwrap();
    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(json["resource"], "https://imap-mcp.example.com/mcp");
}

#[tokio::test]
async fn well_known_oauth_authorization_server_returns_correct_json() {
    let req = Request::builder()
        .uri("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["issuer"], "https://imap-mcp.example.com");
    assert_eq!(
        json["authorization_endpoint"],
        "https://imap-mcp.example.com/auth/login"
    );
    assert_eq!(
        json["token_endpoint"],
        "https://imap-mcp.example.com/auth/token"
    );
    assert_eq!(
        json["registration_endpoint"],
        "https://imap-mcp.example.com/register"
    );
    assert!(json["response_types_supported"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("code")));
    assert!(json["code_challenge_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("S256")));
    assert!(json["grant_types_supported"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("refresh_token")));
    assert_eq!(json["client_id_metadata_document_supported"], false);
}

// --- Dynamic client registration tests ---

#[tokio::test]
async fn register_without_redirect_uris_returns_error() {
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"redirect_uris": []}"#))
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(json["error"], "invalid_redirect_uri");
}

/// Register a client, send an authorization request, and land on our
/// consent entry point with a pending id.
#[tokio::test]
async fn register_then_authorize_redirects_to_consent() {
    let state = test_state();
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"Claude","token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]}"#,
        ))
        .unwrap();
    let resp = send_request_to(state.clone(), req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let client_id = json["client_id"].as_str().unwrap().to_string();

    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let uri = format!(
        "/auth/login?response_type=code&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback\
         &code_challenge={challenge}&code_challenge_method=S256&state=xyz\
         &resource=https%3A%2F%2Fimap-mcp.example.com%2Fmcp"
    );
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = send_request_to(state.clone(), req).await;
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(
        location.starts_with("https://imap-mcp.example.com/auth/connect?pending="),
        "unexpected redirect: {location}"
    );
    let pending: uuid::Uuid = location.rsplit('=').next().unwrap().parse().unwrap();
    let found = state
        .oauth
        .pending(pending, &alice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.client_name, "Claude");
    assert_eq!(found.scope, "mail offline_access");
}

#[tokio::test]
async fn authorize_with_wrong_resource_redirects_with_error() {
    let state = test_state();
    let registered = state
        .oauth
        .register(
            serde_json::json!({"redirect_uris": ["https://claude.ai/cb"]})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
    let uri = format!(
        "/auth/login?response_type=code&client_id={}\
         &redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256&state=s&resource=https%3A%2F%2Fevil.example",
        registered.client_id
    );
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = send_request_to(state, req).await;
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("https://claude.ai/cb?error=invalid_target"));
}

// --- MCP endpoint auth tests ---

#[tokio::test]
async fn mcp_accepts_grantry_access_token() {
    let state = test_state();
    let (_grant, tokens) = state
        .oauth
        .issue_grant(alice(), "client", "Claude", "")
        .await
        .unwrap();
    assert!(tokens.refresh_token.is_some());
    let resp = send_request_to(state, mcp_request(&tokens.access_token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_rejects_token_of_revoked_grant() {
    let state = test_state();
    let (_grant, tokens) = state
        .oauth
        .issue_grant(alice(), "client", "Claude", "")
        .await
        .unwrap();
    assert!(state
        .oauth
        .revoke_token(&tokens.access_token, "logout", None)
        .await
        .unwrap());
    let resp = send_request_to(state, mcp_request(&tokens.access_token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www_auth = resp.headers()["www-authenticate"].to_str().unwrap();
    assert!(www_auth.contains(r#"error="invalid_token""#));
}

#[tokio::test]
async fn mcp_rejects_token_without_mail_scope() {
    let state = test_state();
    let (_grant, tokens) = state
        .oauth
        .issue_grant(alice(), "client", "Claude", "offline_access")
        .await
        .unwrap();
    let resp = send_request_to(state, mcp_request(&tokens.access_token)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_without_bearer_returns_401_with_www_authenticate() {
    let req = Request::builder().uri("/mcp").body(Body::empty()).unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("should have WWW-Authenticate header")
        .to_str()
        .unwrap();
    assert!(
        www_auth.contains("resource_metadata="),
        "WWW-Authenticate should contain resource_metadata"
    );
    assert!(
        www_auth.contains("/.well-known/oauth-protected-resource"),
        "WWW-Authenticate should point to oauth-protected-resource"
    );

    let body = body_string(resp).await;
    assert_eq!(body, "Bearer token required");
}

#[tokio::test]
async fn mcp_with_invalid_bearer_returns_401() {
    let req = Request::builder()
        .uri("/mcp")
        .header("authorization", "Bearer invalid-token-xyz")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = body_string(resp).await;
    assert_eq!(body, "Invalid or expired token");
}

#[tokio::test]
async fn mcp_with_wrong_auth_scheme_returns_401() {
    let req = Request::builder()
        .uri("/mcp")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = body_string(resp).await;
    assert_eq!(body, "Bearer token required");
}

#[tokio::test]
async fn mcp_subpath_without_bearer_returns_401() {
    let req = Request::builder()
        .uri("/mcp/sse")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Auth endpoint tests ---

#[tokio::test]
async fn auth_login_without_params_returns_error() {
    let req = Request::builder()
        .uri("/auth/login")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    // Missing required query params → 422
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422, got {status}"
    );
}

#[tokio::test]
async fn auth_setup_rejects_get_method() {
    let req = Request::builder()
        .method("GET")
        .uri("/auth/setup")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn auth_token_rejects_get_method() {
    let req = Request::builder()
        .method("GET")
        .uri("/auth/token")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn nonexistent_route_returns_404() {
    let req = Request::builder()
        .uri("/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- MCP tool parameter deserialization tests ---

#[test]
fn list_emails_params_defaults() {
    let json = r#"{}"#;
    let params: imap_mcp::mcp::ListEmailsParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.folder, "INBOX");
    assert_eq!(params.limit, 20);
    assert_eq!(params.offset, 0);
}

#[test]
fn list_emails_params_custom() {
    let json = r#"{"folder": "Sent", "limit": 50, "offset": 10}"#;
    let params: imap_mcp::mcp::ListEmailsParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.folder, "Sent");
    assert_eq!(params.limit, 50);
    assert_eq!(params.offset, 10);
}

#[test]
fn get_email_params_with_defaults() {
    let json = r#"{"uid": 42}"#;
    let params: imap_mcp::mcp::GetEmailParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.uid, 42);
    assert_eq!(params.folder, "INBOX");
}

#[test]
fn search_emails_params_defaults() {
    let json = r#"{"query": "UNSEEN"}"#;
    let params: imap_mcp::mcp::SearchEmailsParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.query, "UNSEEN");
    assert_eq!(params.folder, "INBOX");
    assert_eq!(params.limit, 20);
}

#[test]
fn mark_params_with_defaults() {
    let json = r#"{"uid": 99}"#;
    let params: imap_mcp::mcp::MarkParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.uid, 99);
    assert_eq!(params.folder, "INBOX");
}

#[test]
fn mark_params_custom_folder() {
    let json = r#"{"uid": 1, "folder": "Archive"}"#;
    let params: imap_mcp::mcp::MarkParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.uid, 1);
    assert_eq!(params.folder, "Archive");
}

#[test]
fn list_emails_params_accepts_account() {
    let json = r#"{"account": "billing"}"#;
    let params: imap_mcp::mcp::ListEmailsParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.account.as_deref(), Some("billing"));
    assert_eq!(params.folder, "INBOX");
}

// --- /manage route tests ---

#[tokio::test]
async fn manage_without_ticket_or_cookie_redirects_to_oidc() {
    let req = Request::builder()
        .uri("/manage")
        .body(Body::empty())
        .unwrap();
    let resp = send_request(req).await;
    // Temporary redirect to /auth/manage_login (no cookie, no ticket).
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect should have location")
        .to_str()
        .unwrap();
    assert!(
        location.ends_with("/auth/manage_login"),
        "expected /auth/manage_login, got {location}"
    );
}

#[tokio::test]
async fn manage_add_account_without_cookie_returns_401() {
    let req = Request::builder()
        .method("POST")
        .uri("/manage/accounts")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "csrf_token=x&provider_id=factorial&label=L&imap_email=a@b&imap_password=p",
        ))
        .unwrap();
    let resp = send_request(req).await;
    // AppError::Auth(...) maps to 401 in error.rs.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn manage_delete_account_without_cookie_returns_401() {
    let req = Request::builder()
        .method("POST")
        .uri("/manage/accounts/some-id/delete")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("csrf_token=x"))
        .unwrap();
    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn manage_set_default_without_cookie_returns_401() {
    let req = Request::builder()
        .method("POST")
        .uri("/manage/accounts/some-id/set_default")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("csrf_token=x"))
        .unwrap();
    let resp = send_request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
