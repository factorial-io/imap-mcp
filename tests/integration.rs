use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
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

/// Build a test AppState with a fake OIDC client and dummy Redis URL.
fn test_state() -> Arc<AppState> {
    let encryption_key = B64.encode([0xABu8; 32]);
    let sessions = SessionStore::new("redis://localhost:6379", &encryption_key).unwrap();
    Arc::new(AppState::new(
        sessions,
        fake_oidc_client(),
        "imap.example.com".to_string(),
        993,
        "https://imap-mcp.example.com".to_string(),
    ))
}

/// Helper: send a request to the test router and get response.
async fn send_request(req: Request<Body>) -> axum::response::Response {
    let app = build_router(test_state());
    app.oneshot(req).await.unwrap()
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
    assert_eq!(json["resource"], "https://imap-mcp.example.com");
    assert!(json["authorization_servers"].is_array());
    assert_eq!(
        json["authorization_servers"][0],
        "https://imap-mcp.example.com"
    );
    assert!(json["bearer_methods_supported"].is_array());
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- MCP endpoint auth tests ---

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
