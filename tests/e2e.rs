//! End-to-end test: the real `imap-mcp` binary against Redis, a mock OIDC
//! provider and a scripted IMAP server over TLS, driven the way an MCP client
//! (claude.ai) and a user's browser would drive it.
//!
//! Needs a Redis server. Set `E2E_REDIS_URL` to use a running one; otherwise
//! the test starts `redis-server` from `PATH` on a free port. The tests are
//! `#[ignore]`d so `cargo test` works without Redis; run them with
//!
//! ```bash
//! cargo test --test e2e -- --ignored
//! ```
//!
//! The IMAP server's certificate is issued by a test CA
//! (`tests/fixtures/e2e/ca.pem`); the binary trusts it through OpenSSL's
//! `SSL_CERT_FILE`, so no production code path is bypassed.

use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

const OIDC_CLIENT_ID: &str = "imap-mcp-e2e";
const OIDC_CLIENT_SECRET: &str = "e2e-client-secret";
const USER_SUB: &str = "e2e-user-1";
const USER_EMAIL: &str = "alice@example.com";
const USER_NAME: &str = "Alice Example";
const IMAP_PASSWORD: &str = "correct horse battery staple";
const MCP_CLIENT_REDIRECT: &str = "http://127.0.0.1:9/mcp-client/callback";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/e2e")
        .join(name)
}

async fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?.port())
}

async fn serve(router: Router) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(format!("http://{addr}"))
}

/// HTTP client for the test itself: no redirects (we inspect each hop), no
/// proxy (everything is on loopback).
fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?)
}

fn location(resp: &reqwest::Response) -> Result<String> {
    ensure!(
        resp.status().is_redirection(),
        "expected a redirect, got {} from {}",
        resp.status(),
        resp.url()
    );
    Ok(resp
        .headers()
        .get("location")
        .ok_or_else(|| anyhow!("redirect without Location"))?
        .to_str()?
        .to_string())
}

fn query_param(url: &str, name: &str) -> Result<String> {
    let url = url::Url::parse(url).with_context(|| format!("not a URL: {url}"))?;
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow!("no `{name}` in {url}"))
}

fn pkce_challenge(verifier: &str) -> String {
    B64URL.encode(Sha256::digest(verifier.as_bytes()))
}

// --- Redis ---

struct Redis {
    url: String,
    _child: Option<Child>,
}

async fn redis() -> Result<Redis> {
    if let Ok(url) = std::env::var("E2E_REDIS_URL") {
        return Ok(Redis { url, _child: None });
    }
    let port = free_port().await?;
    let child = Command::new("redis-server")
        .args([
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
        ])
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("starting redis-server (install it or set E2E_REDIS_URL)")?;
    let url = format!("redis://127.0.0.1:{port}");
    let client = redis::Client::open(url.as_str())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
            let pong: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut conn).await;
            if pong.is_ok() {
                break;
            }
        }
        ensure!(Instant::now() < deadline, "redis-server did not come up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(Redis {
        url,
        _child: Some(child),
    })
}

// --- Mock OIDC provider ---

#[derive(Default)]
struct OidcState {
    issuer: String,
    /// Authorization codes handed out, with what the token endpoint checks.
    codes: HashMap<String, IssuedCode>,
    /// Successful code exchanges, for assertions.
    exchanges: usize,
}

struct IssuedCode {
    nonce: String,
    redirect_uri: String,
    code_challenge: String,
}

type Oidc = Arc<Mutex<OidcState>>;

fn lock(oidc: &Oidc) -> Result<std::sync::MutexGuard<'_, OidcState>> {
    oidc.lock().map_err(|_| anyhow!("OIDC state poisoned"))
}

fn signing_key() -> Result<CoreRsaPrivateSigningKey> {
    let pem = std::fs::read_to_string(fixture("oidc-signing.pem"))?;
    CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("e2e".into())))
        .map_err(|e| anyhow!("bad OIDC signing key: {e}"))
}

struct OidcError(anyhow::Error);
impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, format!("mock OIDC: {:#}", self.0)).into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for OidcError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

/// `ensure!` for the mock provider's handlers, which answer with `OidcError`.
macro_rules! check {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(OidcError(anyhow!($($msg)+)));
        }
    };
}

async fn oidc_discovery(State(oidc): State<Oidc>) -> Result<Json<Value>, OidcError> {
    let issuer = lock(&oidc)?.issuer.clone();
    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    })))
}

async fn oidc_jwks() -> Result<Json<Value>, OidcError> {
    Ok(Json(
        json!({ "keys": [signing_key()?.as_verification_key()] }),
    ))
}

/// The user is already signed in at the provider: validate the request and
/// redirect straight back with a code.
async fn oidc_authorize(
    State(oidc): State<Oidc>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Redirect, OidcError> {
    let param = |k: &str| {
        q.get(k)
            .cloned()
            .ok_or_else(|| anyhow!("authorize request lacks {k}"))
    };
    check!(param("client_id")? == OIDC_CLIENT_ID, "wrong client_id");
    check!(param("response_type")? == "code", "wrong response_type");
    check!(
        param("code_challenge_method")? == "S256",
        "PKCE must be S256"
    );
    let scopes = param("scope")?;
    for s in ["openid", "email", "profile"] {
        check!(scopes.split(' ').any(|x| x == s), "scope lacks {s}");
    }
    let redirect_uri = param("redirect_uri")?;
    let code = uuid::Uuid::new_v4().to_string();
    lock(&oidc)?.codes.insert(
        code.clone(),
        IssuedCode {
            nonce: param("nonce")?,
            redirect_uri: redirect_uri.clone(),
            code_challenge: param("code_challenge")?,
        },
    );
    let mut back = url::Url::parse(&redirect_uri)?;
    back.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &param("state")?);
    Ok(Redirect::to(back.as_str()))
}

async fn oidc_token(
    State(oidc): State<Oidc>,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, OidcError> {
    let expected = format!(
        "Basic {}",
        B64.encode(format!("{OIDC_CLIENT_ID}:{OIDC_CLIENT_SECRET}"))
    );
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    check!(auth == expected, "client authentication failed");
    let field = |k: &str| {
        form.get(k)
            .cloned()
            .ok_or_else(|| anyhow!("token request lacks {k}"))
    };
    check!(field("grant_type")? == "authorization_code", "wrong grant");

    let (issuer, issued) = {
        let mut state = lock(&oidc)?;
        let issued = state
            .codes
            .remove(&field("code")?)
            .ok_or_else(|| anyhow!("unknown or reused code"))?;
        (state.issuer.clone(), issued)
    };
    check!(
        field("redirect_uri")? == issued.redirect_uri,
        "redirect_uri"
    );
    check!(
        pkce_challenge(&field("code_verifier")?) == issued.code_challenge,
        "PKCE verification failed"
    );

    let now = jiff::Timestamp::now().as_second();
    let claims: CoreIdTokenClaims = serde_json::from_value(json!({
        "iss": issuer,
        "aud": [OIDC_CLIENT_ID],
        "sub": USER_SUB,
        "email": USER_EMAIL,
        "email_verified": true,
        "name": USER_NAME,
        "nonce": issued.nonce,
        "iat": now,
        "exp": now + 300,
    }))?;
    let id_token = CoreIdToken::new(
        claims,
        &signing_key()?,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )?;
    lock(&oidc)?.exchanges += 1;
    Ok(Json(json!({
        "access_token": "provider-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    })))
}

async fn mock_oidc() -> Result<(String, Oidc)> {
    let oidc: Oidc = Arc::default();
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/jwks", get(oidc_jwks))
        .route("/authorize", get(oidc_authorize))
        .route("/token", post(oidc_token))
        .with_state(oidc.clone());
    let issuer = serve(router).await?;
    lock(&oidc)?.issuer = issuer.clone();
    Ok((issuer, oidc))
}

// --- Scripted IMAP server over TLS ---

/// Commands the IMAP server received, without tags, e.g. `LOGIN ...`.
type ImapLog = Arc<Mutex<Vec<String>>>;

async fn imap_server() -> Result<(u16, ImapLog)> {
    let cert = std::fs::read(fixture("imap.pem"))?;
    let key = std::fs::read(fixture("imap.key"))?;
    let identity = native_tls::Identity::from_pkcs8(&cert, &key)?;
    let acceptor: async_native_tls::TlsAcceptor = native_tls::TlsAcceptor::new(identity)?.into();
    let acceptor = Arc::new(acceptor);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let log: ImapLog = Arc::default();
    let conn_log = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let log = conn_log.clone();
            tokio::spawn(async move {
                if let Err(e) = imap_session(&acceptor, tcp, &log).await {
                    eprintln!("fake IMAP session ended: {e:#}");
                }
            });
        }
    });
    Ok((port, log))
}

async fn imap_session(
    acceptor: &async_native_tls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    log: &ImapLog,
) -> Result<()> {
    let tls = acceptor.accept(tcp).await?;
    let (read, mut write) = tokio::io::split(tls);
    let mut lines = BufReader::new(read).lines();
    write
        .write_all(b"* OK [CAPABILITY IMAP4rev1] e2e IMAP ready\r\n")
        .await?;
    let expected_login = format!("LOGIN \"{USER_EMAIL}\" \"{IMAP_PASSWORD}\"");
    let mut authenticated = false;
    while let Some(line) = lines.next_line().await? {
        let (tag, command) = line
            .split_once(' ')
            .ok_or_else(|| anyhow!("malformed IMAP line: {line}"))?;
        log.lock()
            .map_err(|_| anyhow!("IMAP log poisoned"))?
            .push(command.to_string());
        let verb = command
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reply = match verb.as_str() {
            "CAPABILITY" => format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n"),
            "LOGIN" if command == expected_login => {
                authenticated = true;
                format!("{tag} OK LOGIN completed\r\n")
            }
            "LOGIN" => format!("{tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n"),
            "LIST" if authenticated => format!(
                "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
                 * LIST (\\HasNoChildren \\Trash) \"/\" \"Papierkorb\"\r\n\
                 {tag} OK LIST completed\r\n"
            ),
            "LOGOUT" => {
                write
                    .write_all(format!("* BYE bye\r\n{tag} OK LOGOUT completed\r\n").as_bytes())
                    .await?;
                return Ok(());
            }
            _ => format!("{tag} BAD unsupported in e2e server\r\n"),
        };
        write.write_all(reply.as_bytes()).await?;
    }
    Ok(())
}

// --- The server under test ---

struct Server {
    base: String,
    child: Child,
    log_path: PathBuf,
    _redis: Redis,
}

impl Server {
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

async fn start_server(oidc_issuer: &str, imap_port: u16) -> Result<Server> {
    let redis = redis().await?;
    let port = free_port().await?;
    let base = format!("http://127.0.0.1:{port}");
    let log_path = std::env::temp_dir().join(format!("imap-mcp-e2e-{port}.log"));
    let log = std::fs::File::create(&log_path)?;
    let child = Command::new(env!("CARGO_BIN_EXE_imap-mcp"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("OIDC_ISSUER_URL", oidc_issuer)
        .env("OIDC_CLIENT_ID", OIDC_CLIENT_ID)
        .env("OIDC_CLIENT_SECRET", OIDC_CLIENT_SECRET)
        .env("IMAP_HOST", "localhost")
        .env("IMAP_PORT", imap_port.to_string())
        .env("BASE_URL", &base)
        .env("REDIS_URL", &redis.url)
        .env("ENCRYPTION_KEY", B64.encode([0x42u8; 32]))
        .env("BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("SSL_CERT_FILE", fixture("ca.pem"))
        .env("RUST_LOG", "info,imap_mcp=debug")
        .env("NO_COLOR", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .context("starting imap-mcp")?;
    let mut server = Server {
        base,
        child,
        log_path,
        _redis: redis,
    };

    let client = http()?;
    let probe = format!("{}/.well-known/oauth-authorization-server", server.base);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = server.child.try_wait()? {
            bail!("imap-mcp exited with {status}:\n{}", server.logs());
        }
        if let Ok(resp) = client.get(&probe).send().await {
            if resp.status() == StatusCode::OK {
                return Ok(server);
            }
        }
        if Instant::now() > deadline {
            bail!("imap-mcp did not become ready:\n{}", server.logs());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct Env {
    server: Server,
    oidc: Oidc,
    imap_log: ImapLog,
    client: reqwest::Client,
}

async fn env() -> Result<Env> {
    let (issuer, oidc) = mock_oidc().await?;
    let (imap_port, imap_log) = imap_server().await?;
    let server = start_server(&issuer, imap_port).await?;
    Ok(Env {
        server,
        oidc,
        imap_log,
        client: http()?,
    })
}

/// What the MCP client holds once the user reaches the mailbox setup form.
struct AtSetup {
    client_id: String,
    code_verifier: String,
    setup_id: String,
    provider_id: String,
}

/// Register an MCP client, start its authorization and walk the user through
/// the OIDC login up to the mailbox setup form.
async fn sign_in_to_setup(env: &Env) -> Result<AtSetup> {
    let base = &env.server.base;
    let c = &env.client;

    // Dynamic client registration, as claude.ai does it.
    let resp = c
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [MCP_CLIENT_REDIRECT],
            "client_name": "E2E MCP Client",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }))
        .send()
        .await?;
    ensure!(
        resp.status() == StatusCode::CREATED,
        "register: {}",
        resp.status()
    );
    let client_id = resp.json::<Value>().await?["client_id"]
        .as_str()
        .ok_or_else(|| anyhow!("no client_id"))?
        .to_string();

    // Authorization request with PKCE.
    let code_verifier = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let mut authorize = url::Url::parse(&format!("{base}/auth/login"))?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", MCP_CLIENT_REDIRECT)
        .append_pair("code_challenge", &pkce_challenge(&code_verifier))
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", "client-state")
        .append_pair("resource", &format!("{base}/mcp"));
    let resp = c.get(authorize.as_str()).send().await?;
    let consent = location(&resp)?;
    ensure!(
        consent.starts_with(&format!("{base}/auth/connect?pending=")),
        "authorize redirected to {consent}"
    );

    // Consent step sends the browser to the OIDC provider ...
    let resp = c.get(&consent).send().await?;
    let to_provider = location(&resp)?;
    let issuer = lock(&env.oidc)?.issuer.clone();
    ensure!(
        to_provider.starts_with(&format!("{issuer}/authorize?")),
        "consent redirected to {to_provider}"
    );
    // ... which signs the user in and sends them back with a code.
    let resp = c.get(&to_provider).send().await?;
    let callback = location(&resp)?;
    ensure!(
        callback.starts_with(&format!("{base}/auth/callback?")),
        "provider redirected to {callback}"
    );

    let resp = c.get(&callback).send().await?;
    let status = resp.status();
    let html = resp.text().await?;
    ensure!(status == StatusCode::OK, "callback: {status}: {html}");
    ensure!(
        html.contains(USER_NAME),
        "setup form does not greet the user"
    );
    ensure!(
        html.contains("E2E MCP Client"),
        "setup form does not name the client"
    );
    let setup_id = attr_after(&html, r#"name="setup_id" value=""#)?;
    let provider_id = attr_after(&html, r#"<option value=""#)?;
    Ok(AtSetup {
        client_id,
        code_verifier,
        setup_id,
        provider_id,
    })
}

fn attr_after(html: &str, prefix: &str) -> Result<String> {
    let rest = html
        .split_once(prefix)
        .ok_or_else(|| anyhow!("`{prefix}` not in page"))?
        .1;
    Ok(rest.split('"').next().unwrap_or_default().to_string())
}

async fn submit_setup(env: &Env, at: &AtSetup, password: &str) -> Result<reqwest::Response> {
    Ok(env
        .client
        .post(format!("{}/auth/setup", env.server.base))
        .form(&[
            ("setup_id", at.setup_id.as_str()),
            ("provider_id", at.provider_id.as_str()),
            ("label", "Work"),
            ("imap_email", USER_EMAIL),
            ("imap_password", password),
        ])
        .send()
        .await?)
}

async fn token(env: &Env, form: &[(&str, &str)]) -> Result<Value> {
    let resp = env
        .client
        .post(format!("{}/auth/token", env.server.base))
        .form(form)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    ensure!(status == StatusCode::OK, "token endpoint: {status}: {body}");
    Ok(body)
}

/// One JSON-RPC call to `/mcp`.
async fn mcp(env: &Env, access_token: &str, id: u64, method: &str, params: Value) -> Result<Value> {
    let resp = env
        .client
        .post(format!("{}/mcp", env.server.base))
        .bearer_auth(access_token)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18")
        .json(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    ensure!(status == StatusCode::OK, "{method}: {status}: {body}");
    let msg: Value = serde_json::from_str(&body).with_context(|| format!("{method}: {body}"))?;
    ensure!(msg.get("error").is_none(), "{method} failed: {msg}");
    msg.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method}: no result in {msg}"))
}

fn imap_commands(env: &Env) -> Result<Vec<String>> {
    Ok(env
        .imap_log
        .lock()
        .map_err(|_| anyhow!("IMAP log poisoned"))?
        .clone())
}

/// Run `body`, attaching the server's log on failure.
async fn with_logs<F: std::future::Future<Output = Result<()>>>(env: &Env, body: F) -> Result<()> {
    body.await
        .map_err(|e| anyhow!("{e:#}\n--- imap-mcp log ---\n{}", env.server.logs()))
}

#[tokio::test]
#[ignore = "needs Redis: run with `cargo test --test e2e -- --ignored`"]
async fn mcp_client_connects_mailbox_and_lists_folders() -> Result<()> {
    let env = env().await?;
    with_logs(&env, async {
        let base = env.server.base.clone();

        // Unauthenticated MCP requests point at the protected resource metadata.
        let resp = env.client.post(format!("{base}/mcp")).send().await?;
        ensure!(resp.status() == StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        ensure!(
            challenge.contains("/.well-known/oauth-protected-resource"),
            "challenge: {challenge}"
        );

        let at = sign_in_to_setup(&env).await?;
        ensure!(
            lock(&env.oidc)?.exchanges == 1,
            "OIDC code not exchanged once"
        );

        // Connect the mailbox: the server validates the password over IMAPS
        // and hands the MCP client its authorization code.
        let resp = submit_setup(&env, &at, IMAP_PASSWORD).await?;
        ensure!(
            resp.status() == StatusCode::SEE_OTHER,
            "setup: {}",
            resp.status()
        );
        let back = location(&resp)?;
        ensure!(
            back.starts_with(MCP_CLIENT_REDIRECT),
            "setup redirected to {back}"
        );
        ensure!(query_param(&back, "state")? == "client-state");
        let code = query_param(&back, "code")?;

        let resource = format!("{base}/mcp");
        let tokens = token(
            &env,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", MCP_CLIENT_REDIRECT),
                ("client_id", &at.client_id),
                ("code_verifier", &at.code_verifier),
                ("resource", &resource),
            ],
        )
        .await?;
        let access = tokens["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("no access_token: {tokens}"))?
            .to_string();
        let refresh = tokens["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("no refresh_token: {tokens}"))?
            .to_string();

        // MCP session with the access token.
        let init = mcp(
            &env,
            &access,
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "e2e", "version": "0" },
            }),
        )
        .await?;
        ensure!(init["serverInfo"].is_object(), "initialize: {init}");

        let tools = mcp(&env, &access, 2, "tools/list", json!({})).await?;
        let names: Vec<&str> = tools["tools"]
            .as_array()
            .ok_or_else(|| anyhow!("tools/list: {tools}"))?
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for expected in ["list_folders", "list_emails", "get_email", "list_accounts"] {
            ensure!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }

        let folders = mcp(
            &env,
            &access,
            3,
            "tools/call",
            json!({ "name": "list_folders", "arguments": {} }),
        )
        .await?;
        ensure!(folders["isError"] != json!(true), "list_folders: {folders}");
        let text = folders["content"][0]["text"]
            .as_str()
            .ok_or_else(|| anyhow!("list_folders: {folders}"))?;
        let listed: Value = serde_json::from_str(text)?;
        let listed: Vec<&str> = listed
            .as_array()
            .ok_or_else(|| anyhow!("folders: {listed}"))?
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        ensure!(listed == ["INBOX", "Papierkorb"], "folders: {listed:?}");

        let accounts = mcp(
            &env,
            &access,
            4,
            "tools/call",
            json!({ "name": "list_accounts", "arguments": {} }),
        )
        .await?;
        let accounts = accounts.to_string();
        ensure!(
            accounts.contains("Work") && accounts.contains(USER_EMAIL),
            "{accounts}"
        );

        // The mailbox password reached the IMAP server, and only that one.
        let commands = imap_commands(&env)?;
        let logins: Vec<_> = commands.iter().filter(|c| c.starts_with("LOGIN")).collect();
        ensure!(
            logins.len() == 2,
            "setup + list_folders should log in twice: {commands:?}"
        );
        ensure!(
            commands.iter().any(|c| c.starts_with("LIST")),
            "{commands:?}"
        );

        // Refresh rotates the refresh token; the new access token works.
        let refreshed = token(
            &env,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &at.client_id),
                ("resource", &resource),
            ],
        )
        .await?;
        let new_access = refreshed["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("refresh: {refreshed}"))?;
        let new_refresh = refreshed["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("refresh: {refreshed}"))?;
        ensure!(new_refresh != refresh, "refresh token was not rotated");
        mcp(&env, new_access, 5, "tools/list", json!({})).await?;

        // A token the server did not issue is refused.
        let forged = env
            .client
            .post(format!("{base}/mcp"))
            .bearer_auth(format!("{access}x"))
            .header("accept", "application/json, text/event-stream")
            .json(&json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/list" }))
            .send()
            .await?;
        ensure!(
            forged.status() == StatusCode::UNAUTHORIZED,
            "forged: {}",
            forged.status()
        );

        // The code is single-use, and replaying it revokes the whole grant
        // (OAuth 2.1 section 4.1.3): the tokens issued so far stop working.
        let reuse = env
            .client
            .post(format!("{base}/auth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", MCP_CLIENT_REDIRECT),
                ("client_id", at.client_id.as_str()),
                ("code_verifier", at.code_verifier.as_str()),
                ("resource", resource.as_str()),
            ])
            .send()
            .await?;
        ensure!(
            reuse.status() == StatusCode::BAD_REQUEST,
            "code reuse: {}",
            reuse.status()
        );

        let after = env
            .client
            .post(format!("{base}/mcp"))
            .bearer_auth(new_access)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }))
            .send()
            .await?;
        ensure!(
            after.status() == StatusCode::UNAUTHORIZED,
            "token still valid after code replay: {}",
            after.status()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "needs Redis: run with `cargo test --test e2e -- --ignored`"]
async fn wrong_imap_password_is_rejected_at_setup() -> Result<()> {
    let env = env().await?;
    with_logs(&env, async {
        let at = sign_in_to_setup(&env).await?;
        let resp = submit_setup(&env, &at, "not the password").await?;
        ensure!(
            resp.status() == StatusCode::UNAUTHORIZED,
            "setup with a wrong password: {}",
            resp.status()
        );
        ensure!(
            !resp.headers().contains_key("location"),
            "a failed setup must not redirect to the MCP client"
        );
        let commands = imap_commands(&env)?;
        ensure!(
            commands.iter().any(|c| c.starts_with("LOGIN")),
            "password was not checked against IMAP: {commands:?}"
        );
        Ok(())
    })
    .await
}
