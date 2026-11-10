//! The full OAuth code flow over the production Redis store. Needs a Redis
//! server: `REDIS_URL=redis://127.0.0.1:6379 cargo test --test redis_flow -- --ignored`.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use imap_mcp::oauth::{self, Identity};
use sha2::{Digest, Sha256};

#[tokio::test]
#[ignore = "needs a Redis server at REDIS_URL"]
async fn code_flow_over_redis_store() -> anyhow::Result<()> {
    let url = std::env::var("REDIS_URL")?;
    let conn = redis::Client::open(url.as_str())?
        .get_connection_manager()
        .await?;
    let prefix = format!("test:{}:", uuid::Uuid::new_v4());
    let store = Arc::new(grantry_redis::RedisStore::<Identity>::with_prefix(
        conn, prefix,
    ));
    let signer = oauth::signer(None, &B64.encode([7u8; 32]))?;
    let server = oauth::build_server("https://imap.example", signer, store);

    let client = server
        .register(
            serde_json::json!({"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude"})
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("not an object"))?,
        )
        .await?;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let query = format!(
        "response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb\
         &code_challenge={challenge}&code_challenge_method=S256&state=st\
         &resource=https%3A%2F%2Fimap.example%2Fmcp",
        client.client_id
    );
    let pending = server.authorize(&query).await?;
    let me = Identity {
        sub: "sub-1".into(),
        email: "a@example.com".into(),
    };
    // Callback binds, setup approves.
    assert!(server
        .pending(pending.id, &me)
        .await
        .map_err(|e| anyhow::anyhow!(e))?
        .is_some());
    let other = Identity {
        sub: "sub-2".into(),
        email: "b@example.com".into(),
    };
    assert!(server
        .pending(pending.id, &other)
        .await
        .map_err(|e| anyhow::anyhow!(e))?
        .is_none());
    let approved = server.approve(pending.id, &me, None).await?;
    let redirect = url::Url::parse(&approved.redirect)?;
    let params: HashMap<_, _> = redirect.query_pairs().into_owned().collect();
    assert_eq!(params.get("state").map(String::as_str), Some("st"));

    let form: HashMap<String, String> = [
        ("grant_type", "authorization_code"),
        ("code", params["code"].as_str()),
        ("redirect_uri", "https://claude.ai/cb"),
        ("code_verifier", verifier),
        ("resource", "https://imap.example/mcp"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let tokens = server
        .exchange_code(&form, Some(&client.client_id), None)
        .await?;
    let (grant, _) = server.verify_active(&tokens.access_token).await?;
    assert_eq!(grant.subject, me);
    assert_eq!(grant.scope, "mail offline_access");

    let refresh = tokens
        .refresh_token
        .ok_or_else(|| anyhow::anyhow!("no refresh token"))?;
    let (_, next) = server.refresh(&refresh, &client.client_id, None).await?;
    assert!(server.verify_active(&next.access_token).await.is_ok());
    // Replaying the rotated refresh token revokes the grant.
    assert!(server
        .refresh(&refresh, &client.client_id, None)
        .await
        .is_err());
    assert!(server.verify_active(&next.access_token).await.is_err());
    Ok(())
}
