use imap_mcp::{auth, build_router, session::SessionStore, AppState};
use std::sync::Arc;

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} environment variable is required"))
}

fn env_var_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let gitlab_url = env_var("GITLAB_URL");
    let gitlab_client_id = env_var("GITLAB_CLIENT_ID");
    let gitlab_client_secret = env_var("GITLAB_CLIENT_SECRET");
    let imap_host = env_var("IMAP_HOST");
    let imap_port: u16 = env_var_or("IMAP_PORT", "993").parse()?;
    let base_url = env_var("BASE_URL");
    let redis_url = env_var("REDIS_URL");
    let encryption_key = env_var("ENCRYPTION_KEY");

    let sessions = SessionStore::new(&redis_url, &encryption_key)?;

    tracing::info!("Discovering OIDC configuration from {gitlab_url}");
    let oidc_client = auth::build_oidc_client(
        &gitlab_url,
        &gitlab_client_id,
        &gitlab_client_secret,
        &base_url,
    )
    .await?;

    let state = Arc::new(AppState {
        sessions,
        oidc_client,
        imap_host,
        imap_port,
        base_url,
    });

    let app = build_router(state);

    let bind_addr = env_var_or("BIND_ADDR", "0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server listening on {bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
}
