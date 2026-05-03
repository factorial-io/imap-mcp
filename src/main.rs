use clap::Parser;
use imap_mcp::{auth, build_router, providers::ProviderList, session::SessionStore, AppState};
use std::sync::Arc;

/// Server configuration. Most fields are sourced from environment variables;
/// `--imap-providers` is a CLI override that wins over the `IMAP_PROVIDERS`
/// env var.
#[derive(Parser, Debug)]
#[command(version, about = "IMAP MCP server", long_about = None)]
struct Cli {
    #[arg(long, env = "OIDC_ISSUER_URL")]
    oidc_issuer_url: String,

    #[arg(long, env = "OIDC_CLIENT_ID")]
    oidc_client_id: String,

    #[arg(long, env = "OIDC_CLIENT_SECRET")]
    oidc_client_secret: String,

    /// Default IMAP host. Used as the sole entry of the provider allowlist
    /// when neither --imap-providers nor IMAP_PROVIDERS is set, and as the
    /// migration target for legacy single-account sessions.
    #[arg(long, env = "IMAP_HOST")]
    imap_host: String,

    #[arg(long, env = "IMAP_PORT", default_value_t = 993)]
    imap_port: u16,

    #[arg(long, env = "BASE_URL")]
    base_url: String,

    #[arg(long, env = "REDIS_URL")]
    redis_url: String,

    #[arg(long, env = "ENCRYPTION_KEY")]
    encryption_key: String,

    #[arg(long, env = "BIND_ADDR", default_value = "0.0.0.0:8080")]
    bind_addr: String,

    /// IMAP provider allowlist. Either inline JSON (starting with `[`) or a
    /// path to a JSON file. Wins over the `IMAP_PROVIDERS` env var.
    /// When neither is set, the allowlist contains exactly one entry pointing
    /// at `--imap-host` / `--imap-port`.
    #[arg(long)]
    imap_providers: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Provider allowlist: --imap-providers (CLI) wins over IMAP_PROVIDERS (env);
    // either may be inline JSON or a path. If neither is set, the default
    // ships with a single entry pointing at IMAP_HOST/IMAP_PORT.
    let providers = if let Some(raw) = cli.imap_providers.as_deref() {
        ProviderList::parse_inline_or_path(raw)?
    } else if let Ok(raw) = std::env::var("IMAP_PROVIDERS") {
        ProviderList::parse_inline_or_path(&raw)?
    } else {
        ProviderList::factorial_default(&cli.imap_host, cli.imap_port)?
    };

    tracing::info!(
        providers = ?providers.iter().map(|p| &p.id).collect::<Vec<_>>(),
        "IMAP provider allowlist loaded"
    );

    let sessions = SessionStore::new(&cli.redis_url, &cli.encryption_key)?;

    tracing::info!(
        "Discovering OIDC configuration from {}",
        cli.oidc_issuer_url
    );
    let oidc_client = auth::build_oidc_client(
        &cli.oidc_issuer_url,
        &cli.oidc_client_id,
        &cli.oidc_client_secret,
        &cli.base_url,
    )
    .await?;

    let state = Arc::new(AppState::new(
        sessions,
        oidc_client,
        providers,
        cli.base_url,
    ));

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind_addr).await?;
    tracing::info!("Server listening on {}", cli.bind_addr);

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
