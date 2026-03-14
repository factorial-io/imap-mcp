# IMAP MCP Server

A self-hosted Rust service that acts as a multi-tenant IMAP MCP server for claude.ai, using GitLab OIDC for authentication.

Users authenticate via GitLab, enter their IMAP password once, and then claude.ai accesses their email through the MCP protocol using a Bearer token.

## Prerequisites

- Docker and Docker Compose
- A GitLab instance with OAuth application configured
- An IMAP mail server (TLS, port 993)
- Traefik reverse proxy (for HTTPS) or equivalent

## GitLab OAuth App Setup

1. Go to **GitLab > Settings > Applications** (admin or user-level)
2. Create a new application:
   - **Name**: IMAP MCP Server
   - **Redirect URI**: `https://<YOUR_DOMAIN>/auth/callback`
   - **Scopes**: `openid`, `profile`, `email`
   - **Confidential**: Yes
3. Note the **Application ID** and **Secret**

## Deployment

1. Clone this repository:

```bash
git clone <repo-url> && cd imap-mcp
```

2. Create your `.env` file:

```bash
cp .env.example .env
```

3. Fill in the values:

```bash
# Generate an encryption key
openssl rand -base64 32
# Paste it as ENCRYPTION_KEY in .env
```

Edit `.env` with your GitLab OAuth credentials, IMAP host, public domain, etc.

4. Deploy with Docker Compose:

```bash
docker compose up -d
```

The service will be available at `https://<YOUR_DOMAIN>`.

## Adding the MCP Server in claude.ai

1. Open [claude.ai](https://claude.ai)
2. Go to **Settings > Integrations > Add MCP Server**
3. Enter the URL: `https://<YOUR_DOMAIN>/mcp`
4. Claude.ai will open a popup for authentication:
   - You'll be redirected to GitLab to log in
   - After login, enter your IMAP password in the setup form
   - The form validates your credentials against the IMAP server
   - On success, you'll receive a Bearer token
5. The MCP server is now connected — claude.ai can read your email

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_folders` | List all IMAP mailbox folders |
| `list_emails` | List emails in a folder (uid, date, from, subject, seen flag) |
| `get_email` | Fetch full email by UID (headers + plain text body) |
| `search_emails` | Search emails using IMAP SEARCH criteria |
| `mark_read` | Set \Seen flag on an email by UID |
| `mark_unread` | Unset \Seen flag on an email by UID |

## Architecture

```
User → claude.ai → Bearer token → /mcp endpoint
                                       ↓
                              Validate token (Redis)
                                       ↓
                              Decrypt IMAP password
                                       ↓
                              Connect to IMAP server
                                       ↓
                              Execute MCP tool
                                       ↓
                              Return results to claude.ai
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITLAB_URL` | Yes | GitLab instance URL |
| `GITLAB_CLIENT_ID` | Yes | OAuth application ID |
| `GITLAB_CLIENT_SECRET` | Yes | OAuth application secret |
| `IMAP_HOST` | Yes | IMAP server hostname |
| `IMAP_PORT` | No | IMAP port (default: 993) |
| `BASE_URL` | Yes | Public URL of this service, no trailing slash |
| `REDIS_URL` | Yes | Redis connection URL |
| `ENCRYPTION_KEY` | Yes | 32-byte AES-256 key, base64-encoded |
| `RUST_LOG` | No | Log level (default: info) |
| `BIND_ADDR` | No | Listen address (default: 0.0.0.0:8080) |

## Local Development

A `docker-compose.dev.yml` is provided for local testing with claude.ai using ngrok as a tunnel.

### Prerequisites

- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) — secrets are stored in 1Password
- An [ngrok](https://ngrok.com/) account (free tier works, paid gives a stable domain)

### Setup

1. Copy the example env file and fill in your GitLab OAuth credentials in 1Password (vault: **Employee**, item: **IMAP MCP Server**):

```bash
cp .env.example .env
```

2. Set `BASE_URL` in `.env` to your ngrok URL (see step 4).

3. Configure the GitLab OAuth app redirect URI to `https://<NGROK_URL>/auth/callback`.

4. Start all services:

```bash
op run --env-file=.env -- docker compose -f docker-compose.dev.yml up --build
```

5. Get the ngrok public URL:

```bash
curl -s http://localhost:4040/api/tunnels | jq '.tunnels[0].public_url'
```

Or open http://localhost:4040 in your browser.

6. Update `BASE_URL` in `.env` with the ngrok URL and restart the app:

```bash
op run --env-file=.env -- docker compose -f docker-compose.dev.yml restart imap-mcp
```

If you have a reserved ngrok domain, set `NGROK_DOMAIN` in `.env` to skip steps 5-6.

### Connect claude.ai

1. Go to **Settings > Integrations > Add MCP Server** on [claude.ai](https://claude.ai)
2. Enter the URL: `https://<NGROK_URL>/mcp`
3. Authenticate via GitLab and enter your IMAP password
4. Try prompts like "List my email folders" or "Show my latest emails"

## Security

- PKCE (S256) is mandatory for the OIDC flow
- IMAP passwords are encrypted at rest with AES-256-GCM
- IMAP passwords are never logged or returned in responses
- Session tokens are opaque UUIDs (not JWTs)
- Sessions expire after 30 days, refreshed on each use
- IMAP connections are opened per-request (no persistent pool)
