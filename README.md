# IMAP MCP Server

[![CI](https://github.com/factorial-io/imap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/factorial-io/imap-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A self-hosted Rust service that acts as a multi-tenant IMAP MCP server for claude.ai, using any OpenID Connect provider for authentication.

Users authenticate via their OIDC provider (e.g. GitLab, Keycloak, Auth0), connect one or more IMAP mailboxes (personal, shared team boxes, or — when the operator enables them — private accounts on Gmail, Fastmail, etc.), and then claude.ai accesses email across those mailboxes through the MCP protocol using a Bearer token. Each Claude install corresponds to one OIDC identity and may hold multiple connected mailboxes.

## Prerequisites

- Docker and Docker Compose
- An OpenID Connect provider (GitLab, Keycloak, Auth0, etc.) with an OAuth application configured
- An IMAP mail server (TLS, port 993)
- Traefik reverse proxy (for HTTPS) or equivalent

## System dependencies

Some attachment formats are extracted by shelling out to external binaries.
Install them on the host where the server runs:

| Format | Binary | Install |
| --- | --- | --- |
| Legacy `.doc` (Word 97-2003) | `antiword` | `apt install antiword` (Debian/Ubuntu) |

If `antiword` is not on `PATH`, `.doc` attachments are returned as metadata
only and the server logs a clear "extractor not installed" error. PDF, DOCX,
XLSX, PPTX, and modern formats are handled natively and require nothing extra.

LibreOffice (`soffice --headless --convert-to txt`) is a heavier alternative
that also handles `.doc` and many other legacy formats; it is not wired up
by default but can be substituted by users who already run it.

## OIDC Provider Setup

Create an OAuth/OIDC application in your identity provider:

- **Redirect URI**: `https://<YOUR_DOMAIN>/auth/callback`
- **Scopes**: `openid`, `profile`, `email`
- **Confidential**: Yes

Note the **Client ID**, **Client Secret**, and **Issuer URL** (e.g. `https://gitlab.example.com`).

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

Edit `.env` with your OIDC credentials, IMAP host, public domain, etc.

4. Deploy with Docker Compose:

```bash
docker compose up -d
```

The service will be available at `https://<YOUR_DOMAIN>`.

## Adding the MCP Server in claude.ai

1. Open [claude.ai](https://claude.ai)
2. Go to **Settings > Integrations > Add MCP Server**
3. Enter the URL: `https://<YOUR_DOMAIN>/mcp`
4. Claude.ai handles the OAuth flow automatically:
   - Registers itself as an OAuth client (RFC 7591 dynamic registration)
   - Opens a popup where you log in via your OIDC provider
   - After login, enter your IMAP password in the setup form
   - The form validates your credentials against the IMAP server
   - On success, claude.ai receives an access token via OAuth code exchange
5. The MCP server is now connected — claude.ai can read your email

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_accounts` | List the user's connected mailboxes (account_id, label, IMAP login, host, last-used time, disabled flag) and return a 15-minute signed `manage_url` for adding/removing accounts |
| `add_account_url` | Return a fresh 15-minute signed link the user opens in a browser to connect another mailbox |
| `list_folders` | List all IMAP mailbox folders |
| `create_folder` | Create a new IMAP folder (supports hierarchy separators) |
| `list_emails` | List emails in a folder (uid, date, from, subject, seen flag) |
| `get_email` | Fetch full email by UID (headers + plain text body, S/MIME signed supported) |
| `search_emails` | Search emails using IMAP SEARCH criteria |
| `mark_read` | Set \Seen flag on an email by UID |
| `mark_unread` | Unset \Seen flag on an email by UID |
| `move_email` | Move an email to another folder by UID |
| `delete_email` | Delete an email by UID (moves to Trash, undoable) |
| `get_attachment` | Fetch an attachment (text, image, or extracted text from PDF/Office docs) |
| `create_draft` / `update_draft` | Compose or modify a draft email |

Every IMAP-touching tool accepts an optional `account` parameter (the
`account_id` from `list_accounts`, or the user's chosen `label`). When the
user has only one mailbox connected the parameter is optional and defaults
to it; when they have more than one it is required.

## Multi-Account Support

Each OIDC-authenticated user can connect multiple IMAP mailboxes behind a
single Claude connector install (Team plans don't let end users add more
connectors themselves, so all of a user's mailboxes live under one bearer
token).

- The first account is connected during initial OIDC login.
- Subsequent accounts are added at `https://<YOUR_DOMAIN>/manage`. The URL
  is also returned, fresh and signed with a 15-minute lifetime, by the
  `list_accounts` and `add_account_url` MCP tools.
- The `/manage` page lets the user list, add, and remove mailboxes. v1
  doesn't support renaming — delete and re-add to change a label.
- An account is auto-disabled after 3 consecutive IMAP login failures and
  must be re-validated in `/manage`.

## IMAP Provider Allowlist

The server only logs into IMAP hosts on a server-side allowlist. The default
ships with exactly one entry pointing at `IMAP_HOST` / `IMAP_PORT`
(intended for `mail.factorial.io`). External providers (Gmail with an app
password, Fastmail, mailbox.org, …) are opt-in by the operator at deploy
time:

- `IMAP_PROVIDERS` env var: a JSON list (or path to a JSON file).
- `--imap-providers <path-or-json>` CLI flag: same JSON shape, wins over
  the env var.

```json
[
  { "id": "factorial",  "label": "Factorial",  "host": "mail.factorial.io", "port": 993 },
  { "id": "gmail",      "label": "Gmail",      "host": "imap.gmail.com",    "port": 993, "note": "Use an app password" },
  { "id": "fastmail",   "label": "Fastmail",   "host": "imap.fastmail.com", "port": 993 }
]
```

Custom hosts are not user-enterable; broadening the list is an operator
action. Users without an entry on the allowlist cannot connect that mailbox.

## Architecture

```
claude.ai → POST /register (dynamic client registration)
         → GET  /auth/login (OAuth authorize → redirects to OIDC provider)
                    → OIDC provider login
                    → GET /auth/callback (IMAP setup form: provider + login + password + nickname)
                    → POST /auth/setup (validate IMAP, create first Account, generate auth code)
                    → redirect to claude.ai with authorization code
         → POST /auth/token (exchange code for access token, PKCE verified)
         → POST /mcp (Bearer token → MCP JSON-RPC)
                    ↓
           Validate token (Redis)
                    ↓
           Resolve Account from oidc_sub + optional `account` selector
                    ↓
           Decrypt IMAP password (AES-256-GCM)
                    ↓
           Connect to IMAP server (TLS); record last_used_at on success,
           bump auth_failure_count on auth failure (auto-disable at 3)
                    ↓
           Execute MCP tool
                    ↓
           Return results to claude.ai

User → GET  /manage?t=<ticket>  (15-min single-use link from MCP tools)
     → cookie session set, page renders the user's accounts
     → POST /manage/accounts          (add a mailbox; CSRF-protected)
     → POST /manage/accounts/{id}/delete (remove a mailbox; CSRF-protected)
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ISSUER_URL` | Yes | OIDC provider URL (e.g. `https://gitlab.example.com`) |
| `OIDC_CLIENT_ID` | Yes | OIDC application client ID |
| `OIDC_CLIENT_SECRET` | Yes | OIDC application client secret |
| `IMAP_HOST` | Yes | Default IMAP host. Used as the sole entry of the provider allowlist when `IMAP_PROVIDERS` is unset, and as the migration target for legacy single-account sessions. |
| `IMAP_PORT` | No | Default IMAP port (default: 993) |
| `IMAP_PROVIDERS` | No | JSON list (or path to JSON file) of allowed IMAP providers. Replaces the default single-entry allowlist. See "IMAP Provider Allowlist" above. May also be supplied via the `--imap-providers` CLI flag, which takes precedence. |
| `BASE_URL` | Yes | Public URL of this service, no trailing slash |
| `REDIS_URL` | Yes | Redis connection URL |
| `ENCRYPTION_KEY` | Yes | 32-byte AES-256 key, base64-encoded |
| `RUST_LOG` | No | Log level (default: info) |
| `BIND_ADDR` | No | Listen address (default: 0.0.0.0:8080) |

## Kubernetes Deployment

You can also host imap-mcp on Kubernetes. The container image is published to `ghcr.io/factorial-io/imap-mcp`.

### Requirements

- A Kubernetes cluster (1.24+)
- An **Ingress controller** (e.g. nginx-ingress, Traefik) with TLS termination — claude.ai requires HTTPS
- A **Redis** instance accessible from the cluster (e.g. via [Bitnami Redis Helm chart](https://github.com/bitnami/charts/tree/main/bitnami/redis) or a managed service)
- An **OIDC provider** with a configured OAuth application (see [OIDC Provider Setup](#oidc-provider-setup))
- A **Secret** containing the environment variables listed in [Environment Variables](#environment-variables)

### Minimal manifests

Create a Secret with your configuration:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: imap-mcp
stringData:
  OIDC_ISSUER_URL: "https://gitlab.example.com"
  OIDC_CLIENT_ID: "your-client-id"
  OIDC_CLIENT_SECRET: "your-client-secret"
  IMAP_HOST: "mail.example.com"
  BASE_URL: "https://imap-mcp.example.com"
  REDIS_URL: "redis://redis:6379"
  ENCRYPTION_KEY: "<output of: openssl rand -base64 32>"
```

Deploy the application:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: imap-mcp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: imap-mcp
  template:
    metadata:
      labels:
        app: imap-mcp
    spec:
      containers:
        - name: imap-mcp
          image: ghcr.io/factorial-io/imap-mcp:latest
          ports:
            - containerPort: 8080
          envFrom:
            - secretRef:
                name: imap-mcp
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: imap-mcp
spec:
  selector:
    app: imap-mcp
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: imap-mcp
spec:
  tls:
    - hosts:
        - imap-mcp.example.com
      secretName: imap-mcp-tls
  rules:
    - host: imap-mcp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: imap-mcp
                port:
                  number: 80
```

Adjust the Ingress annotations for your ingress controller and TLS setup. The container runs as a non-root user and listens on port 8080.

## Local Development

A `docker-compose.dev.yml` is provided for local testing with claude.ai using ngrok as a tunnel.

### Prerequisites

- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) — secrets are stored in 1Password
- An [ngrok](https://ngrok.com/) account (free tier works, paid gives a stable domain)

### Setup

1. Copy the example env file and fill in your OIDC credentials in 1Password (vault: **Employee**, item: **IMAP MCP Server**):

```bash
cp .env.example .env
```

2. Set `BASE_URL` in `.env` to your ngrok URL (see step 4).

3. Configure the OIDC provider's redirect URI to `https://<NGROK_URL>/auth/callback`.

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
3. Authenticate via your OIDC provider and enter your IMAP password
4. Try prompts like "List my email folders" or "Show my latest emails"

## Security

- OAuth 2.0 with PKCE (S256) for the full authorization flow
- Dynamic client registration (RFC 7591) — redirect URIs must use HTTPS
- IMAP passwords are encrypted at rest with AES-256-GCM and wrapped in `SecretString` in memory
- IMAP passwords are never logged or returned in responses
- Session tokens are opaque UUIDs (not JWTs)
- Sessions expire after 30 days, refreshed on each use
- Authorization codes are single-use with 5-minute TTL
- IMAP input validation prevents command injection via folder names and search queries
- HTML output is escaped to prevent XSS
- CORS restricted to required methods and headers
- Container runs as non-root user
- IMAP connections are opened per-request (no persistent pool)

## License

MIT -- see [LICENSE](LICENSE).

## Acknowledgements

Development time and API tokens sponsored by [Factorial.io](https://www.factorial.io/).
