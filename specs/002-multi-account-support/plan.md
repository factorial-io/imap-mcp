# Multi-Account Support — Plan

Status: Draft proposal
Branch: `claude/multi-account-support-plan-Yr2F7`

## Goals

1. **Shared / non-personal mailboxes.** A team member can connect a shared mailbox (e.g. `billing@factorial.io`, `support@factorial.io`) whose IMAP password they already know.
2. **Private mailboxes on `mail.factorial.io`.** Same flow as today, but the IMAP login email no longer has to match the OIDC email.
3. **Bonus: arbitrary IMAP servers** (Gmail with app password, Fastmail, mailbox.org, …) for users who want to connect a private email account.
4. **Lean** — minimal new surface area; reuse the existing OIDC, encryption, and session machinery.
5. **Safe** — no broader trust model than today; no new secret types; no path to abuse the server as a generic credential prober.

## Non-Goals (for v1)

- Switching between accounts inside a single MCP session / single tool call.
- Cross-account search or unified inbox.
- OAuth/XOAUTH2 against external providers (still password / app-password based).
- A management UI to list, rename, or revoke connected accounts (Redis TTL + re-auth covers this for now).
- Provisioning shared-mailbox passwords centrally — sharing is still out-of-band.

## Current State (concise)

| Concern | Today | Code |
|---|---|---|
| IMAP host/port | Single global env var (`IMAP_HOST`, `IMAP_PORT`) | `src/lib.rs:27-28`, `src/main.rs` |
| IMAP login email | Forced equal to OIDC email claim | `src/auth.rs:223-226`, `src/auth.rs:310-317` |
| IMAP auth | Plain `LOGIN` with password | `src/imap.rs`, `src/auth.rs:310-317` |
| Session | One `Session` per bearer token, holds `email + oidc_sub + encrypted password` | `src/session.rs:58-65` |
| MCP tools | No `account` parameter; implicit single mailbox | `src/mcp.rs:14-28` |
| Per-tool host/port | Hardcoded from `AppState` | `src/lib.rs:134-135`, `src/mcp.rs:32-38` |

Everything except `IMAP_HOST/PORT` and the OIDC-email-equals-IMAP-email assumption is already flexible enough.

## Recommended Design

**One bearer token = one mailbox.** To connect a second mailbox, the user re-runs the OAuth flow and obtains a second token. Claude.ai treats each connector install as independent, so each mailbox shows up as its own connector.

This is the leanest model that gives us all three goals:

- No tool signature changes — `list_emails`, `get_email`, etc. stay as-is.
- No multi-tenant routing inside one session.
- Each session is still a clean `OIDC sub → 1 IMAP login` mapping, which keeps the audit story simple.
- Trade-off: connecting N mailboxes means N connector installs in claude.ai. Acceptable; the per-account installs also keep claude.ai's UI labels distinct.

### Data model changes

`Session`, `AuthCode`, and `PendingSetup` each gain three fields:

```rust
pub imap_email: String,    // user-supplied, may differ from oidc email
pub imap_host: String,     // chosen from a server-side allowlist
pub imap_port: u16,
```

`oidc_sub` and `email` (the OIDC identity claim) stay — this preserves the audit trail of "which human used which mailbox". `email` is renamed to `oidc_email` for clarity; `imap_email` is new.

Backwards compatibility: deserialize legacy sessions by treating missing `imap_*` fields as the old global `IMAP_HOST`/`IMAP_PORT` and `imap_email = oidc_email`. Old tokens keep working until their TTL expires.

### IMAP server allowlist

Introduce a server-side configured list of IMAP providers. Default config ships with one entry (`mail.factorial.io`) and is extended via env or a small JSON file:

```json
[
  { "id": "factorial",  "label": "Factorial",  "host": "mail.factorial.io", "port": 993 },
  { "id": "gmail",      "label": "Gmail",      "host": "imap.gmail.com",    "port": 993, "note": "Use an app password" },
  { "id": "fastmail",   "label": "Fastmail",   "host": "imap.fastmail.com", "port": 993 },
  { "id": "mailbox-org","label": "mailbox.org","host": "imap.mailbox.org",  "port": 993 }
]
```

Why an allowlist:
- Keeps the server from being usable as an open IMAP credential prober against arbitrary hosts.
- Avoids accidental SSRF-adjacent surprises (pointing the IMAP client at internal RFC1918 addresses).
- The list is short and rarely changes; a custom-host option is intentionally **not** offered in v1.
- Users who need a non-listed provider ask the operator to add it — explicit, auditable, low effort.

### Auth flow changes

`/auth/callback` (after successful OIDC) renders an updated setup form:

```
Hi {name}!  ({oidc_email})

Provider:    [ Factorial ▼ ]   ← dropdown from allowlist
IMAP email:  [ alice@factorial.io ]   ← prefilled with oidc_email, editable
Password:    [ … ]
[ Connect ]
```

`POST /auth/setup`:

1. Look up the chosen provider in the allowlist; reject unknown ids.
2. Validate IMAP login against `provider.host:provider.port` with the supplied `imap_email` + password (same code path as today).
3. Persist the chosen `imap_host`, `imap_port`, `imap_email` into the `AuthCode` and ultimately the `Session`.

`mcp_handler` (`src/lib.rs:88-158`) stops reading `state.imap_host/port` and instead reads them from the resolved `Session`. The `AppState` global IMAP host/port becomes a fallback used only for legacy sessions.

### MCP tool layer

No change. `ImapMcpServer::new` already takes host/port as parameters (`src/mcp.rs:21`); we just pass session-derived values into it.

## Alternatives Considered

1. **Multiple accounts per session, with an `account` parameter on every tool.** Richer (cross-account in one conversation), but: changes every tool signature, complicates the MCP schema, requires an "active account" UX, and forces session-storage migration for users who have only one mailbox. Defer to a future iteration if/when there's demand.
2. **Free-form host/port input in the setup form.** Most flexible, but turns the server into a generic IMAP login proxy. Rejected; allowlist instead.
3. **Per-account subdomains / paths** (e.g. `/connect/billing`). Not needed — claude.ai treats each OAuth install as independent already; bearer tokens are unique. Skip.
4. **Server-side mapping of OIDC group → preset shared mailboxes.** Nice future enhancement (auto-suggesting "you can also connect billing@…"), but overlaps with operator-managed allowlists and adds policy code. Out of v1.

## Implementation Phases

1. **Allowlist plumbing.** Add `ImapProvider` struct, load list from env (`IMAP_PROVIDERS` JSON or path to file). Default to a single-entry list pointing at `IMAP_HOST/IMAP_PORT` so existing deployments keep working.
2. **Schema migration.** Extend `Session`/`AuthCode`/`PendingSetup` with `imap_email/host/port`. Add `serde(default)`-based fallbacks for legacy records. Update `SessionStore::create_session` to take the new fields.
3. **Setup form.** Update the HTML in `src/auth.rs:259-288` to render the provider dropdown and the editable IMAP-email field. Add minimal client-side default-fill (no JS framework — plain `<select>`).
4. **`/auth/setup` handler.** Look up provider, validate, store new fields.
5. **`mcp_handler`.** Source IMAP host/port/email from the session.
6. **Tests.** Unit: session/auth-code serialization roundtrip with new fields; legacy decode path. Integration: connecting two different mailboxes from the same OIDC user yields two distinct working tokens; provider-id outside the allowlist is rejected.
7. **Docs.** Update `README` / quickstart with the new env var and a short note on connecting a second mailbox.

Estimated size: ~300–500 LOC delta, almost entirely additive.

## Security Considerations

- **Allowlist enforcement** is the main new control; centralised in one place (`AuthCode` creation) so it can't be bypassed.
- **Rate-limit `/auth/setup` failures** per OIDC `sub` (e.g. 5 failed validations / 10 min) to keep the server from being usable to brute-force passwords against allowlisted providers. Small addition — a Redis counter.
- **Encryption at rest** unchanged: AES-256-GCM with a server-held key. New fields are non-sensitive (host/port/email).
- **Audit trail** improves: each session pairs the verified `oidc_sub` with the mailbox actually used. Log on session create: `oidc_sub=… imap_email=… imap_host=…`.
- **No new secret types**: still username + password. We do not introduce OAuth-against-the-mail-provider flows in v1.
- **Token isolation**: each bearer token still carries exactly one mailbox's credentials. Compromise of a token compromises one account, not a portfolio.
- **Phishing surface**: the setup form lets the user type any IMAP login email. That's already true today (the OIDC email field is just display-only). Not a regression.

## Open Questions

1. Should we offer a "label / nickname" field at setup so the operator (and the user) can distinguish two installs in logs and UI? Probably yes, free-form, length-capped, HTML-escaped on render. Cheap addition.
2. Should the allowlist live in env (`IMAP_PROVIDERS` JSON) or a config file path (`IMAP_PROVIDERS_PATH`)? File is friendlier for ops; env is simpler for the current 12-factor-style setup. Default: env JSON, with a documented escape hatch for ops who want a file.
3. Do we need to gate which providers a given OIDC user/group can pick? Current answer: no — possessing the IMAP password is the access control. Revisit if/when we add OIDC group claims.
4. TTL on connections / sessions when an IMAP login starts failing (password changed, account locked). Today the session sticks around for 30 days even if the password is dead. Worth a cheap follow-up: invalidate session on persistent auth-failed errors.

## Out of Scope / Future Work

- Single-session multi-account with an `account` param on tools.
- OAuth2 / XOAUTH2 against Gmail, Microsoft 365, etc.
- Operator-managed shared-mailbox presets keyed by OIDC group.
- A `/accounts` listing / revocation UI.
