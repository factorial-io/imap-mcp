# Multi-Account Support — Plan

Status: Draft proposal (revision 2)
Branch: `claude/multi-account-support-plan-Yr2F7`

## Goals

1. **Shared / non-personal mailboxes.** A team member can connect a shared mailbox (e.g. `billing@factorial.io`, `support@factorial.io`) whose IMAP password they already know.
2. **Private mailboxes on `mail.factorial.io`.** Same flow as today, but the IMAP login email no longer has to match the OIDC email.
3. **Bonus: arbitrary IMAP servers** (Gmail with app password, Fastmail, mailbox.org, …) for users who want to connect a private email account.
4. **Lean** — minimal new surface area; reuse the existing OIDC, encryption, and session machinery.
5. **Safe** — no broader trust model than today; no new secret types; no path to abuse the server as a generic credential prober.

## Platform Constraint (drives this revision)

We use a **Claude Team plan**. End users on the desktop app cannot add or configure MCP connectors themselves — connectors are installed centrally by a workspace admin and appear once, identically, for every team member. That rules out the v1 design (one bearer token = one mailbox; "to add another, reconnect"): there is no per-user UI to install the same connector a second time with different parameters.

Consequence: a single connector install must surface multiple mailboxes per user, behind one bearer token, with tool calls able to pick which mailbox they target.

## Non-Goals

- Cross-account search or a unified inbox tool.
- OAuth/XOAUTH2 against external providers (still password / app-password based).
- **Operator-managed shared-mailbox credential distribution** (admin pre-loads shared credentials, OIDC groups grant access). Confirmed off the roadmap — every team member who wants a shared mailbox supplies its IMAP password themselves. The credential-sharing problem stays out-of-band, not in this server.
- A polished UI for managing accounts. v1 ships a minimal HTML page; richer UX is later work.

## Decisions (locked in)

- **OIDC identity and IMAP login may differ.** Users can connect a mailbox whose address doesn't match their OIDC email. Both `oidc_sub` / `oidc_email` and `account_id` / `imap_email` are written to every audit log line.
- **Token blast radius is accepted.** A bearer token reaches every account that user has connected. Audit logging per `account_id` and per-account revocation in `/manage` are sufficient; we don't add per-account sub-tokens, step-up auth, or a forced shorter session TTL on top of the existing 30 days in v1.
- **External providers are off by default.** The provider allowlist ships with `mail.factorial.io` only; any non-Factorial provider is opt-in by the operator (see "IMAP provider allowlist" below).

## Current State (concise)

| Concern | Today | Code |
|---|---|---|
| IMAP host/port | Single global env var (`IMAP_HOST`, `IMAP_PORT`) | `src/lib.rs:27-28`, `src/main.rs` |
| IMAP login email | Forced equal to OIDC email claim | `src/auth.rs:223-226`, `src/auth.rs:310-317` |
| IMAP auth | Plain `LOGIN` with password | `src/imap.rs`, `src/auth.rs:310-317` |
| Session | One `Session` per bearer token, holds `email + oidc_sub + encrypted password` | `src/session.rs:58-65` |
| MCP tools | No `account` parameter; implicit single mailbox | `src/mcp.rs:14-28` |
| Per-tool host/port | Hardcoded from `AppState` | `src/lib.rs:134-135`, `src/mcp.rs:32-38` |

## Recommended Design

**One bearer token → one OIDC identity → N IMAP accounts.**

A bearer token resolves to a verified `oidc_sub`. Accounts attach to that `sub`, so any token for the same human sees the same account list. Every IMAP-touching tool gains an optional `account` parameter; the server defaults to the user's only account when there's exactly one, and requires explicit selection when there's more than one.

### Data model

Two Redis records per user:

- `mcp:session:{token}` → `{ oidc_sub, oidc_email, created_at }` (no IMAP credentials).
- `mcp:accounts:{oidc_sub}` → list of `Account` records:

```rust
pub struct Account {
    pub account_id:        String,  // server-issued stable slug
    pub label:             String,  // user-supplied nickname, e.g. "Billing"
    pub imap_email:        String,
    pub imap_host:         String,  // must be in the provider allowlist
    pub imap_port:         u16,
    pub password_enc:      String,  // AES-256-GCM, unchanged scheme
    pub password_iv:       String,
    pub created_at:        i64,
    pub last_used_at:      Option<i64>,  // updated on each successful tool call
    pub auth_failure_count: u32,    // consecutive failures since last success
    pub disabled_at:       Option<i64>, // set when auto-disabled
}
```

The verified `oidc_sub` is the trust anchor; tokens are references to it. Revoking a token doesn't lose accounts. Migration shim: legacy single-account sessions are read once and rewritten as one auto-generated `Account` keyed under their `oidc_sub`, with `label = imap_email` (unambiguous and distinct if the user later adds another account).

### Onboarding flow

- **Initial connect** (existing OAuth flow, lightly extended). OIDC → setup form → user picks provider from the allowlist, supplies IMAP email + password + nickname → first `Account` created and attached to `oidc_sub` → bearer token issued.
- **Adding another mailbox.** The MCP server exposes a small `/manage` page (server-side rendered HTML, OIDC-protected, no JS framework). The page lists the user's accounts and lets them add or remove one. The page does **not** support renaming in v1 — to change a label, delete the account and re-add it. Users reach `/manage` via:
  - The `manage_url` returned by the new `list_accounts` MCP tool (a 15-minute single-use ticket — see "manage_url ticket scheme" below).
  - A new `add_account_url` MCP tool that returns the same kind of ticket-link without first listing accounts (for "add my Gmail" intents).
  - A direct bookmark to `https://<mcp-host>/manage`.
- **Removing an account** deletes the record from Redis. Other accounts and the bearer token are unaffected.

### MCP tool changes

- New tool: `list_accounts` → `[{ account_id, label, imap_email, imap_host, last_used_at, disabled }, …]`, plus a short-lived signed `manage_url` for adding/removing accounts.
- New tool: `add_account_url` → `{ url, expires_at }`. Returns a fresh 15-minute signed `/manage` link. For when the agent's intent is "add a new mailbox" without first enumerating existing ones.
- Every existing tool gains an optional `account` parameter (`account_id` or `label`). Resolution rules:
  - 0 accounts → error with the `manage_url` ("No mailboxes connected — open … to add one").
  - 1 account → `account` optional, defaults to that one.
  - 2+ accounts → `account` required; on omission the error tells the agent to call `list_accounts` first.
- `label` is accepted as a convenience for agent ergonomics; ambiguous labels error.

### `manage_url` ticket scheme

`manage_url` is **not** a cryptographically signed token. It carries an
opaque random UUID stored as a server-side Redis record:

- `mgmt:ticket:{uuid}` → `{ oidc_sub, oidc_email, created_at }` with a
  900-second TTL.
- The first GET to `/manage?t=<uuid>` redeems the ticket: it is read,
  validated against the live Redis record, and **deleted** (single-use).
  A separate `mgmt_session` cookie is set that persists for the rest of
  the management session.
- An attacker who steals a `manage_url` from a transcript or browser
  history can use it once, within 15 minutes, after which it's
  unusable. They cannot forge new ones — minting requires either a valid
  bearer token (via the `list_accounts` / `add_account_url` MCP tools)
  or an interactive OIDC flow at `/auth/manage_login`.

We deliberately don't use HMAC- or JWT-style signed URLs here: a
random-UUID-with-Redis-lookup avoids signing-key management, has no
forgery surface even if a server-side leak happens, and gets revocation
(via Redis flush) for free. The trade-off is one Redis round-trip per
redemption, which is fine.

The cookie session itself is an opaque UUID stored under
`mgmt:session:{uuid}` with a 30-minute TTL; CSRF tokens for mutations
live alongside it in the same record. No bearer-token-only path exists
to add or remove accounts.

### Behavior at the 1→2 account transition

Adding a second account changes the tool API contract for that user:
the optional `account` parameter becomes effectively required on every
IMAP-touching tool call. We treat this as a deliberate sharp edge
rather than a bug:

- The `account_required` error message is explicit ("Multiple mailboxes
  are connected — pass `account` (account_id or label). Call
  list_accounts to see them.") so the agent can recover by calling
  `list_accounts` and re-issuing the call.
- We do **not** introduce a sticky default. A sticky default would have
  to be read+written on every call, would need a UI to change, and
  would mask the multi-account state from the agent in ways that
  surface worse later (e.g. when the sticky account becomes disabled).
- The `/manage` page should later grow a one-line note above the "Add"
  form when the user already has one account ("Adding a second mailbox
  means future tool calls must specify `account` — pass an account_id
  or label"). This is a UX polish item, not a correctness item, so it
  ships as a follow-up.

### IMAP provider allowlist

Env-configured list of `{ id, label, host, port }`. Default ships with **only** `mail.factorial.io`; external providers (Gmail, Fastmail, mailbox.org, …) are opt-in by the operator at deploy time. Two equivalent ways to enable them, mirroring how `main.rs` reads config today:

- `IMAP_PROVIDERS` env var: JSON list of provider entries that **replaces** the default. The deployment that wants Gmail + Fastmail in addition to Factorial sets the full list explicitly.
- `--imap-providers <path-or-json>` CLI flag (added together with a small `clap`-based arg layer in `main.rs`): same JSON format, points at a file or accepts inline JSON. CLI wins over env if both are set.

The `/manage` form's provider dropdown is built from this list at startup. Custom hosts are not user-enterable; broadening the list is an operator action only.

### Account auto-disable on auth failure

After **3 consecutive** failed IMAP logins for the same account, the resolver marks the account `disabled` (sets `disabled_at`) and stops attempting it. Subsequent tool calls return a clear "credentials no longer valid — re-validate at `<manage_url>`" error that includes a fresh signed `manage_url`. Re-validating the password successfully in `/manage` clears `disabled_at` and resets `auth_failure_count`. Any successful login also resets the counter, so transient blips don't accumulate over days.

### Audit trail

Every IMAP operation logs `{ oidc_sub, account_id, imap_email, imap_host, tool, outcome }`. `oidc_sub` is the human; `account_id` is which mailbox they used. `last_used_at` on the account is updated on success.

## Alternatives Considered

1. **One bearer token = one mailbox, user installs the connector N times** (v1 of this plan). Rejected: not possible on Team plans where users can't add connectors.
2. **Single admin-managed global account list, no per-user accounts.** Simplest for the operator, but doesn't cover the "private email account" goal and forces every team member to share credentials for the same accounts. Rejected.
3. **Free-form host/port input** instead of an allowlist. Same trade-off as v1: rejected, allowlist instead.
4. **Operator-curated shared mailboxes with OIDC-group ACLs** (admin pre-loads `billing@factorial.io` once, OIDC group `team-billing` gets read/write). Rejected per product direction: shared-mailbox credential distribution stays out-of-band; users supply the password themselves.

## Implementation Phases

1. **Schema split.** Move IMAP credentials out of `Session` into a per-`oidc_sub` `Account` record. Add `account_id`. Migration shim: legacy sessions get one auto-generated account on first read.
2. **Allowlist plumbing.** `IMAP_PROVIDERS` env (JSON) loaded into `AppState`. Default to a single entry pointing at the existing `IMAP_HOST/PORT`.
3. **`/manage` page.** OIDC-protected HTML route to list / add / remove accounts. Reuses the existing setup-form HTML and credential-validation path. CSRF-token-protected POSTs.
4. **Account resolver.** Single helper `(oidc_sub, requested_account) -> Account` used by every tool, with the 0/1/N rules above.
5. **MCP tool updates.** Add `list_accounts` and `add_account_url` tools. Add optional `account` parameter to every existing tool. Pass the resolved `Account` into `ImapMcpServer::new`. Update `last_used_at` on success; bump `auth_failure_count` and auto-disable on the third consecutive failure.
6. **Tests.** Unit: account-record serialization; resolver rules (0/1/N); legacy-session migration with `label = imap_email`; auto-disable trigger at 3 failures; counter reset on success. Integration: add two accounts, target each independently, remove one and verify the other still works, verify legacy single-account sessions still work post-migration, verify a disabled account returns the manage-url error.
7. **Docs.** README, `/manage` page copy, env example.

Estimated size: ~600–900 LOC. A step up from the v1 estimate because of the data-model split, the account parameter on every tool, and the management page — still mostly additive.

## Security Considerations

- **Allowlist enforcement** is the only gate on which IMAP hosts the server logs into. Enforced at **both** account-create time (in the `/auth/setup` and `/manage/accounts` POST handlers) **and** at account-resolve time (in `AccountResolver::resolve`, before every tool call). If an operator removes a provider from the allowlist after users have connected mailboxes there, those accounts immediately stop working with a clear error pointing the user at `/manage` to remove and reconnect; no manual Redis surgery is required.
- **`/manage` is OIDC-protected.** Bearer tokens (issued to MCP clients) cannot add or remove accounts on their own — only an interactive OIDC re-auth in a browser can. This keeps token theft from upgrading into mailbox-add capability.
- **`account` parameter is not free-form server input.** The resolver only loads accounts already attached to the authenticated `oidc_sub`. Cross-user account access is structurally impossible.
- **Per-`oidc_sub` rate-limit on failed credential validations** (e.g. 5 / 10 min) to neuter brute-force misuse.
- **Encryption at rest** unchanged: AES-256-GCM with a server-held key, one nonce per account record.
- **Token compromise reaches every connected account.** Accepted trade-off (see Decisions). Mitigations are limited to per-account revoke from `/manage` and per-`account_id` audit logs; existing 30-day session TTL is unchanged.
- **No new secret types**; still username + password against IMAP.

## Resolved Open Questions

1. **Account-add UX:** dedicated `add_account_url` MCP tool **in addition** to the `manage_url` returned by `list_accounts` and zero-account errors.
2. **Auto-disable on auth failure:** mark the account disabled after **3 consecutive** failed IMAP logins; surface a re-validate error with a fresh `manage_url`. Counter resets on any successful login.
3. **`manage_url` lifetime:** **15 minutes**. OIDC re-auth still required at `/manage` itself.
4. **Per-account `last_used_at` timestamp:** **track it.** Updated on every successful tool call; surfaced in `list_accounts`.
5. **Renaming accounts:** **not in v1** — delete-and-re-add only. Legacy single-account migrations get `label = imap_email` so they are immediately distinguishable.

## Out of Scope / Future Work

- OAuth2 / XOAUTH2 against Gmail / Microsoft 365.
- Cross-account search or a unified inbox tool.
- A self-service way for non-admins to broaden the IMAP provider allowlist.
- Audit-log export / SIEM integration.
