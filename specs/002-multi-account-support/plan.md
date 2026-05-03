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

## Non-Goals (for v1)

- Cross-account search or a unified inbox tool.
- OAuth/XOAUTH2 against external providers (still password / app-password based).
- Operator-managed shared-mailbox provisioning (admin pre-loads shared credentials and grants by OIDC group). Powerful and probably the right v2; intentionally deferred.
- A polished UI for managing accounts. v1 ships a minimal HTML page; richer UX is later work.

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
    pub account_id:   String,  // server-issued stable slug
    pub label:        String,  // user-supplied nickname, e.g. "Billing"
    pub imap_email:   String,
    pub imap_host:    String,  // must be in the provider allowlist
    pub imap_port:    u16,
    pub password_enc: String,  // AES-256-GCM, unchanged scheme
    pub password_iv:  String,
    pub created_at:   i64,
}
```

The verified `oidc_sub` is the trust anchor; tokens are references to it. Revoking a token doesn't lose accounts. Migration shim: legacy single-account sessions are read once and rewritten as one auto-generated `Account` keyed under their `oidc_sub`.

### Onboarding flow

- **Initial connect** (existing OAuth flow, lightly extended). OIDC → setup form → user picks provider from the allowlist, supplies IMAP email + password + nickname → first `Account` created and attached to `oidc_sub` → bearer token issued.
- **Adding another mailbox.** The MCP server exposes a small `/manage` page (server-side rendered HTML, OIDC-protected, no JS framework). The page lists the user's accounts and lets them add or remove one. Users reach it via:
  - The `manage_url` returned by the new `list_accounts` MCP tool (short-lived, signed, OIDC required when opened).
  - A direct bookmark to `https://<mcp-host>/manage`.
- **Removing an account** deletes the record from Redis. Other accounts and the bearer token are unaffected.

### MCP tool changes

- New tool: `list_accounts` → `[{ account_id, label, imap_email, imap_host }, …]`, plus a short-lived signed `manage_url` for adding/removing accounts.
- Every existing tool gains an optional `account` parameter (`account_id` or `label`). Resolution rules:
  - 0 accounts → error with the `manage_url` ("No mailboxes connected — open … to add one").
  - 1 account → `account` optional, defaults to that one.
  - 2+ accounts → `account` required; on omission the error tells the agent to call `list_accounts` first.
- `label` is accepted as a convenience for agent ergonomics; ambiguous labels error.

### IMAP provider allowlist

Same as v1: env-configured list of `{ id, label, host, port }`, default ships with `mail.factorial.io`. The `/manage` form's dropdown uses it. Custom hosts are intentionally not offered in v1 — providers added centrally by the operator.

### Audit trail

Every IMAP operation logs `{ oidc_sub, account_id, imap_email, imap_host, tool }`. `oidc_sub` is the human; `account_id` is which mailbox they used.

## Alternatives Considered

1. **One bearer token = one mailbox, user installs the connector N times** (v1 of this plan). Rejected: not possible on Team plans where users can't add connectors.
2. **Single admin-managed global account list, no per-user accounts.** Simplest for the operator, but doesn't cover the "private email account" goal and forces every team member to share credentials for the same accounts. Rejected.
3. **Free-form host/port input** instead of an allowlist. Same trade-off as v1: rejected, allowlist instead.
4. **Operator-curated shared mailboxes with OIDC-group ACLs** (admin pre-loads `billing@factorial.io` once, OIDC group `team-billing` gets read/write). Powerful and probably the right v2 — but it's a sizeable separate feature. Deferred.

## Implementation Phases

1. **Schema split.** Move IMAP credentials out of `Session` into a per-`oidc_sub` `Account` record. Add `account_id`. Migration shim: legacy sessions get one auto-generated account on first read.
2. **Allowlist plumbing.** `IMAP_PROVIDERS` env (JSON) loaded into `AppState`. Default to a single entry pointing at the existing `IMAP_HOST/PORT`.
3. **`/manage` page.** OIDC-protected HTML route to list / add / remove accounts. Reuses the existing setup-form HTML and credential-validation path. CSRF-token-protected POSTs.
4. **Account resolver.** Single helper `(oidc_sub, requested_account) -> Account` used by every tool, with the 0/1/N rules above.
5. **MCP tool updates.** Add `list_accounts` tool. Add optional `account` parameter to every existing tool. Pass the resolved `Account` into `ImapMcpServer::new`.
6. **Tests.** Unit: account-record serialization; resolver rules (0/1/N); legacy-session migration. Integration: add two accounts, target each independently, remove one and verify the other still works, verify legacy single-account sessions still work post-migration.
7. **Docs.** README, `/manage` page copy, env example.

Estimated size: ~600–900 LOC. A step up from the v1 estimate because of the data-model split, the account parameter on every tool, and the management page — still mostly additive.

## Security Considerations

- **Allowlist enforcement** is the only gate on which IMAP hosts the server logs into. Centralised at account-create time.
- **`/manage` is OIDC-protected.** Bearer tokens (issued to MCP clients) cannot add or remove accounts on their own — only an interactive OIDC re-auth in a browser can. This keeps token theft from upgrading into mailbox-add capability.
- **`account` parameter is not free-form server input.** The resolver only loads accounts already attached to the authenticated `oidc_sub`. Cross-user account access is structurally impossible.
- **Per-`oidc_sub` rate-limit on failed credential validations** (e.g. 5 / 10 min) to neuter brute-force misuse.
- **Encryption at rest** unchanged: AES-256-GCM with a server-held key, one nonce per account record.
- **Token compromise has wider blast radius than v1**: a stolen bearer token now reaches every account that user has connected, not just one mailbox. Mitigations: revoke-from-`/manage` per account; revisit the 30-day session TTL (perhaps shorter); audit-log every tool call with `account_id`.
- **No new secret types**; still username + password against IMAP.

## Open Questions

1. **Account-add UX from inside Claude.** Is surfacing `manage_url` in `list_accounts` (and in zero-account errors) enough, or do we want a dedicated `add_account_url` tool? Lean default: just `list_accounts` + zero-account error.
2. **Auto-disable on persistent auth failure.** Should an account be marked unusable after N failed IMAP logins (password changed, account locked) and require re-validation in `/manage`? Probably yes; pin down N and the user-visible message.
3. **Session TTL.** The current 30-day TTL was sized for the old single-account model. Worth shortening now that a token unlocks more mailboxes?
4. **`manage_url` lifetime.** 5 min? 15? Pick a default and document.
5. **Should the server retain a per-account "last used" timestamp** to support a future "stale account cleanup" pass? Cheap to add now.
6. **Renaming accounts.** Required in v1, or is delete-and-re-add fine? Delete-and-re-add is fine if labels are easy to set; revisit if we hear pain.

## Out of Scope / Future Work

- Operator-managed shared mailboxes with OIDC-group ACLs (the v2 shape that admins will probably want).
- OAuth2 / XOAUTH2 against Gmail / Microsoft 365.
- Cross-account search or a unified inbox tool.
- A self-service way for non-admins to broaden the IMAP provider allowlist.
- Audit-log export / SIEM integration.
