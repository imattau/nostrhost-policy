# nostrhost-policy

Reusable authorisation library for the [nostrhost](../) Nostr-native YunoHost
derivative. Extracted from the reference implementation
[`yunohost-mcp`](https://github.com/imattau/yunohost-mcp) (the MCP server that
still ships for stock YunoHost via
[`yunohost-mcp_ynh`](https://github.com/imattau/yunohost-mcp_ynh) — which
remains operational during this migration).

The policy implementation is preserved as-is by design; the roadmap explicitly
says *not* to introduce a new policy engine while restructuring the system.

## What it provides

| module | provides |
|---|---|
| `policy.roles` | role → scope resolution, deny-by-default |
| `policy.scopes` | the shared permission vocabulary (`Scope` enum, `ALL_SCOPES`) |
| `policy.rules` | deterministic safeguards: `require_confirmation`, `require_backup`, `minimum_free_space_bytes`, `require_owner_signature` |
| `policy.confirmation` | bound single-use approval/confirmation tickets |
| `policy.locks` | write lock, `LockedError` |
| `policy.package_sessions` | package-test session store |
| `auth.identity` | pubkey → role/scope identity store (`identity.toml`) + request-scoped resolution |
| `auth.nip98` | NIP-98 HTTP-auth verification (kind 27235) |
| `auth.nostr` | NIP-01 event model + verification (coincurve) |
| `auth.npub` | npub/nsec ↔ hex |
| `auth.replay` | replay cache |
| `auth.owner` | configured owner (NIP-46 co-signature target) |
| `auth.delegation` | delegation-event verification + resolution |
| `auth.signing` | client signing helpers |
| `auth.revocation` | revocation store |
| `auth.groups` | system group resolution |
| `auth.server_identity` | server Nostr identity key handling |
| `audit` | JSON-lines audit trail (decorator + `AuditLog`) |
| `redaction` | shared secret-shaped redaction pass |

The same policy engine is intended to serve Admin UI, MCP, Portal and SSO
(roadmap stage 6); keeping it framework-free here is what makes that possible.

## Explicitly not here (yet)

MCP-transport coupling — `policy.enforcement` (tool decorators mapping to MCP
`ToolError`), `auth.middleware` (ASGI), and the yunohost-adapter lookups
(`auth.nostr_auth_lookup`, `auth.nostr_auth_relay_lookup`) — stays in the
reference until the native service layer (roadmap stage 11) consumes this
library. The Armada/concord and broker layers are likewise out of scope.

## Development

```
uv sync --all-groups
uv run pytest
```