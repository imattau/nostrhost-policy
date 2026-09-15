"""Owner identity resolution (owner-approval-plan.md).

v1 scope is the `solo` profile only: exactly one owner, trusted to approve
high-risk operations (Scope.OWNER_APPROVE, policy/rules.py's
require_owner_signature) via server.py's approve_operation. Household/team/
strict multi-owner sets are explicitly out of scope for v1 - this module
never returns more than one pubkey.

Resolution order:
  1. an explicit `owner_npub` setting (YUNOHOST_MCP_OWNER_NPUB) - what a
     packaged install seeds from the install-time admin_npub. This is the
     only way to name an owner independent of "whichever single
     administrator identity.toml happens to have".
  2. bootstrap fallback: exactly one identity.toml entry with the
     "administrator" role. Zero or more than one administrator is
     ambiguous and resolves to no owner rather than guessing - per
     owner-approval-plan.md's "reject ambiguous or malformed owner
     configuration safely" and "do not silently make every administrator
     an owner". No owner configured means require_owner_signature
     operations can never be approved until one is set explicitly: fail
     closed, not fail open onto some administrator.
"""

from __future__ import annotations

from nostrhost_policy.auth.identity import IdentityStore
from nostrhost_policy.auth.key_resolve import resolve_pubkey_to_hex


class OwnerConfigError(ValueError):
    """owner_npub is set but isn't a valid npub/hex pubkey (or is an nsec)."""


def resolve_owner_pubkey(*, owner_npub: str | None, identity_store: IdentityStore) -> str | None:
    if owner_npub:
        return _to_hex(owner_npub)

    administrators = identity_store.pubkeys_with_role("administrator")
    if len(administrators) == 1:
        return administrators[0]
    return None


def _to_hex(raw: str) -> str:
    # Owner config, like identity.toml, names a public identity - never a
    # secret (PLAN.md Phase 9), and is held to the same 64-character hex
    # validation identity.toml entries get (auth/key_resolve.py) - a
    # malformed owner_npub is rejected here rather than silently accepted
    # as a "pubkey" that happens to be the wrong shape.
    return resolve_pubkey_to_hex(raw, error_cls=OwnerConfigError, subject="owner_npub")
