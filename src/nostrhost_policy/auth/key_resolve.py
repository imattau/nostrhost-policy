"""Shared validation for resolving a config-supplied Nostr public key
(npub or hex) to canonical lowercase hex.

Used by both auth/identity.py (identity.toml entries) and auth/owner.py
(owner_npub) so the same nsec-rejection, npub-decode, and 64-character hex
checks apply in both places. Before this was unified, owner.py's `_to_hex`
was missing the hex-length check identity.py's `_resolve_key_to_hex`
enforced - a malformed owner_npub (too short, too long, or containing
non-hex characters but not starting with "npub1"/"nsec1") would silently
pass through owner.py's `raw.lower()` fallback and be treated as a valid
pubkey, where the identical string in identity.toml would have been
rejected. Sharing this function closes that gap for owner.py as well.
"""

from __future__ import annotations

import re

from nostrhost_auth.keys import Bech32Error, npub_to_hex

_HEX_PUBKEY_RE = re.compile(r"[0-9a-f]{64}")


def resolve_pubkey_to_hex(raw: str, *, error_cls: type[Exception], subject: str) -> str:
    """Resolve `raw` (an "npub1..." string or a 64-character hex pubkey) to
    lowercase hex.

    Raises `error_cls` (expected to be a ValueError subclass) for any of:
    an nsec (private key) - identity/owner config names public identities,
    never secrets (PLAN.md Phase 9); a malformed npub; or a string that is
    neither a valid npub nor a 64-character hexadecimal pubkey.

    `subject` names the caller's field in error messages, e.g.
    "identity.toml key" or "owner_npub".
    """
    if raw.startswith("nsec1"):
        raise error_cls(
            f"{subject} looks like an nsec (private key), not an npub/hex pubkey - "
            "yunohost-mcp must never be given a private key"
        )
    if raw.startswith("npub1"):
        try:
            return npub_to_hex(raw)
        except Bech32Error as exc:
            raise error_cls(f"{subject} {raw!r} is not a valid npub: {exc}") from exc
    candidate = raw.lower()
    if not _HEX_PUBKEY_RE.fullmatch(candidate):
        raise error_cls(f"{subject} must be an npub or 64-character hexadecimal public key")
    return candidate
