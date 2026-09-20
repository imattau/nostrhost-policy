"""Compatibility re-export of the canonical Nostr event model (NIP-01).

The generic Nostr event model moved to ``nostrhost_auth.events``. This module
re-exports the same names and exception classes (exception identity preserved)
so existing ``nostrhost_policy.auth.nostr`` import paths keep working for one
release. New code should import from :mod:`nostrhost_auth.events` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.events import (
    HEX32_LEN,
    HEX64_LEN,
    NostrEvent,
    NostrEventError,
    UnsignedNostrEvent,
    compute_event_id,
    sign_event,
    verify_event,
)

warnings.warn(
    "nostrhost_policy.auth.nostr is deprecated; import from nostrhost_auth.events",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "HEX32_LEN",
    "HEX64_LEN",
    "NostrEvent",
    "NostrEventError",
    "UnsignedNostrEvent",
    "compute_event_id",
    "sign_event",
    "verify_event",
]