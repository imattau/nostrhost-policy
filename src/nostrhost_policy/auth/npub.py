"""Compatibility re-export of the canonical NIP-19 key conversions.

The generic key conversions (npub/nsec/hex) moved to ``nostrhost_auth.keys``.
This module re-exports the same names and exception classes (exception
identity preserved) so existing ``nostrhost_policy.auth.npub`` import paths
keep working for one release. New code should import from
:mod:`nostrhost_auth.keys` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.keys import (
    NPUB_HRP,
    NSEC_HRP,
    Bech32Error,
    hex_to_npub,
    hex_to_nsec,
    npub_to_hex,
    nsec_to_hex,
)

warnings.warn(
    "nostrhost_policy.auth.npub is deprecated; import from nostrhost_auth.keys",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "NPUB_HRP",
    "NSEC_HRP",
    "Bech32Error",
    "hex_to_npub",
    "hex_to_nsec",
    "npub_to_hex",
    "nsec_to_hex",
]