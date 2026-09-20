"""Compatibility re-export of the canonical client request signing.

Client-side NIP-98 signing moved to ``nostrhost_auth.signing``. This module
re-exports the same names and exception classes (exception identity preserved)
so existing ``nostrhost_policy.auth.signing`` import paths keep working for
one release. New code should import from :mod:`nostrhost_auth.signing`
directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.signing import ClientIdentity, KeyLoadError

warnings.warn(
    "nostrhost_policy.auth.signing is deprecated; import from nostrhost_auth.signing",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["ClientIdentity", "KeyLoadError"]