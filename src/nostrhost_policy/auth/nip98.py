"""Compatibility re-export of the canonical NIP-98 verification.

NIP-98 verification moved to ``nostrhost_auth.nip98``. This module re-exports
the same names and exception classes (exception identity preserved) so
existing ``nostrhost_policy.auth.nip98`` import paths keep working for one
release. New code should import from :mod:`nostrhost_auth.nip98` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.nip98 import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    Nip98Error,
    Nip98Identity,
    verify_nip98_request,
)
from nostrhost_protocol import KindNip98 as NIP98_KIND

warnings.warn(
    "nostrhost_policy.auth.nip98 is deprecated; import from nostrhost_auth.nip98",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "NIP98_KIND",
    "Nip98Error",
    "Nip98Identity",
    "verify_nip98_request",
]