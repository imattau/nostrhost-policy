"""Compatibility re-export of the canonical replay protection.

Replay protection moved to ``nostrhost_auth.replay``. This module re-exports
the same names and exception classes (exception identity preserved) so
existing ``nostrhost_policy.auth.replay`` import paths keep working for one
release. New code should import from :mod:`nostrhost_auth.replay` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.replay import ReplayCache, ReplayError

warnings.warn(
    "nostrhost_policy.auth.replay is deprecated; import from nostrhost_auth.replay",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["ReplayCache", "ReplayError"]