"""Compatibility re-export of the canonical server signing identity.

The server signing identity moved to ``nostrhost_auth.server_identity``. This
module re-exports the same names and exception classes (exception identity
preserved) so existing ``nostrhost_policy.auth.server_identity`` import paths
keep working for one release. New code should import from
:mod:`nostrhost_auth.server_identity` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_auth.server_identity import ServerIdentity, ServerIdentityError

warnings.warn(
    "nostrhost_policy.auth.server_identity is deprecated; "
    "import from nostrhost_auth.server_identity",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["ServerIdentity", "ServerIdentityError"]