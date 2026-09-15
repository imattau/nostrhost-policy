"""Shared "load a config TOML file, or a safe default if it's missing"
helper.

identity.toml (auth/identity.py), revoked_delegations.toml
(auth/revocation.py), and policy.toml (policy/rules.py) all reimplement the
same shape: missing file -> an empty/default config (not an error - none of
these files are required to exist), present file -> ``tomllib.loads`` it,
wrapping ``tomllib.TOMLDecodeError`` in that module's own config-error type
so callers only ever catch one exception type per domain. This module
factors out that shared shape; parsing the loaded dict into identity
records / revoked ids / policy rules stays in each caller, since that part
genuinely differs.
"""

from __future__ import annotations

import tomllib
from pathlib import Path


def load_toml(path: Path, error_cls: type[Exception]) -> dict | None:
    """Return the parsed TOML at `path`, or None if `path` doesn't exist.

    Raises `error_cls(f"{path}: invalid TOML: {exc}")` - chained from the
    underlying `tomllib.TOMLDecodeError` - if the file exists but doesn't
    parse. `error_cls` is expected to be a `ValueError` subclass; callers
    pass their own module's config-error type so a caller catching e.g.
    `IdentityConfigError` never has to also know about `tomllib`.
    """
    if not path.exists():
        return None
    try:
        return tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise error_cls(f"{path}: invalid TOML: {exc}") from exc
