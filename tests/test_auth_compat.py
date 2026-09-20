"""Compat re-export identity tests: the old nostrhost_policy.auth primitive
paths must re-export the canonical nostrhost_auth names with identical
exception classes (no duplicate exception types)."""

from __future__ import annotations

import warnings

import pytest

import nostrhost_auth.events as events
import nostrhost_auth.keys as keys
import nostrhost_auth.nip98 as nip98
import nostrhost_auth.replay as replay
import nostrhost_auth.server_identity as server_identity
import nostrhost_auth.signing as signing
from nostrhost_policy.auth import nostr, npub, replay as policy_replay, nip98 as policy_nip98
from nostrhost_policy.auth import server_identity as policy_server_identity
from nostrhost_policy.auth import signing as policy_signing


def test_exception_identity_preserved():
    assert nostr.NostrEventError is events.NostrEventError
    assert npub.Bech32Error is keys.Bech32Error
    assert policy_replay.ReplayError is replay.ReplayError
    assert policy_nip98.Nip98Error is nip98.Nip98Error
    assert policy_signing.KeyLoadError is signing.KeyLoadError
    assert policy_server_identity.ServerIdentityError is server_identity.ServerIdentityError


def test_re_exported_callables_are_identical():
    assert nostr.verify_event is events.verify_event
    assert npub.npub_to_hex is keys.npub_to_hex
    assert policy_replay.ReplayCache is replay.ReplayCache
    assert policy_nip98.verify_nip98_request is nip98.verify_nip98_request
    assert policy_signing.ClientIdentity is signing.ClientIdentity
    assert policy_server_identity.ServerIdentity is server_identity.ServerIdentity


def test_compat_import_emits_deprecation_warning():
    # The compat modules are already imported at the top of this file, so their
    # warnings already fired. Re-import one fresh to observe the warning.
    import importlib
    import sys

    if "nostrhost_policy.auth.nip98" in sys.modules:
        del sys.modules["nostrhost_policy.auth.nip98"]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.import_module("nostrhost_policy.auth.nip98")

    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    # Restore so the module-level imports at the top of this file stay valid.
    importlib.import_module("nostrhost_policy.auth.nip98")