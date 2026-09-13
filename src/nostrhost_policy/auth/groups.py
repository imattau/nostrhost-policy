"""MCP authorization from dedicated YunoHost groups."""

from __future__ import annotations

import grp
import pwd
from collections.abc import Callable

from nostrhost_policy.auth.identity import IdentityRecord, _resolve_key_to_hex
from nostrhost_policy.policy.roles import scopes_for_roles

DEFAULT_GROUP_ROLES = {
    "yunohost-mcp-readonly": "readonly",
    "yunohost-mcp-operator": "operator",
    "yunohost-mcp-app-admin": "app-admin",
    "yunohost-mcp-package-developer": "package-developer",
    "yunohost-mcp-administrator": "administrator",
}


class GroupIdentityStore:
    """Resolve a pubkey via an external identity lookup, then local groups."""

    def __init__(self, username_lookup: Callable[[str], str | None], *, group_roles=None) -> None:
        self.username_lookup = username_lookup
        self.group_roles = dict(group_roles or DEFAULT_GROUP_ROLES)

    def lookup(self, pubkey_hex: str) -> IdentityRecord | None:
        try:
            pubkey = _resolve_key_to_hex(pubkey_hex)
        except ValueError:
            return None
        username = self.username_lookup(pubkey)
        if username is None:
            return None
        groups = self._groups_for_user(username)
        roles = tuple(role for group, role in self.group_roles.items() if group in groups)
        if not roles:
            return None
        return IdentityRecord(pubkey=pubkey, name=username, roles=roles, scopes=scopes_for_roles(roles))

    def pubkeys_with_role(self, role: str) -> list[str]:
        # Owner bootstrap should use an explicit owner_npub with this backend;
        # the lookup contract intentionally has no enumeration operation.
        return []

    @staticmethod
    def _groups_for_user(username: str) -> set[str]:
        try:
            user = pwd.getpwnam(username)
        except KeyError:
            return set()
        groups: set[str] = set()
        try:
            groups.add(grp.getgrgid(user.pw_gid).gr_name)
        except KeyError:
            pass
        for entry in grp.getgrall():
            if username in entry.gr_mem:
                groups.add(entry.gr_name)
        return groups
