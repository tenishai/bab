"""Identity sync: Okta engineering groups -> `user:<email> member team:<name>`.

Reads an Okta groups JSON API (behind IAP). Group `engineering_platform_infra`
becomes `team:platform-infra`. Users are keyed by email — the one identifier Okta,
Slack (users.lookupByEmail) and GCP all share.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable

from bab.store import Tuple

log = logging.getLogger(__name__)

Fetch = Callable[[str], object]  # path -> parsed JSON
RELATIONS = {"member"}


def team_name(group: str, prefix: str = "engineering_") -> str | None:
    if not group.startswith(prefix):
        return None
    return group[len(prefix):].replace("_", "-")


def tuples(fetch: Fetch, prefix: str = "engineering_") -> Iterable[Tuple]:
    groups = fetch("/api/groups")
    for g in groups:
        team = team_name(g["profile"]["name"], prefix)
        if not team:
            continue
        users = fetch(f"/api/groups/{g['id']}/users")
        for u in users:
            email = (u.get("profile") or {}).get("email") or (u.get("profile") or {}).get("login")
            if email:
                yield Tuple(f"user:{email.lower()}", "member", f"team:{team}")
        log.debug("okta group %s -> team:%s (%d users)", g["profile"]["name"], team, len(users))


def http_fetch(base_url: str, token: str | None = None) -> Fetch:
    import httpx

    headers = {"Authorization": f"Bearer {token}"} if token else {}

    def fetch(path: str) -> object:
        r = httpx.get(base_url.rstrip("/") + path, headers=headers, timeout=30)
        r.raise_for_status()
        return r.json()

    return fetch
