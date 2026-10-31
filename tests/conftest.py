from __future__ import annotations

import pytest

from bab.catalogue import Catalogue
from bab.store import StoreError


class FakeStore:
    """Records tuples; answers check/list from them literally (no inheritance —
    the model's semantics are covered by `fga model test`, not here)."""

    def __init__(self, tuples=(), broken=False):
        self.tuples = set(tuples)
        self.broken = broken

    def _guard(self):
        if self.broken:
            raise StoreError("connection refused")

    def check(self, user, relation, object, context=None):
        self._guard()
        now = (context or {}).get("current_time")
        for t in self.tuples:
            if t.key != (user, relation, object):
                continue
            if t.expires_at is None:
                return True
            if now is None:
                raise StoreError("conditional tuple checked without current_time")
            if now < t.expires_at:
                return True
        return False

    def list_users(self, object, relation, user_type="user"):
        self._guard()
        return sorted(t.user for t in self.tuples
                      if t.object == object and t.relation == relation and t.user.startswith(user_type + ":"))

    def list_objects(self, user, relation, object_type):
        self._guard()
        return sorted(t.object for t in self.tuples
                      if t.user == user and t.relation == relation and t.object.startswith(object_type + ":"))

    def write(self, tuples):
        self.tuples |= set(tuples)

    def delete(self, tuples):
        self.tuples -= set(tuples)

    def read_all(self):
        self._guard()
        return sorted(self.tuples, key=str)


@pytest.fixture
def cat():
    return Catalogue.from_dict({
        "resources": ["project", "cluster", "namespace"],
        "actions": [
            {"name": "log_read", "tier": "read", "global": True},
            {"name": "pod_delete", "tier": "mutate"},
        ],
    })


class FakeDatadog:
    """Datadog's service-account application-key API, as the DatadogMinter's `http` function:
    records every call, hands out key ids, forgets a key on DELETE, 404s one already gone."""

    def __init__(self, refuse: str | None = None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.keys: dict[str, dict] = {}
        self.refuse = refuse  # an error sentence Datadog answers every create with
        self.last_headers: dict = {}
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        self.last_headers = dict(headers)
        _, _, key_id = url.rpartition("/application_keys/") if "/application_keys/" in url else (None, None, "")
        if method == "POST":
            if self.refuse:
                return 403, {"errors": [{"title": "Forbidden", "detail": self.refuse}]}
            self.n += 1
            kid = f"kid-{self.n}"
            attrs = body["data"]["attributes"]
            self.keys[kid] = {"name": attrs["name"], "scopes": list(attrs["scopes"])}
            return 201, {"data": {"type": "application_keys", "id": kid,
                                  "attributes": {**self.keys[kid], "key": f"secret-{kid}"}}}
        if method == "DELETE":
            return (204, {}) if self.keys.pop(key_id, None) is not None else (404, {"errors": ["Not found"]})
        return 405, {"errors": ["method"]}


class FakeGitHub:
    """GitHub's App API as the GitHubMinter's `http` function: the app, one installation,
    installation tokens that echo what they were narrowed to, a repository count."""

    def __init__(self, refuse: str | None = None, installation: str = "777"):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.headers: list[dict] = []
        self.refuse = refuse
        self.installation = installation
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        self.headers.append(dict(headers))
        path = url.split("/", 3)[3] if url.count("/") >= 3 else ""
        if method == "GET" and path == "app":
            return 200, {"id": 4242, "slug": "acme-room"}
        if method == "GET" and path == f"app/installations/{self.installation}":
            return 200, {"id": int(self.installation), "app_slug": "acme-room", "account": {"login": "acme"}}
        if method == "GET" and path.startswith("app/installations/"):
            return 404, {"message": "Not Found"}
        if method == "POST" and path == f"app/installations/{self.installation}/access_tokens":
            if self.refuse:
                return 422, {"message": self.refuse}
            self.n += 1
            out = {"token": f"ghs-{self.n}", "expires_at": "2026-10-30T15:05:00Z", "permissions": body["permissions"]}
            if body.get("repositories"):
                out["repositories"] = [{"name": r} for r in body["repositories"]]
            return 201, out
        if method == "GET" and path.startswith("installation/repositories"):
            return 200, {"total_count": 3}
        return 405, {"message": "method"}
