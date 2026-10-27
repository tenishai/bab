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
