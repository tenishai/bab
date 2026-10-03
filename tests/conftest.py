from __future__ import annotations

import pytest

from bab.catalogue import Catalogue
from bab.store import StoreError, Tuple


class FakeStore:
    """Records tuples; answers check/list from them literally (no inheritance —
    the model's semantics are covered by `fga model test`, not here)."""

    def __init__(self, tuples=(), broken=False):
        self.tuples = set(tuples)
        self.broken = broken

    def _guard(self):
        if self.broken:
            raise StoreError("connection refused")

    def check(self, user, relation, object):
        self._guard()
        return Tuple(user, relation, object) in self.tuples

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
