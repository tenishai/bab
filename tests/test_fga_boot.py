import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from bab import catalogue
from bab.service.fga_boot import ensure_store_and_model

pytestmark = pytest.mark.skipif(shutil.which("fga") is None and not Path("./fga").exists(), reason="fga CLI not present")


class FakeClient:
    def __init__(self, stores):
        self.stores = stores
        self.created = []
        self.models = []
        self.store_id = None

    def list_stores(self):
        return SimpleNamespace(stores=[SimpleNamespace(id=i, name=n) for i, n in self.stores])

    def create_store(self, body):
        self.created.append(body["name"])
        return SimpleNamespace(id="01NEW")

    def set_store_id(self, sid):
        self.store_id = sid

    def write_authorization_model(self, body):
        self.models.append(body)
        return SimpleNamespace(authorization_model_id="01MODEL")


def test_boot_finds_the_store_by_name_or_creates_it_and_writes_the_catalogue_model():
    cat = catalogue.load("catalogues/room.yaml")
    c = FakeClient([("01OLD", "bab")])
    assert ensure_store_and_model("http://fga", cat, "bab", client=c) == ("01OLD", "01MODEL")
    assert c.created == [] and c.store_id == "01OLD"
    conds = c.models[0]["conditions"]
    assert "grant_window" in conds and c.models[0]["schema_version"] == "1.1"
    c = FakeClient([])
    assert ensure_store_and_model("http://fga", cat, "bab", client=c) == ("01NEW", "01MODEL")
    assert c.created == ["bab"]
