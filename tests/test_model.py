import shutil
import subprocess
from pathlib import Path

import pytest

from bab import catalogue, model


def test_committed_model_is_generated_from_catalogue():
    """model/example.fga is an artifact of catalogues/example.yaml — never hand-edited."""
    assert Path("model/example.fga").read_text() == model.generate(catalogue.load("catalogues/example.yaml"))


def test_every_action_gets_the_five_relations_at_every_level(cat):
    text = model.generate(cat)
    for level in cat.resources:
        block = text.split(f"type {level}\n", 1)[1].split("\ntype ", 1)[0]
        for rel in ("pod_delete", "pod_delete_gated", "can_pod_delete", "ceiling_pod_delete", "ceiling_pod_delete_gated"):
            assert f"define {rel}:" in block, (level, rel)
    assert "define log_read: [agent, agent:*, agent with grant_window]" in text   # global
    assert "define pod_delete: [agent, agent with grant_window]\n" in text        # not global
    assert "define ceiling_pod_delete: [team]" in text          # ceilings never expire
    assert text.rstrip().endswith("condition grant_window(current_time: timestamp, expires_at: timestamp) {\n  current_time < expires_at\n}")
    assert "define approver: member from owner" in text        # root
    assert "define approver: approver from cluster" in text    # inherited


@pytest.mark.skipif(shutil.which("fga") is None and not Path("./fga").exists(), reason="fga CLI not present")
def test_suite_passes_under_fga_cli():
    fga = shutil.which("fga") or "./fga"
    out = subprocess.run([fga, "model", "test", "--tests", "model/example.fga.yaml"], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAILING" not in out.stdout
