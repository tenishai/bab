"""Topology sync: the resource tree and who owns it.

Shape (YAML file today; Gojira's /api/v1/topology tomorrow, same shape):

  teams:      [{name: platform-infra}]
  agents:     [{name: atlas, team: platform-infra}]
  projects:   [{name: acme-platform-prod, team: platform-infra}]
  clusters:   [{name: platform-prod, project: acme-platform-prod}]
  namespaces: [{name: platform-prod/ingest, cluster: platform-prod}]

Levels below the root are generic: each entry names its parent by the parent level's key.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

import yaml

from bab.catalogue import Catalogue
from bab.store import Tuple

log = logging.getLogger(__name__)


def relations(cat: Catalogue) -> set[str]:
    return {"team", "owner", *cat.resources[:-1]}


def tuples(topo: dict, cat: Catalogue) -> Iterable[Tuple]:
    for a in topo.get("agents") or ():
        yield Tuple(f"team:{a['team']}", "team", f"agent:{a['name']}")
    root = cat.root
    for p in topo.get(f"{root}s") or ():
        if p.get("team"):
            yield Tuple(f"team:{p['team']}", "owner", f"{root}:{p['name']}")
    for parent, level in zip(cat.resources, cat.resources[1:]):
        for item in topo.get(f"{level}s") or ():
            yield Tuple(f"{parent}:{item[parent]}", parent, f"{level}:{item['name']}")


def from_file(path: str | Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def from_gojira(base_url: str, token: str) -> dict:
    import httpx

    r = httpx.get(base_url.rstrip("/") + "/api/v1/topology",
                  headers={"Authorization": f"Bearer {token}"}, timeout=30)
    r.raise_for_status()
    return r.json()
