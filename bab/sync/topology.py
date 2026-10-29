"""Topology sync: the agents, their teams, and who owns the root resource.

Shape (a YAML file, Gojira's /api/v1/topology, or the body the room PUTs to
/topology; all the same):

  teams:  [{name: platform-infra}]
  agents: [{name: atlas, team: platform-infra, namespace: atlas, service_account: agent-atlas}]
  rooms:  [{name: acme, team: platform-infra}]

The sync owns two relations: `team` (agent -> team) and `owner` (team -> root).
It does not own the levels under the root: integrations are connected in the
room by a person (PUT /integrations), and a sync that also wrote the `room`
relation would delete those links on its next run (seen live, #19).

An agent's `namespace` and `service_account` say which pod identity is that
agent. They are optional; without them the agent is its service account's name.
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
    return {"team", "owner"}


def tuples(topo: dict, cat: Catalogue) -> Iterable[Tuple]:
    for a in topo.get("agents") or ():
        yield Tuple(f"team:{a['team']}", "team", f"agent:{a['name']}")
    root = cat.root
    for p in topo.get(f"{root}s") or ():
        if p.get("team"):
            yield Tuple(f"team:{p['team']}", "owner", f"{root}:{p['name']}")


def agents(topo: dict) -> list[dict]:
    """The agent entries, normalised: name, team, namespace, service_account (the last two may be None)."""
    out = []
    for a in topo.get("agents") or ():
        out.append({"name": str(a["name"]), "team": str(a["team"]),
                    "namespace": (str(a["namespace"]) if a.get("namespace") else None),
                    "service_account": (str(a["service_account"]) if a.get("service_account") else None)})
    return out


def from_file(path: str | Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def from_gojira(base_url: str, token: str) -> dict:
    import httpx

    r = httpx.get(base_url.rstrip("/") + "/api/v1/topology",
                  headers={"Authorization": f"Bearer {token}"}, timeout=30)
    r.raise_for_status()
    return r.json()
