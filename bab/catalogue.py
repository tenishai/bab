"""The catalogue: resource levels + actions. The OpenFGA model is generated from it.

Humans (later: the console) edit the catalogue. Nobody hand-edits the model.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

TIERS = ("read", "mutate", "destroy")
IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
# Relations the generator emits itself; an action may not collide with them.
RESERVED = {"member", "team", "owner", "approver", "user", "agent"}


class CatalogueError(ValueError):
    """The catalogue is structurally wrong."""


@dataclass(frozen=True)
class Action:
    name: str
    tier: str
    description: str = ""
    global_: bool = False  # may be granted to every agent at once (agent:*)

    @property
    def gated(self) -> str:
        return f"{self.name}_gated"


@dataclass(frozen=True)
class Catalogue:
    resources: tuple[str, ...]  # root first; each level inherits from its parent
    actions: tuple[Action, ...] = field(default_factory=tuple)

    def action(self, name: str) -> Action | None:
        return next((a for a in self.actions if a.name == name), None)

    @property
    def root(self) -> str:
        return self.resources[0]

    @classmethod
    def from_dict(cls, raw: dict) -> Catalogue:
        resources = tuple(raw.get("resources") or ())
        if not resources:
            raise CatalogueError("resources must list at least one level (root first)")
        for r in resources:
            if not IDENT.match(r) or r in RESERVED:
                raise CatalogueError(f"bad resource name {r!r}")
        if len(set(resources)) != len(resources):
            raise CatalogueError("duplicate resource level")

        actions: list[Action] = []
        for entry in raw.get("actions") or ():
            name = entry.get("name", "")
            if not IDENT.match(name) or name in RESERVED or name in resources:
                raise CatalogueError(f"bad action name {name!r}")
            if name.startswith("ceiling_") or name.endswith("_gated"):
                raise CatalogueError(f"action {name!r} collides with a generated relation")
            tier = entry.get("tier")
            if tier not in TIERS:
                raise CatalogueError(f"action {name!r}: tier must be one of {TIERS}, got {tier!r}")
            actions.append(Action(name, tier, entry.get("description", ""), bool(entry.get("global"))))
        names = [a.name for a in actions]
        if len(set(names)) != len(names):
            raise CatalogueError("duplicate action name")
        log.debug("catalogue: %d levels, %d actions", len(resources), len(actions))
        return cls(resources, tuple(actions))


def load(path: str | Path) -> Catalogue:
    with open(path) as fh:
        return Catalogue.from_dict(yaml.safe_load(fh) or {})
