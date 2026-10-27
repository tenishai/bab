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
# Per tier: how long a minted lease lives, and how long a grant stays valid (None = standing).
TIER_DEFAULTS: dict[str, tuple[int, int | None]] = {
    "read": (3600, None),
    "mutate": (3600, 30),
    "destroy": (1800, 7),
}
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
    group: str = ""  # display grouping in a console (the vendor's own section), never a relation
    vendor: str = ""  # which integration family this permission belongs to (aws, datadog, github)
    extra: dict = field(default_factory=dict)  # minter data (e.g. aws: {"iam": ["ec2:Describe*"]})

    @property
    def gated(self) -> str:
        return f"{self.name}_gated"


@dataclass(frozen=True)
class Tier:
    name: str
    lease_seconds: int
    validity_days: int | None  # None = a grant on this tier never expires on its own


@dataclass(frozen=True)
class Catalogue:
    resources: tuple[str, ...]  # root first; each level inherits from its parent
    actions: tuple[Action, ...] = field(default_factory=tuple)
    tiers: tuple[Tier, ...] = field(default_factory=lambda: tuple(
        Tier(n, lease, days) for n, (lease, days) in TIER_DEFAULTS.items()))

    def action(self, name: str) -> Action | None:
        return next((a for a in self.actions if a.name == name), None)

    def tier(self, name: str) -> Tier:
        return next(t for t in self.tiers if t.name == name)

    def for_vendor(self, vendor: str) -> tuple[Action, ...]:
        return tuple(a for a in self.actions if a.vendor == vendor)

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
            extra = entry.get("extra") or {}
            if not isinstance(extra, dict):
                raise CatalogueError(f"action {name!r}: extra must be a mapping")
            actions.append(Action(name, tier, entry.get("description", ""), bool(entry.get("global")),
                                  str(entry.get("group", "") or ""), str(entry.get("vendor", "") or ""),
                                  dict(extra)))
        names = [a.name for a in actions]
        if len(set(names)) != len(names):
            raise CatalogueError("duplicate action name")

        overrides = raw.get("tiers") or {}
        for t in overrides:
            if t not in TIERS:
                raise CatalogueError(f"tiers: unknown tier {t!r}")
        tiers = []
        for t, (lease, days) in TIER_DEFAULTS.items():
            o = overrides.get(t) or {}
            lease = int(o.get("lease_seconds", lease))
            days = o.get("validity_days", days)
            days = None if days in (None, "standing") else int(days)
            if lease <= 0 or (days is not None and days <= 0):
                raise CatalogueError(f"tiers.{t}: lease_seconds and validity_days must be positive")
            tiers.append(Tier(t, lease, days))
        log.debug("catalogue: %d levels, %d actions", len(resources), len(actions))
        return cls(resources, tuple(actions), tuple(tiers))


def load(path: str | Path) -> Catalogue:
    with open(path) as fh:
        return Catalogue.from_dict(yaml.safe_load(fh) or {})
