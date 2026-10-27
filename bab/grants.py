"""Grants: the one writer of permission tuples, and the sweep that tidies expired ones.

A grant is written only after the ceiling check (`ceiling.permitted`). Its expiry
comes from the action's tier unless the caller sets one; the tuple carries it as
OpenFGA's `grant_window` condition, so the store stops honouring it on time with
no sweeper in the path. `sweep` deletes what has already expired, for tidiness.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from bab import ceiling
from bab.catalogue import Catalogue
from bab.door import rfc3339
from bab.store import Store, Tuple

log = logging.getLogger(__name__)


class CeilingError(PermissionError):
    """The team holds no ceiling that covers this grant."""


def expiry_for(cat: Catalogue, action: str, now: datetime) -> datetime | None:
    """When a grant on this action expires by default: the tier's validity, or never."""
    act = cat.action(action)
    if act is None:
        raise ValueError(f"action {action!r} is not in the catalogue")
    days = cat.tier(act.tier).validity_days
    return None if days is None else now + timedelta(days=days)


def grant(store: Store, cat: Catalogue, team: str, g: ceiling.Grant, now: datetime,
          expires_at: datetime | None | str = "tier") -> Tuple:
    """Write one grant after the ceiling check. `expires_at="tier"` takes the tier default."""
    if cat.action(g.action) is None:
        raise ValueError(f"action {g.action!r} is not in the catalogue")
    if not ceiling.permitted(store, team, g):
        raise CeilingError(f"{team} holds no ceiling for {g.relation} on {g.object}")
    if expires_at == "tier":
        expires_at = expiry_for(cat, g.action, now)
    t = Tuple(g.subject, g.relation, g.object, rfc3339(expires_at) if expires_at else None)
    store.write([t])
    log.info("granted %s", t)
    return t


def expired(store: Store, now: datetime) -> list[Tuple]:
    """Tuples whose window has closed. They already answer no; this is what `sweep` removes."""
    cutoff = rfc3339(now)
    return [t for t in store.read_all() if t.expires_at and t.expires_at <= cutoff]


def sweep(store: Store, now: datetime) -> list[Tuple]:
    dead = expired(store, now)
    if dead:
        store.delete(dead)
        log.info("swept %d expired grants", len(dead))
    return dead
