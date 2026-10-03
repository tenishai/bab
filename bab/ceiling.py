"""Ceiling: the most a team may grant its own agents. Enforced when a grant is written.

Ceilings are tuples `team:T ceiling_<action>[_gated] <object>`, inherited down the
tree like everything else. An allow ceiling implies an approve ceiling (see model).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bab.store import Store, Tuple

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Grant:
    agent: str      # "atlas" or "agent:atlas"; "*" for a global
    action: str
    object: str
    gated: bool = False

    @property
    def relation(self) -> str:
        return f"{self.action}_gated" if self.gated else self.action

    @property
    def subject(self) -> str:
        return "agent:*" if self.agent == "*" else (self.agent if ":" in self.agent else f"agent:{self.agent}")

    def as_tuple(self) -> Tuple:
        return Tuple(self.subject, self.relation, self.object)


def permitted(store: Store, team: str, grant: Grant) -> bool:
    """Does `team` hold a ceiling that covers this grant (allow needs allow, approve needs either)?"""
    team = team if ":" in team else f"team:{team}"
    ok = store.check(team, f"ceiling_{grant.relation}", grant.object)
    log.debug("ceiling %s %s -> %s", team, grant, ok)
    return ok


def team_of(store: Store, agent: str) -> str | None:
    subject = agent if ":" in agent else f"agent:{agent}"
    teams = store.list_users(subject, "team", user_type="team")
    return teams[0] if teams else None


def violations(store: Store, grants: list[tuple[str, Grant]]) -> list[tuple[str, Grant]]:
    """Grants (team, grant) that no longer fit their ceiling — what a ceiling shrink must revoke."""
    return [(team, g) for team, g in grants if not permitted(store, team, g)]
