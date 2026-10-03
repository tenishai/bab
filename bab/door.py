"""The door: one decision per tool dispatch.

  allow    -> run the tool
  approve  -> post the plan, wait for ✅ from one of `approvers`
  deny     -> tool result explains; the LLM does not retry

Fail-closed: if the store cannot answer, reads are allowed and everything else
requires approval from the agent's static fallback approvers (its config today).
No fallback approvers -> deny. `degraded=True` marks such decisions in the audit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from bab.catalogue import Catalogue
from bab.store import Store, StoreError

log = logging.getLogger(__name__)


class Verdict(str, Enum):
    ALLOW = "allow"
    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    approvers: tuple[str, ...] = ()
    degraded: bool = False


class Door:
    def __init__(self, store: Store, catalogue: Catalogue, fallback_approvers: tuple[str, ...] = ()):
        self.store = store
        self.catalogue = catalogue
        self.fallback_approvers = tuple(fallback_approvers)

    def decide(self, agent: str, action: str, object: str) -> Decision:
        act = self.catalogue.action(action)
        if act is None:
            return Decision(Verdict.DENY, f"action {action!r} is not in the catalogue")
        typ, sep, _ = object.partition(":")
        if not sep or typ not in self.catalogue.resources:
            return Decision(Verdict.DENY, f"object {object!r} is not a {'/'.join(self.catalogue.resources)}")
        subject = agent if ":" in agent else f"agent:{agent}"

        try:
            if self.store.check(subject, act.name, object):
                return Decision(Verdict.ALLOW, f"{subject} holds {act.name} on {object}")
            if self.store.check(subject, act.gated, object):
                approvers = tuple(self.store.list_users(object, "approver"))
                if not approvers:
                    return Decision(Verdict.DENY, f"{object} has no approvers; nobody can say yes")
                return Decision(Verdict.APPROVE, f"{subject} holds {act.gated} on {object}", approvers)
            return Decision(Verdict.DENY, f"{subject} holds neither {act.name} nor {act.gated} on {object}")
        except StoreError as exc:
            log.warning("door degraded: %s", exc)
            if act.tier == "read":
                return Decision(Verdict.ALLOW, f"store unreachable; {act.tier} allowed", degraded=True)
            if self.fallback_approvers:
                return Decision(Verdict.APPROVE, "store unreachable; fallback approvers",
                                self.fallback_approvers, degraded=True)
            return Decision(Verdict.DENY, "store unreachable and no fallback approvers", degraded=True)
