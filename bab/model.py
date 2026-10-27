"""Generate the OpenFGA model (DSL 1.1) from a catalogue.

Per action A on every resource level:
  A               agent may act directly                    -> ALLOW
  A_gated         agent may act after a human approves      -> APPROVE
  can_A           either (the SDK asks this first)
  ceiling_A       the owning TEAM may hold an allow grant here (checked at write time)
  ceiling_A_gated the team may hold an approve grant here; an allow ceiling implies it
Approvers on the root = members of the owning team; every level below inherits.

Grants may expire: `A` and `A_gated` accept `agent with grant_window`, the one
condition the model defines. A tuple written with `expires_at` in its context
answers yes only while the check's `current_time` is before it. Ceilings and the
tree never carry conditions.
"""

from __future__ import annotations

from bab.catalogue import Catalogue
from bab.store import CONDITION

HEADER = """model
  schema 1.1

type user

type team
  relations
    define member: [user]

type agent
  relations
    define team: [team]
"""

FOOTER = f"""condition {CONDITION}(current_time: timestamp, expires_at: timestamp) {{
  current_time < expires_at
}}
"""


def generate(cat: Catalogue) -> str:
    out = [HEADER]
    for i, level in enumerate(cat.resources):
        parent = cat.resources[i - 1] if i else None
        lines = [f"type {level}", "  relations"]
        if parent:
            lines += [f"    define {parent}: [{parent}]", f"    define approver: approver from {parent}"]
        else:
            lines += ["    define owner: [team]", "    define approver: member from owner"]

        def inherit(rel: str, parent: str | None = parent) -> str:
            return f" or {rel} from {parent}" if parent else ""

        for a in cat.actions:
            direct = "agent, agent:*" if a.global_ else "agent"
            subjects = f"[{direct}, agent with {CONDITION}]"
            lines += [
                f"    define {a.name}: {subjects}{inherit(a.name)}",
                f"    define {a.gated}: {subjects}{inherit(a.gated)}",
                f"    define can_{a.name}: {a.name} or {a.gated}",
                f"    define ceiling_{a.name}: [team]{inherit(f'ceiling_{a.name}')}",
                f"    define ceiling_{a.gated}: [team] or ceiling_{a.name}{inherit(f'ceiling_{a.gated}')}",
            ]
        out.append("\n".join(lines) + "\n")
    out.append(FOOTER)
    return "\n".join(out)
