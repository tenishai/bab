---
card: arch-card:bab-door
updated: 2026-10-27
anchor: bab/door.py sha=a93c9e4b52685fa9ac985a4ef0990d36d40156f7
anchor: bab/model.py sha=3110c52dd3ab4310cd8ffed19677925176fba4ce
anchor: bab/grants.py sha=5cf081fffe38a10889716a14f3dcc41eb54eda89
---
# door — one fail-closed decision per tool dispatch

WHAT / SEAM: `Door(store: Store, catalogue: Catalogue, fallback_approvers=())`, `.decide(agent, action, object, now=None) -> Decision(verdict: Verdict, reason, approvers: tuple, degraded: bool)`. Verdict is a str Enum: "allow" | "approve" | "deny". Agent may be "atlas" or "agent:atlas"; object is "<level>:<id>".
The relation names Door checks are emitted by bab/model.py `generate(catalogue)`. Per action A, on EVERY resource level:
- `A` [agent, agent with grant_window] → allow; `A_gated` same subjects → approve; `can_A` = A or A_gated (not used by Door). The model ends with the one condition `grant_window(current_time, expires_at) { current_time < expires_at }`; a tuple written with `expires_at` answers yes only while the check's `current_time` is before it.
- `ceiling_A` [team]; `ceiling_A_gated` [team] or ceiling_A (allow ceiling implies approve ceiling)
- non-root levels add `or <rel> from <parent>` (inheritance down the tree); root has `owner: [team]`, `approver: member from owner`; children `approver: approver from <parent>`
- `global: true` actions accept `agent:*` as a subject (never conditional).
- Every Door check passes `context={"current_time": rfc3339(now)}` (door.rfc3339: RFC 3339 UTC, whole seconds). Ceilings and the tree never carry conditions.
- bab/grants.py is the ONE writer of grant tuples: `grant(store, cat, team, Grant, now, expires_at="tier")` runs `ceiling.permitted` first (CeilingError otherwise) and takes the expiry from the action's tier (`Catalogue.tier(name).validity_days`; None = standing); `expired(store, now)` / `sweep(store, now)` delete tuples whose window closed (tidiness only, they already answer no).
OPS / FLOW: decide → action not in catalogue → DENY; object type not a catalogue level → DENY → check(agent, A, obj) → ALLOW → else check(agent, A_gated, obj) → list_users(obj, "approver") → none → DENY ("nobody can say yes"), else APPROVE with approvers → else DENY. Any StoreError → degraded path.
INVARIANTS:
- Default is deny: unknown action, unknown level, no tuple.
- APPROVE with zero approvers is DENY: an approval nobody can give is a refusal.
- Fail-closed when the store can't answer (StoreError): tier `read` → ALLOW degraded; otherwise fallback_approvers → APPROVE degraded; none → DENY degraded. `degraded=True` marks it for audit. Only reads are ever allowed blind.
- Door does not check ceilings. Ceilings are a WRITE-time rule: bab/grants.py `grant` is the writer that enforces them; a tuple written any other way is honoured regardless.
- Relation-name contract: Door (`act.name`, `act.gated`), ceiling.Grant.relation, sync/topology.relations(), the fixture model/example.fga.yaml and any future caller all hard-code these names. Renaming a suffix in model.py breaks every one; catalogue.py forbids actions named `*_gated`, `ceiling_*`, or RESERVED (member, team, owner, approver, user, agent) so generated names can't collide.
- The generated model is committed and drift-checked (tests/test_model.py, CI `git diff --exit-code model/example.fga`).
CONSUMERS: bab/cli.py cmd_check; README "In an agent" example; tests/test_door.py (FakeStore, no inheritance); `fga model test` on model/example.fga.yaml for inheritance semantics. Planned, not built: agent SDK at tool dispatch, kobo /guardrails/check (docs/design.md).
API: bab.Door, bab.Decision, bab.Verdict, bab.door.rfc3339; bab.store.{Store, StoreError, Tuple(expires_at), OpenFgaStore, CONDITION}; bab.model.generate; bab.grants.{grant, expiry_for, expired, sweep, CeilingError}; bab.catalogue.{Tier, TIER_DEFAULTS}.
