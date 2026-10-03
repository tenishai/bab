---
card: arch-card:bab-door
updated: 2026-09-28
anchor: bab/door.py sha=904e202c6503120c6e33503f55bc374b55f4f281
anchor: bab/model.py sha=44257872f30356e6404841b930ac6008644d7b64
---
# door — one fail-closed decision per tool dispatch

WHAT / SEAM: `Door(store: Store, catalogue: Catalogue, fallback_approvers=())`, `.decide(agent, action, object) -> Decision(verdict: Verdict, reason, approvers: tuple, degraded: bool)`. Verdict is a str Enum: "allow" | "approve" | "deny". Agent may be "iris" or "agent:iris"; object is "<level>:<id>".
The relation names Door checks are emitted by bab/model.py `generate(catalogue)`. Per action A, on EVERY resource level:
- `A` [agent] → allow; `A_gated` [agent] → approve; `can_A` = A or A_gated (not used by Door)
- `ceiling_A` [team]; `ceiling_A_gated` [team] or ceiling_A (allow ceiling implies approve ceiling)
- non-root levels add `or <rel> from <parent>` (inheritance down the tree); root has `owner: [team]`, `approver: member from owner`; children `approver: approver from <parent>`
- `global: true` actions accept `agent:*` as a subject.
OPS / FLOW: decide → action not in catalogue → DENY; object type not a catalogue level → DENY → check(agent, A, obj) → ALLOW → else check(agent, A_gated, obj) → list_users(obj, "approver") → none → DENY ("nobody can say yes"), else APPROVE with approvers → else DENY. Any StoreError → degraded path.
INVARIANTS:
- Default is deny: unknown action, unknown level, no tuple.
- APPROVE with zero approvers is DENY: an approval nobody can give is a refusal.
- Fail-closed when the store can't answer (StoreError): tier `read` → ALLOW degraded; otherwise fallback_approvers → APPROVE degraded; none → DENY degraded. `degraded=True` marks it for audit. Only reads are ever allowed blind.
- Door does not check ceilings. Ceilings are a WRITE-time rule (bab/ceiling.py permitted); a grant tuple in the store is honoured regardless.
- Relation-name contract: Door (`act.name`, `act.gated`), ceiling.Grant.relation, sync/topology.relations(), the fixture model/example.fga.yaml and any future caller all hard-code these names. Renaming a suffix in model.py breaks every one; catalogue.py forbids actions named `*_gated`, `ceiling_*`, or RESERVED (member, team, owner, approver, user, agent) so generated names can't collide.
- The generated model is committed and drift-checked (tests/test_model.py, CI `git diff --exit-code model/example.fga`).
CONSUMERS: bab/cli.py cmd_check; README "In an agent" example; tests/test_door.py (FakeStore, no inheritance); `fga model test` on model/example.fga.yaml for inheritance semantics. Planned, not built: agent SDK at tool dispatch, kobo /guardrails/check (docs/design.md).
API: bab.Door, bab.Decision, bab.Verdict; bab.store.{Store, StoreError, Tuple, OpenFgaStore}; bab.model.generate.
