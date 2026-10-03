---
card: repo-card:bab
updated: 2026-09-28
anchor: pyproject.toml sha=2f534437e1458529a2138462443648d026ebb11c
---
# bab — repo card

WHAT: "the door": actor → action → object authorization for agent fleets on OpenFGA, with three verdicts: allow, approve (a human on the owning team says yes), deny (default). A YAML catalogue generates the OpenFGA model; `Door.decide` is the one runtime check at tool dispatch.
STATE: main, v0.1.0 (pyproject + bab/__init__.py), package name `tenish-bab`. Increment one of docs/design.md done 2026-09-16 (catalogue, generated model with ceilings, door, ceiling check, Okta + topology syncs, CLI, demo). No commits since. Not deployed from here; no sibling repo imports it yet.
STACK: Python ≥3.11, hatchling. Deps: openfga-sdk ≥0.9 (sync client, imported lazily inside OpenFgaStore), pyyaml, httpx. Dev: pytest, ruff. OpenFGA CLI `fga` (FGA_VERSION 0.7.20) fetched by `make fga`. Dockerfile: python:3.12-slim, ENTRYPOINT `bab` (meant for sync CronJobs / ops checks).
ENTRY:
- CLI `bab` → bab/cli.py:main: `model <catalogue>` (DSL to stdout), `check --agent --action --object [--fallback-approver]` (exit 2 on deny), `sync okta|topology [--dry-run] [--file]`. Store from --url/--store-id/--model-id or BAB_FGA_URL / BAB_FGA_STORE_ID / BAB_FGA_MODEL_ID.
- library → `from bab import Door, Catalogue, Decision, Verdict`; bab.store.OpenFgaStore.
- Makefile: fga, model (regenerate + validate), test-model (`fga model test` on model/example.fga.yaml), demo / demo-down (OpenFGA in Docker on :18080).

SEAMS → card:
- door  bab/door.py + bab/model.py  (decision contract, fail-closed; relation names the generator emits)  → docs/arch/door.md
- (uncarded) bab/catalogue.py: resources (root first) + actions (tier read|mutate|destroy, global); validates names against RESERVED and generated suffixes
- (uncarded) bab/store.py: `Store` Protocol (check, list_users, list_objects, write, delete, read_all) + OpenFgaStore; everything above talks to Store
- (uncarded) bab/ceiling.py: write-time check `permitted(store, team, Grant)`; `violations()` for a ceiling shrink; `team_of()`. Callers today: tests only (the grant writer is the planned kobo console)
- (uncarded) bab/sync/: `reconcile(store, desired, relations)`; okta.py → `user:<email> member team:<t>` from engineering_* groups; topology.py → agent team, root owner, parent links (YAML file or Gojira GET /api/v1/topology)

DEPS: none imported. Calls out over HTTP: an Okta viewer JSON API (okta sync, bearer BAB_OKTA_TOKEN), gojira /api/v1/topology (BAB_GOJIRA_TOKEN; design.md says the endpoint does not exist yet; unverified here), OpenFGA server. Planned callers (design.md increments 3-4, not built): the agent SDK calling Door.decide at tool dispatch; a kobo console module for grants/assertions.
HEALTH: 5 test files, 21 passed + 1 skipped locally (test_suite_passes_under_fga_cli skips without `fga`). tests/conftest.py FakeStore answers tuples literally, NO inheritance: model semantics are covered only by `fga model test`. CI .github/workflows/ci.yml (3.12, ubuntu-latest): ruff check, make fga, `make model && git diff --exit-code model/example.fga` (generated-model drift), make test-model, pytest. No branch protection: CI reports, never blocks.
GOTCHAS:
- model/example.fga is GENERATED from catalogues/example.yaml by bab/model.py. Never hand-edit; CI and tests/test_model.py both diff it.
- model/example.fga.yaml is the fixture + assertions for `fga model test` AND the demo's `fga store import`. Its users are bare ids (user:shaz) while the Okta sync keys users by lowercased email; the fixture is illustrative, not sync output.
- Its grants exceed its ceilings (e.g. iris configmap_update on a dev project with no ceiling_configmap_update). Legal: ceilings are enforced at WRITE time by ceiling.permitted, never at check time. A tuple written directly bypasses them.
- Syncs own WHOLE relations: okta owns `member`; topology owns `team`, `owner` and parent-link relations. A topology sync from a partial file deletes every link it didn't produce.
- OpenFgaStore wraps check/list_users/list_objects errors in StoreError (door fails closed), but write/delete/read_all do not: a sync failure surfaces as a raw SDK exception.
- The write gate with pinned assertions (README "every policy change is tested before it lands") is design, not code: nothing here runs assertions on a grant write.
- docs/design.md is partly stale: its data-model section names ceiling tuples `<action>_ceiling` and says ceilings stay out of the runtime model; the code (and design.md's own "Decisions" section) uses `ceiling_<action>[_gated]` relations in the model. It cites `gen_model.py` / `scripts/gen_model.py`; the generator is bab/model.py.
- bab is authorization, NOT the approval UX: it returns approvers; posting the plan and waiting for ✅ is the caller's job.
RELATED DOCS: docs/design.md (data model, API sketch, increments), README.md.
