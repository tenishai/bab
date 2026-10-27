---
card: repo-card:bab
updated: 2026-10-27
anchor: pyproject.toml sha=3a2e2c9bcdb25633aba73c68bcc70f6870361c06
---
# bab — repo card

WHAT: "the door": actor → action → object authorization for agent fleets on OpenFGA, with three verdicts: allow, approve (a human on the owning team says yes), deny (default). A YAML catalogue generates the OpenFGA model; `Door.decide` is the one runtime check, meant to run at tool dispatch.
STATE: main, v0.2.0 (pyproject + bab/__init__.py), package name `tenish-bab`. Increment one of docs/design.md (catalogue, model with ceilings, door, syncs, CLI) tagged v0.1.0; increments two and three of docs/design-leases.md (expiring grants, `bab serve`, ledger, AWS minter) are 0.2.0. Deployed on one dev cluster through a sibling config repo (bab + OpenFGA, Postgres-backed); CHANGELOG.md from 0.2.0.
STACK: Python ≥3.11, hatchling. Deps: openfga-sdk ≥0.9 (sync client, imported lazily inside OpenFgaStore), pyyaml, httpx. Extras: service (fastapi, uvicorn, sqlalchemy, PyJWT), postgres (psycopg), aws (botocore). Dev: pytest, ruff, httpx. OpenFGA CLI `fga` (FGA_VERSION 0.7.20) fetched by `make fga`. Dockerfile: python:3.12-slim, ENTRYPOINT `bab` (meant for sync CronJobs / ops checks).
ENTRY:
- CLI `bab` → bab/cli.py:main: `model <catalogue>` (DSL to stdout), `check --agent --action --object [--fallback-approver]` (exit 2 on deny), `sync okta|topology [--dry-run] [--file]`, `serve [--host --port]` (the HTTP service from BAB_*), `sweep` (delete expired grant tuples). Store from --url/--store-id/--model-id or BAB_FGA_URL / BAB_FGA_STORE_ID / BAB_FGA_MODEL_ID.
- library → `from bab import Door, Catalogue, Decision, Verdict`; bab.store.OpenFgaStore.
- Makefile: fga, model (regenerate + validate), test-model (`fga model test` on model/example.fga.yaml), demo / demo-down (OpenFGA in Docker on :18080).

SEAMS → card:
- door  bab/door.py + bab/model.py + bab/grants.py  (decision contract, fail-closed; relation names the generator emits; the grant_window condition; the one grant writer and the sweep)  → docs/arch/door.md
- (uncarded) bab/catalogue.py: resources (root first) + actions (tier read|mutate|destroy, global, display `group`) + `tiers` (lease_seconds, validity_days per tier; defaults TIER_DEFAULTS read 3600/standing, mutate 3600/30d, destroy 1800/7d); validates names against RESERVED and generated suffixes
- (uncarded) bab/store.py: `Store` Protocol (check(..., context), list_users, list_objects, write, delete, read_all) + OpenFgaStore; `Tuple.expires_at` rides as the `grant_window` condition's context; everything above talks to Store
- (uncarded) bab/ceiling.py: write-time check `permitted(store, team, Grant)`; `violations()` for a ceiling shrink; `team_of()`. Caller: bab/grants.py `grant`
- (uncarded) bab/service/: bab as an HTTP service (`bab serve`, FastAPI, the `[service]` extra). app.py `create_app(store, cat, ledger, agent_verifier, console, minters, settings)`: PUT /integrations/{id} (connect + ceiling tuples for every team + room link), POST/GET /requests, POST /requests/decide (bulk; admin or security team; destroy tier needs security; ceiling-checked grant per permission via bab/grants.py), GET /agents/{a}/grants, DELETE /grants/{id} (revoke now), POST /leases (agent token only: batch check with current_time -> mint for the granted subset, 202 + a one-hour `lease` request for gated ones, 403 when nothing), GET /leases, POST /check, POST /sweep, GET /catalogue/{vendor}. ledger.py: SQLAlchemy tables integrations, requests, grants, leases, events; BAB_DATABASE_URL is required and must be PostgreSQL (a `bab` database on the room's instance) unless BAB_ALLOW_SQLITE=1; tests use SQLite in memory. identity.py: TokenReviewVerifier (in-cluster), JwksVerifier (issuer + JWKS), StaticVerifier (tests); agent = the service account's name; ConsoleAuth = shared token + X-Bab-Actor email. minters.py: `Minter.mint(agent, integration, spec, permissions, seconds) -> Minted`, AwsMinter (AssumeRoleWithWebIdentity with bab's own Google ID token, RoleSessionName=bab-<agent> (that API takes no SourceIdentity), session policy = union of the permissions' `extra.iam`), StaticMinter. config.py builds it all from BAB_* (BAB_FGA_URL/STORE_ID/MODEL_ID, BAB_CATALOGUE, BAB_DATABASE_URL, BAB_ROOM, BAB_ADMIN_TEAM, BAB_SECURITY_TEAM, BAB_CONSOLE_TOKEN, BAB_IDENTITY=tokenreview|jwks:<issuer>|static:...)
- (uncarded) catalogues/room.yaml: the room-shaped catalogue (resources room, integration; permissions per vendor with `group`, `vendor`, `extra.iam`); not drift-checked (only example.fga is)
- (uncarded) bab/sync/: `reconcile(store, desired, relations)`; okta.py → `user:<email> member team:<t>` from engineering_* groups; topology.py → agent team, root owner, parent links (YAML file or Gojira, the service that connects GitHub repos to GKE, GET /api/v1/topology)

DEPS: none imported. Calls out over HTTP: an Okta groups JSON API (behind IAP) (okta sync, bearer BAB_OKTA_TOKEN), gojira /api/v1/topology (BAB_GOJIRA_TOKEN; design.md says the endpoint does not exist yet; unverified here), OpenFGA server. Planned callers (design.md increments 3-4, not built): the agent SDK calling Door.decide at tool dispatch; a kobo (the web console) module for grants/assertions.
HEALTH: 5 test files, 21 passed + 1 skipped locally (test_suite_passes_under_fga_cli skips without `fga`). tests/conftest.py FakeStore answers tuples literally, NO inheritance: model semantics are covered only by `fga model test`. CI .github/workflows/ci.yml (3.12, ubuntu-latest): ruff check, make fga, `make model && git diff --exit-code model/example.fga` (generated-model drift), make test-model, pytest. No branch protection: CI reports, never blocks.
GOTCHAS:
- model/example.fga is GENERATED from catalogues/example.yaml by bab/model.py. Never hand-edit; CI and tests/test_model.py both diff it.
- model/example.fga.yaml is the fixture + assertions for `fga model test` AND the demo's `fga store import`. Its users are bare ids (user:alice) while the Okta sync keys users by lowercased email; the fixture is illustrative, not sync output.
- Its grants exceed its ceilings (e.g. atlas configmap_update on a dev project with no ceiling_configmap_update). Legal: ceilings are checked at write time by bab/grants.py `grant`; the fixture is imported, not granted, and Door never checks them.
- Syncs own WHOLE relations: okta owns `member`; topology owns `team`, `owner` and parent-link relations. A topology sync from a partial file deletes every link it didn't produce.
- OpenFgaStore wraps check/list_users/list_objects errors in StoreError (door fails closed), but write/delete/read_all do not: a sync failure surfaces as a raw SDK exception.
- The write gate with pinned assertions (README "every policy change is tested before it lands") is design, not code: nothing here runs assertions on a grant write.
- docs/design.md is a design record: the console, deploy and SDK hook it describes are plans, not code.
- bab is authorization, NOT the approval UX: it returns approvers; posting the plan and waiting for ✅ is the caller's job.
RELATED DOCS: docs/design.md (data model, API sketch, increments), README.md.
