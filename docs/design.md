# Fleet Guardrails — data model and API (draft for review)

2026-09-16 · Ember · status: APPROVED (increment one: model, ceiling, live enforcement, syncs)

> **Design record.** Written in September 2026 to decide what to build. Only
> increment one exists in this repo; the console, the deploy and the SDK hook
> below are plans. [ARCHITECTURE.md](../ARCHITECTURE.md) describes the code as
> it is. Ember is the AI coding agent Shaz pairs with (see the README).

## Shape

Actor → action → object, with three verdicts: **allow**, **approve** (a human
in the owning team says yes), **deny** (default). Approvers are derived from
team membership, not pasted into each agent.

## Components

| Part | What | Runtime path? |
|---|---|---|
| Store | OpenFGA server, a new database on an existing PostgreSQL-compatible cluster (dev first) | yes |
| Enforcement | the agent SDK policy hook: one `check` at tool dispatch, fail-closed | yes |
| Console | kobo module: what-can, playground, grant editor, pinned assertions | no |
| Syncs | Okta (people), topology (resources), console (grants) | no |

The runtime never depends on the console. If the store is unreachable past a
TTL, the SDK degrades to *approve for every mutation, allow reads*. The
emergency lever stays in IAM: revoke the GSA binding or scale the agent to 0.

## Data model

### Catalogue (human-edited, generates the OpenFGA model)

```yaml
resources: [project, cluster, namespace]     # root first; each inherits from its parent
actions:
  - {name: pod_delete, tier: mutate, description: ...}
  - {name: log_read,   tier: read, global: true}   # global: grantable to agent:*
```

The generator (`bab/model.py`) emits, per action A on every level: `A`
(allow), `A_gated` (approve), `can_A` (either), and the team ceilings
`ceiling_A` and `ceiling_A_gated`, each inheriting from the parent level.
Approver on a project = `member from owner`; clusters and namespaces inherit it.
Nobody hand-edits `model/example.fga`; a catalogue change regenerates it and
reruns the suite.

### Types

`user`, `team`, `agent`, `project`, `cluster`, `namespace`.
Adding a level (e.g. `topic` under `cluster`) is one list entry in the catalogue.

### Tuple sources (nothing else writes to the store)

| Source | Tuples | Cadence |
|---|---|---|
| **Okta sync** via an Okta groups JSON API (IAP) | `user:X member team:T` for each `engineering_*` group | every 15 min; deletions supersede |
| **Topology sync** from Gojira (clusters, apps, namespaces); a graph store later once it holds infra nodes | `agent → team`, `project owner team`, `cluster project`, `namespace cluster` | on provision events + hourly reconcile |
| **Console** (kobo) | grants: `agent:A <action> <object>` / `<action>_gated`, and `agent:* <action>` for globals | on demand, immediate |

### Ceiling (what a tenant may hold at most)

Per team, a list of `(action, verdict, object)` maxima, stored as
`team:T ceiling_<action>[_gated] <object>` tuples; the model inherits them down
the levels like grants, and an allow ceiling implies an approve ceiling. A grant
is refused unless the agent's team holds a ceiling covering that action at that
object or an ancestor, and a grant of `allow` needs an `allow` ceiling (an
`approve` ceiling only permits `approve` grants). The check runs at **write
time** (`bab.ceiling.permitted`), not at tool dispatch, because OpenFGA can't
traverse from the agent to its team inside a single relation. Ceiling edits
require a second team-member approval in the console (four-eyes), same hour.

### Write gate (replaces git review)

Every console write runs, against the candidate tuples, (1) the ceiling check,
(2) every pinned assertion. Any failure rejects the write with the failing
assertion named. Writes commit atomically; OpenFGA's change log records who and
when. Pinned assertions are stored alongside the grants and rendered in the
console as sentences with a live green/red status.

### Verdict algorithm (SDK, at tool dispatch)

```
if check(agent, A, object):        allow → run tool
elif check(agent, A_gated, object): approve → post plan, wait for ✅ from any
                                    user with approver on object (list_users)
else:                               deny → tool result explains, LLM does not retry
```
Every decision is logged with the store's consistency token, so an audit can
replay what the policy was at that moment.

## API (kobo module, sketch)

| Method | Path | Purpose |
|---|---|---|
| POST | `/guardrails/check` | `{agent, action, object, requester?}` → verdict + approvers |
| POST | `/guardrails/explain` | same input → verdict + the tuple chain (expand) |
| GET | `/guardrails/agents/{agent}` | what-can table: action × objects × verdict × approvers |
| GET | `/guardrails/teams/{team}/ceiling` | current maxima |
| POST | `/guardrails/grants` | propose grant; runs write gate; commits or returns the failure |
| DELETE | `/guardrails/grants/{id}` | revoke (immediate; IAM render follows) |
| POST | `/guardrails/assertions` | pin a playground check as a suite assertion |
| POST | `/guardrails/tests/run` | run the suite against the live store; results per assertion |
| POST | `/guardrails/sync/{okta,topology}` | trigger a sync; also on schedule |

Runtime agents call `check` on the OpenFGA gRPC port directly, not through kobo.

## Decisions taken during increment one

- **Identity key is email** (`user:alice@example.com`): the one id Okta, Slack
  (`users.lookupByEmail`) and GCP share. Agents' Slack approval flows resolve
  email -> Slack id at approval time.
- **Ceilings live in the model** as `ceiling_<action>[_gated]` relations on
  teams, inherited like grants; an allow ceiling implies an approve ceiling.
  The write-time check is one `check` call (`bab.ceiling.permitted`).
- **Syncs own whole relations**: Okta owns `member`; topology owns `team`,
  `owner` and the parent links. Reconcile deletes what the source stopped
  producing and touches nothing else, so a sync can never clobber a grant.
- **Gojira needs `GET /api/v1/topology`** (clusters + project, apps + team +
  environments' namespaces) — it has no list endpoints today. Until then the
  topology sync reads a YAML file of the same shape.
- **Team ownership of projects** is not recorded anywhere yet; the namespace
  label `example.com/team` is the nearest existing fact and the topology endpoint
  should surface it.

## Increments

1. **Done (this repo)**: catalogue, generated model with ceilings, suite,
   door (fail-closed), ceiling check, both syncs, CLI, live demo.
2. Deploy: OpenFGA on the dev cluster against a new database on an existing
   PostgreSQL-compatible cluster; sync CronJobs; Gojira topology endpoint.
3. SDK: the agent SDK calls `Door.decide` at tool dispatch; Atlas + Beacon adopt.
4. Console in kobo: what-can, playground + explain, grants with the write gate,
   pinned assertions.

## Not decided / open

- IAM rendering from grants (GSA bindings, K8s RBAC) — designed as a later
  emitter; not in the first increment.
- Requester attributes beyond team membership (time windows, ticket refs) —
  deferred until a real rule needs them; OpenFGA conditions exist if so.
- Atlas's full action list (7 gated kinds today) and Beacon's need entering in
  the catalogue; the prototype carries 5 representative actions.

## Prototype artifacts

`catalogues/example.yaml`, `bab/model.py` (the generator), `model/example.fga`
(generated), `model/example.fga.yaml` (the `fga model test` suite, which CI
runs).
