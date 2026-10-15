# bab — the door

*bab* (باب, "door") decides who may pass: **actor → action → object**, with three
verdicts — **allow**, **approve** (a human on the owning team says yes), **deny**
(default). Built for fleets of AI agents; the same shape serves a parent setting
what a child's companion may do.

- A small **catalogue** (resource tree + actions) generates an
  [OpenFGA](https://openfga.dev) model. Nobody hand-edits the model.
- Three **tuple sources** and nothing else writes to the store: an identity sync
  (people → teams), a topology sync (the resource tree and who owns it), and the
  console (grants, ceiling-checked at write time).
- The runtime path is one `check` at tool dispatch, fail-closed. The console is
  never in the runtime path; the emergency lever stays in IAM.
- Policy changes are meant to be **tested** before they land: pinned assertions
  run against the candidate tuples and a failure names the assertion. This write
  gate is design, not code yet (docs/design.md, increment 4).

Design: [docs/design.md](docs/design.md). First profile: [catalogues/example.yaml](catalogues/example.yaml).

## Try it

```
make fga         # fetch the OpenFGA CLI for this platform
make model       # catalogue -> model/example.fga (generated; CI fails if it drifts)
make test-model  # run model/example.fga.yaml: checks, list-objects, list-users
make demo        # real OpenFGA in Docker, example profile loaded, six live verdicts (needs: pip install -e .)
make demo-down
```

`make demo` prints, for example:

```
atlas     pod_delete   namespace:platform-dev/ingest   -> {"verdict": "allow", ...}
atlas     pod_delete   namespace:platform-prod/ingest  -> {"verdict": "approve", "approvers": ["user:alice", "user:bob", "user:carol"], ...}
beacon   pod_delete   namespace:data-kafka/streams   -> {"verdict": "deny", "reason": "agent:beacon holds neither pod_delete nor pod_delete_gated on ...
--- store unreachable (fail-closed):
{"verdict": "approve", "reason": "store unreachable; fallback approvers", "degraded": true}
```

## In an agent

```python
from bab import Door, catalogue
from bab.store import OpenFgaStore

door = Door(OpenFgaStore(url, store_id), catalogue.load("catalogues/example.yaml"),
            fallback_approvers=("user:alice@example.com",))
d = door.decide("atlas", "pod_delete", "namespace:platform-prod/ingest")
# d.verdict in {ALLOW, APPROVE, DENY}; d.approvers; d.reason; d.degraded
```

## Syncs

```
bab sync okta --okta-url https://okta.example.com   # or BAB_OKTA_URL; required
bab sync topology --file topology.yaml              # or from Gojira: --gojira-url / BAB_GOJIRA_URL
```

The okta sync turns groups named `engineering_<team>` into team members;
`--prefix` changes that prefix. Bearer tokens come from `BAB_OKTA_TOKEN` and
`BAB_GOJIRA_TOKEN`. `--dry-run` prints the writes (`+`) and deletes (`-`)
without applying them. Each sync owns whole relations, so it deletes any tuple
in those relations that it didn't produce.

## Layout

| Path | What |
|---|---|
| `catalogues/*.yaml` | resource levels + actions; one profile per deployment (the example ships) |
| `bab/model.py` | catalogue -> OpenFGA DSL (allow / approve / either / two ceilings, per level) |
| `bab/door.py` | the decision at tool dispatch, fail-closed |
| `bab/ceiling.py` | write-time check: may this team hold this grant? |
| `bab/sync/` | identity (Okta groups -> members), topology (tree + owners); reconcile owns whole relations |
| `model/example.fga.yaml` | the fixture + assertions; `fga model test` and `fga store import` both read it |

## How this was built

tenishai is a small team of engineers who build with AI coding agents. Most of
this code was written in pairing sessions with Claude models in Claude Code: a
person set the design, directed the work and reviewed what landed, and the
agent wrote much of the code and docs. Many commits name the agent in a
`Co-Authored-By:` trailer, either a Claude model or Poe (earlier Raven), the
name of the agent one of us pairs with. A commit without a trailer may still
have had AI help.

In this repo, "Ember (SRE AI)" in docs and pull requests is the agent Shaz pairs
with. Its commits name the Claude model in the trailer, not Ember.

## License

AGPL-3.0-or-later, the GNU Affero General Public License version 3 or (at your option) any later version (see [LICENSE](LICENSE)).

Copyright (C) 2026 tenish and the bab contributors
