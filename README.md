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
- Every policy change is **tested** before it lands: pinned assertions run
  against the candidate tuples and a failure names the assertion.

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
atlas     pod_delete   namespace:platform-prod/ingest  -> {"verdict": "approve", "approvers": ["user:carol", "user:bob", "user:alice"], ...}
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

## Layout

| Path | What |
|---|---|
| `catalogues/*.yaml` | resource levels + actions; one profile per deployment (the example ships) |
| `bab/model.py` | catalogue -> OpenFGA DSL (allow / approve / either / two ceilings, per level) |
| `bab/door.py` | the decision at tool dispatch, fail-closed |
| `bab/ceiling.py` | write-time check: may this team hold this grant? |
| `bab/sync/` | identity (Okta groups -> members), topology (tree + owners); reconcile owns whole relations |
| `model/example.fga.yaml` | the fixture + assertions; `fga model test` and `fga store import` both read it |

## License

AGPL-3.0, the GNU Affero General Public License version 3 (see [LICENSE](LICENSE)).

Copyright (C) 2026 tenishai
