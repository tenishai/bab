"""bab CLI: model generation, a decision, and the syncs."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from bab import catalogue as cat_mod
from bab import model as model_mod
from bab.door import Door
from bab.store import OpenFgaStore
from bab.sync import okta, reconcile, topology


def _store(args) -> OpenFgaStore:
    url = args.url or os.environ.get("BAB_FGA_URL", "http://localhost:8080")
    store_id = args.store_id or os.environ.get("BAB_FGA_STORE_ID")
    if not store_id:
        sys.exit("store id required (--store-id or BAB_FGA_STORE_ID)")
    return OpenFgaStore(url, store_id, args.model_id or os.environ.get("BAB_FGA_MODEL_ID"),
                        os.environ.get("BAB_FGA_TOKEN") or None)


def cmd_model(args) -> int:
    sys.stdout.write(model_mod.generate(cat_mod.load(args.catalogue)))
    return 0


def cmd_check(args) -> int:
    door = Door(_store(args), cat_mod.load(args.catalogue), tuple(args.fallback_approver or ()))
    d = door.decide(args.agent, args.action, args.object)
    print(json.dumps({"verdict": d.verdict.value, "reason": d.reason,
                      "approvers": list(d.approvers), "degraded": d.degraded}))
    return 0 if d.verdict.value != "deny" else 2


def cmd_sync(args) -> int:
    store = _store(args)
    if args.source == "okta":
        fetch = okta.http_fetch(args.okta_url, os.environ.get("BAB_OKTA_TOKEN"))
        desired, rels = okta.tuples(fetch, args.prefix), okta.RELATIONS
    else:
        cat = cat_mod.load(args.catalogue)
        topo = topology.from_file(args.file) if args.file else topology.from_gojira(
            args.gojira_url, os.environ.get("BAB_GOJIRA_TOKEN", ""))
        desired, rels = topology.tuples(topo, cat), topology.relations(cat)
    write, delete = reconcile(store, desired, rels, dry_run=args.dry_run)
    for t in write:
        print(f"+ {t}")
    for t in delete:
        print(f"- {t}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from bab.service.config import build_app

    uvicorn.run(build_app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_sweep(args) -> int:
    from datetime import UTC, datetime

    from bab import grants

    dead = grants.sweep(_store(args), datetime.now(UTC))
    for t in dead:
        print(f"- {t}")
    print(f"swept {len(dead)} expired grants")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bab", description="the door")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("model", help="generate the OpenFGA model from a catalogue")
    m.add_argument("catalogue")
    m.set_defaults(fn=cmd_model)

    def store_args(sp):
        sp.add_argument("--url")
        sp.add_argument("--store-id")
        sp.add_argument("--model-id")
        sp.add_argument("--catalogue", default="catalogues/example.yaml")

    c = sub.add_parser("check", help="decide: allow / approve / deny")
    store_args(c)
    c.add_argument("--agent", required=True)
    c.add_argument("--action", required=True)
    c.add_argument("--object", required=True)
    c.add_argument("--fallback-approver", action="append")
    c.set_defaults(fn=cmd_check)

    s = sub.add_parser("sync", help="reconcile one tuple source into the store")
    store_args(s)
    s.add_argument("source", choices=["okta", "topology"])
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--okta-url", default=os.environ.get("BAB_OKTA_URL", ""))
    s.add_argument("--prefix", default="engineering_")
    s.add_argument("--file", help="topology YAML (instead of Gojira)")
    s.add_argument("--gojira-url", default=os.environ.get("BAB_GOJIRA_URL", ""))
    s.set_defaults(fn=cmd_sync)

    sv = sub.add_parser("serve", help="run the HTTP service (configured by BAB_* variables)")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=int(os.environ.get("BAB_PORT", "8080")))
    sv.set_defaults(fn=cmd_serve)

    sw = sub.add_parser("sweep", help="delete grant tuples whose window has closed")
    store_args(sw)
    sw.set_defaults(fn=cmd_sweep)

    args = p.parse_args(argv)
    if getattr(args, "source", None) == "okta" and not args.okta_url:
        p.error("--okta-url (or BAB_OKTA_URL) is required for the okta sync")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
