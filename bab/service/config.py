"""Build the service from the environment. One place that reads BAB_* for `bab serve`."""

from __future__ import annotations

import os

from bab import catalogue as cat_mod
from bab.service.app import Settings, create_app
from bab.service.identity import ConsoleAuth, JwksVerifier, StaticVerifier, TokenReviewVerifier
from bab.service.ledger import Ledger
from bab.service.minters import default_minters
from bab.store import OpenFgaStore

K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def _required(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"{name} is required")
    return v


def agent_verifier():
    mode = os.environ.get("BAB_IDENTITY", "tokenreview").strip()
    audience = os.environ.get("BAB_TOKEN_AUDIENCE", "bab")
    if mode == "tokenreview":
        api = os.environ.get("BAB_K8S_API", "https://kubernetes.default.svc")
        with open(os.environ.get("BAB_K8S_TOKEN_FILE", K8S_TOKEN)) as fh:
            bearer = fh.read().strip()
        return TokenReviewVerifier(api, bearer, audience, os.environ.get("BAB_K8S_CA_FILE", K8S_CA))
    if mode.startswith("jwks:"):
        return JwksVerifier(mode[len("jwks:"):], audience, os.environ.get("BAB_JWKS_URI") or None)
    if mode.startswith("static:"):  # "static:token=agent,token2=agent2" for local runs only
        pairs = (p.split("=", 1) for p in mode[len("static:"):].split(",") if "=" in p)
        return StaticVerifier({k: v for k, v in pairs})
    raise SystemExit(f"BAB_IDENTITY {mode!r}: tokenreview | jwks:<issuer> | static:<token=agent,...>")


def build_app():
    store = OpenFgaStore(_required("BAB_FGA_URL"), _required("BAB_FGA_STORE_ID"),
                         os.environ.get("BAB_FGA_MODEL_ID") or None)
    cat = cat_mod.load(os.environ.get("BAB_CATALOGUE", "catalogues/room.yaml"))
    db = _required("BAB_DATABASE_URL")  # the room's PostgreSQL, a `bab` database beside OpenFGA's
    if db.startswith("sqlite") and os.environ.get("BAB_ALLOW_SQLITE") != "1":
        raise SystemExit("BAB_DATABASE_URL points at SQLite; a deployment uses PostgreSQL "
                         "(set BAB_ALLOW_SQLITE=1 for a laptop run)")
    ledger = Ledger(db)
    settings = Settings(room=_required("BAB_ROOM"), admin_team=_required("BAB_ADMIN_TEAM"),
                        security_team=_required("BAB_SECURITY_TEAM"))
    return create_app(store, cat, ledger, agent_verifier(), ConsoleAuth(_required("BAB_CONSOLE_TOKEN")),
                      default_minters(), settings)
