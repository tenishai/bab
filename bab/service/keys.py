"""Where a vendor key that outlives a lease is kept, so a restart finds it again.

A lease is short, but a vendor's own key need not be: Datadog's application keys do not
expire, and making one an hour per agent is noise in Datadog's audit trail and in the
inbox of whoever owns the service account. So the minter keeps one key per agent and
hands the same one out lease after lease. That key has to survive bab's own restart,
and bab's ledger records leases, not secrets. It goes to the room's secret store.

The store is written through sero's machine lane and read from a mounted Secret: sero
never returns a value, it delivers one to the cluster, so what bab wrote comes back as
a file a minute or so later. bab only needs the file after a restart; while it runs,
the key it made is in memory.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from typing import Protocol

import httpx

log = logging.getLogger("bab.keys")

SERO_URL_ENV, SERO_AUDIENCE_ENV = "BAB_SERO_URL", "BAB_SERO_AUDIENCE"
SERO_NAMESPACE_ENV, SERO_ACTING_EMAIL_ENV, SERO_APP_ENV = "BAB_SERO_NAMESPACE", "BAB_SERO_ACTING_EMAIL", "BAB_SERO_APP"
SERO_DEFAULT_APP = "bab"
# How often the cluster re-reads the stored path: the longest a restart can miss a key
# bab has just made (it then makes another, and the first is deleted with its lease).
SERO_REFRESH = "1m"
# A record's name is a key in a Kubernetes Secret and a file name in its mount.
NAME_OK = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")


class KeyStoreError(RuntimeError):
    """The store did not take a write. The sentence names a path and a status, never a value."""


class KeyStore(Protocol):
    """Records by name. `get` and `all` are what a restart would find, which lags `put` and
    `remove`; `names` asks the store itself, so it shows a record before a restart could."""

    def get(self, name: str) -> dict | None: ...

    def all(self) -> dict[str, dict]: ...

    def names(self) -> set[str]: ...

    def put(self, name: str, record: dict) -> None: ...

    def remove(self, name: str) -> None: ...


def _http(method: str, url: str, headers: dict, body: dict | None, params: dict | None) -> tuple[int, dict]:
    try:
        resp = httpx.request(method, url, headers=headers, json=body, params=params, timeout=10.0)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        raise KeyStoreError(f"the secret store did not answer: {exc.__class__.__name__}") from exc
    try:
        data = resp.json() if resp.content else {}
    except ValueError:
        data = {}
    return resp.status_code, data if isinstance(data, dict) else {}


class SeroKeys:
    """One path in sero, one key per record, delivered to bab's own namespace as one Secret.

    bab calls as itself: a Google ID token for `audience`, which sero pins to bab's subject
    and to one namespace. sero records `acting_email` beside every write and trusts it for
    nothing; no person is behind these writes, so a deployment names the address they are
    recorded under. The first write also asks sero to deliver the path, which onboards the
    application there when it is new."""

    def __init__(self, url: str, audience: str, namespace: str, acting_email: str, directory: str, *,
                 token: Callable[[str], str], app: str = SERO_DEFAULT_APP, secret: str = "bab-datadog-keys",
                 path: str | None = None, http=None, k8s_namespace: str | None = None):
        self.url, self.audience, self.namespace = url.rstrip("/"), audience, namespace
        self.acting_email, self.directory, self.token = acting_email, directory, token
        self.app, self.secret = app, secret
        # Where bab runs, when it knows. sero delivers to the namespace named after the
        # application unless told; naming it turns a Secret delivered somewhere bab cannot
        # mount it into a refusal bab can log.
        self.k8s_namespace = k8s_namespace
        self.path = path or f"apps/{app}/datadog-keys"
        self.http = http or _http
        self._delivered = False

    # ---- the mount: what a restart finds --------------------------------------

    def get(self, name: str) -> dict | None:
        if not NAME_OK.match(name):
            return None
        try:
            with open(os.path.join(self.directory, name)) as fh:
                record = json.loads(fh.read())
        except (OSError, ValueError):  # no mount, no such file, or not a record
            return None
        return record if isinstance(record, dict) else None

    def all(self) -> dict[str, dict]:
        try:
            names = sorted(os.listdir(self.directory))
        except OSError:
            return {}
        found = {name: self.get(name) for name in names if not name.startswith(".")}
        return {name: record for name, record in found.items() if record is not None}

    # ---- the lane: what bab writes --------------------------------------------

    def _send(self, method: str, route: str, what: str, body: dict | None = None, params: dict | None = None,
              absent_ok: bool = False) -> dict | None:
        try:
            bearer = self.token(self.audience)
        except Exception as exc:  # a token file that is not there is an OSError, not a refusal
            said = exc if isinstance(exc, RuntimeError) else exc.__class__.__name__
            raise KeyStoreError(f"{what}: no identity token for the secret store ({said})") from exc
        status, data = self.http(method, f"{self.url}{route}",
                                 {"Authorization": f"Bearer {bearer}", "Accept": "application/json"}, body, params)
        if absent_ok and status == 404:
            return None
        if not 200 <= status < 300:
            raise KeyStoreError(f"{what}: the secret store answered HTTP {status}")
        return data

    def _where(self) -> dict:
        return {"acting_email": self.acting_email, "namespace": self.namespace, "path": self.path}

    def put(self, name: str, record: dict) -> None:
        if not NAME_OK.match(name):
            raise KeyStoreError(f"{name!r} cannot name a stored key")
        self._send("POST", "/api/service/secrets", f"could not store {name} at {self.path}",
                   {**self._where(), "values": {name: json.dumps(record, sort_keys=True)}, "remove_keys": [], "apply": True})
        self._deliver()

    def _deliver(self) -> None:
        """Ask sero to deliver the path to bab's namespace, once per process. A refusal is
        logged and asked again with the next write. The key is stored either way; until it
        is delivered a restart cannot read it, and the agent's leases get a key of their own."""
        if self._delivered:
            return
        try:
            report = self._send("POST", "/api/service/sync", f"could not deliver {self.path} to the cluster",
                                {**self._where(), "app": self.app, "name": self.secret, "target_name": self.secret,
                                 **({"k8s_namespace": self.k8s_namespace} if self.k8s_namespace else {}),
                                 "refresh_interval": SERO_REFRESH, "apply": True}) or {}
            blocked = [b for b in report.get("blocked") or [] if isinstance(b, str)]
            if blocked:
                raise KeyStoreError(f"could not deliver {self.path} to the cluster: it did not accept {', '.join(blocked)}")
        except KeyStoreError as exc:
            log.warning("%s", exc)
            return
        self._delivered = True

    def names(self) -> set[str]:
        """What sero holds at the path right now (it gives names, never values)."""
        held = self._send("GET", "/api/service/secrets", f"could not read which keys are stored at {self.path}",
                          params=self._where(), absent_ok=True)
        return {k for k in (held or {}).get("keys") or [] if isinstance(k, str)}

    def remove(self, name: str) -> None:
        """Take one record out. sero refuses a merge that would leave a path empty, so the
        last record goes with its path."""
        names = self.names()
        if name not in names:
            return
        what = f"could not remove {name} from {self.path}"
        if names == {name}:
            self._send("DELETE", "/api/service/secrets", what, {**self._where(), "apply": True})
        else:
            self._send("POST", "/api/service/secrets", what,
                       {**self._where(), "values": {}, "remove_keys": [name], "apply": True})


def _own_namespace(path: str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace") -> str | None:
    """The Kubernetes namespace this process runs in, or None outside a cluster."""
    try:
        with open(path) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def sero_keys_from_env(env, directory: str, token: Callable[[str], str]) -> SeroKeys | None:
    """The secret store when a deployment names all of it, else None: bab then keeps no key
    past its lease, which is how it ran before there was a store to keep one in."""
    url, audience, namespace, email = (env.get(k, "").strip() for k in (
        SERO_URL_ENV, SERO_AUDIENCE_ENV, SERO_NAMESPACE_ENV, SERO_ACTING_EMAIL_ENV))
    named = [v for v in (url, audience, namespace, email) if v]
    if len(named) < 4:
        if named:
            log.warning("the secret store is half configured (%s, %s, %s and %s go together): no key is kept past its lease",
                        SERO_URL_ENV, SERO_AUDIENCE_ENV, SERO_NAMESPACE_ENV, SERO_ACTING_EMAIL_ENV)
        return None
    return SeroKeys(url, audience, namespace, email, directory, token=token,
                    app=env.get(SERO_APP_ENV, "").strip() or SERO_DEFAULT_APP, k8s_namespace=_own_namespace())
