"""Minters: one per credential family. Each turns a granted permission set into a
short-lived vendor credential, scoped as far as the vendor allows, and can end
one early where the vendor allows that too.

bab is the only principal the vendor trusts; agents never hold anything standing.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from bab.catalogue import Action

log = logging.getLogger(__name__)


class MintError(RuntimeError):
    """The vendor refused, or the integration is not set up for minting."""


class NotConfigured(MintError):
    """bab holds nothing for this vendor yet; connecting it is what is missing, not a retry."""


@dataclass(frozen=True)
class Minted:
    credential: dict[str, Any]  # vendor shape, handed to the agent
    expires_at: float  # epoch seconds
    handle: dict[str, Any]  # what `end` needs; {} when the vendor cannot end early
    note: str = ""  # one line the console shows about how far the vendor narrows


class Minter(Protocol):
    name: str

    def mint(self, agent: str, integration_id: str, spec: dict, permissions: list[Action],
             seconds: int) -> Minted: ...

    def end(self, handle: dict) -> None: ...


class StaticMinter:
    """Tests and local runs: an opaque credential naming what it covers."""

    name = "static"

    def __init__(self, now=time.time):
        self.now = now
        self.ended: list[dict] = []
        self.minted: list[dict] = []
        self.probed: list[tuple] = []
        # Accounts whose spoke role is missing, for discover tests.
        self.refusing_accounts: set[str] = {"222222222222"}

    def mint(self, agent, integration_id, spec, permissions, seconds):
        self.minted.append({"agent": agent, "integration": integration_id, "spec": dict(spec)})
        token = base64.urlsafe_b64encode(json.dumps({
            "agent": agent, "integration": integration_id, "permissions": [p.name for p in permissions],
        }).encode()).decode()
        return Minted({"token": token}, self.now() + seconds, {"token": token}, "a test credential")

    def end(self, handle):
        self.ended.append(handle)

    def identity(self, audience: str = "sts.amazonaws.com") -> dict:
        return {"subject": "static-minter", "email": None, "audience": audience}

    def probe(self, role_arn: str, audience: str = "sts.amazonaws.com", hub_role_arn: str | None = None,
              external_id: str | None = None) -> dict:
        self.probed.append((role_arn, hub_role_arn, external_id))
        for arn in (hub_role_arn, role_arn):
            if arn and "refuse" in arn:
                raise MintError(f"AWS refused {arn}: AccessDenied")
        if hub_role_arn and role_arn.split(":")[4] in self.refusing_accounts:
            raise MintError(f"AWS refused {role_arn}: AccessDenied")
        return {"account": role_arn.split(":")[4], "assumed_arn": role_arn.replace(":role/", ":assumed-role/") + "/bab-probe",
                "hops": 2 if hub_role_arn else 1}

    def list_accounts(self, hub_role_arn: str, audience: str = "sts.amazonaws.com") -> list[dict]:
        return [{"id": "111111111111", "name": "acme-prod", "email": None, "status": "ACTIVE"},
                {"id": "222222222222", "name": "acme-data", "email": None, "status": "ACTIVE"}]


# ---- AWS: AssumeRoleWithWebIdentity with a session policy -----------------------

METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
TOKEN_FILE_ENV = "BAB_AWS_WEB_IDENTITY_TOKEN_FILE"
DEFAULT_AUDIENCE = "sts.amazonaws.com"
_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")
_SESSION_NAME_BAD = re.compile(r"[^\w+=,.@-]")
MIN_SECONDS, MAX_SECONDS = 900, 43200


def session_name(prefix: str, agent: str) -> str:
    return _SESSION_NAME_BAD.sub("-", f"{prefix}{agent}")[:64].ljust(2, "x")


def web_identity_token(audience: str) -> str:
    """bab's own Google ID token, from the metadata server (or a file for tests)."""
    path = os.environ.get(TOKEN_FILE_ENV, "").strip()
    if path:
        with open(path) as fh:
            return fh.read().strip()
    try:
        resp = httpx.get(METADATA_IDENTITY_URL, params={"audience": audience, "format": "full"},
                         headers={"Metadata-Flavor": "Google"}, timeout=5.0)
    except httpx.HTTPError as exc:
        raise MintError(f"no identity token: the metadata server did not answer ({exc})") from exc
    if resp.status_code != 200:
        raise MintError("no identity token: bab's service account has no Google identity linked")
    return resp.text.strip()


# Data-plane reads a read permission never means: object bodies, secret and parameter
# values, table items, queue messages, stream records, query result rows, decryption.
# Denied in every session whatever a permission's `iam` list says, so a wildcard like
# s3:Get* in a catalogue entry can widen configuration reads but never reach the data.
DATA_PLANE_DENY = (
    "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTorrent", "s3:SelectObjectContent",
    "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory",
    "kms:Decrypt", "kms:GenerateDataKey*", "kms:GetPublicKey",
    "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
    "dynamodb:ExecuteStatement", "dynamodb:PartiQLSelect",
    "sqs:ReceiveMessage", "kinesis:GetRecords", "kinesis:GetShardIterator",
    "athena:GetQueryResults", "athena:GetQueryResultsStream",
    "rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement", "redshift-data:GetStatementResult",
    "timestream-query:Query", "lambda:GetFunction", "lambda:GetLayerVersion",
)


def session_policy(permissions: list[Action]) -> dict | None:
    """The IAM session policy that narrows the role to the granted permissions.
    Each permission's `extra.iam` lists its IAM actions; a permission without one
    adds nothing, and if none has one the role's own policy is the only wall. Every
    policy carries the data-plane Deny: a lease is for configuration and listings."""
    actions = sorted({a for p in permissions for a in (p.extra.get("iam") or [])})
    if not actions:
        return None
    return {"Version": "2012-10-17",
            "Statement": [{"Sid": "BabLease", "Effect": "Allow", "Action": actions, "Resource": "*"},
                          {"Sid": "BabNoData", "Effect": "Deny", "Action": list(DATA_PLANE_DENY), "Resource": "*"}]}


class AwsMinter:
    """Two shapes of connection. Flat: `role_arn`, assumed with bab's identity. Hub and spoke
    (one hub role per AWS organization, in its management account): `hub_role_arn` assumed
    with bab's identity, then `spoke_role_arn` in the member account assumed from the hub
    with `external_id`; the session policy and the agent's session name go on the second
    hop, which is the one CloudTrail in the member account records. No cross-organization
    assumes: a second organization is a second hub."""

    name = "aws"

    def __init__(self, token_source=web_identity_token, assume=None, assume_role=None, list_org_accounts=None):
        self.token_source = token_source
        self.assume = assume or self._assume
        self.assume_role = assume_role or self._assume_role
        self.list_org_accounts = list_org_accounts or self._list_org_accounts

    @staticmethod
    def _assume(role_arn: str, token: str, name: str, seconds: int, policy: dict | None) -> dict:
        """AssumeRoleWithWebIdentity. It takes no SourceIdentity (AssumeRole does); the agent's
        name rides in RoleSessionName, which CloudTrail records as the assumed-role ARN's suffix."""
        try:
            import botocore.session
            from botocore import UNSIGNED
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:  # pragma: no cover
            raise MintError("botocore is not installed; install bab with the [aws] extra") from exc
        sts = botocore.session.get_session().create_client(
            "sts", region_name="us-east-1", config=Config(signature_version=UNSIGNED))
        kwargs = {"RoleArn": role_arn, "RoleSessionName": name, "WebIdentityToken": token,
                  "DurationSeconds": seconds}
        if policy:
            kwargs["Policy"] = json.dumps(policy)
        try:
            return sts.assume_role_with_web_identity(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise MintError(f"AWS refused {role_arn}: {err.get('Code', 'error')} {err.get('Message', '')}".strip()) from exc
        except BotoCoreError as exc:
            raise MintError(f"AWS call failed: {exc}") from exc

    @staticmethod
    def _assume_role(creds: dict, role_arn: str, name: str, seconds: int, policy: dict | None,
                     external_id: str | None) -> dict:
        """The second hop: AssumeRole from the hub's session into the member account's role."""
        try:
            import botocore.session
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:  # pragma: no cover
            raise MintError("botocore is not installed; install bab with the [aws] extra") from exc
        sts = botocore.session.get_session().create_client(
            "sts", region_name="us-east-1", aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        kwargs = {"RoleArn": role_arn, "RoleSessionName": name, "DurationSeconds": seconds}
        if external_id:
            kwargs["ExternalId"] = external_id
        if policy:
            kwargs["Policy"] = json.dumps(policy)
        try:
            return sts.assume_role(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise MintError(f"AWS refused {role_arn}: {err.get('Code', 'error')} {err.get('Message', '')}".strip()) from exc
        except BotoCoreError as exc:
            raise MintError(f"AWS call failed: {exc}") from exc

    @staticmethod
    def _list_org_accounts(creds: dict) -> list[dict]:
        """Every account in the organization the hub's session can see."""
        try:
            import botocore.session
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:  # pragma: no cover
            raise MintError("botocore is not installed; install bab with the [aws] extra") from exc
        org = botocore.session.get_session().create_client(
            "organizations", region_name="us-east-1", aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        out, token = [], None
        try:
            while True:
                page = org.list_accounts(NextToken=token) if token else org.list_accounts()
                out += [{"id": a["Id"], "name": a.get("Name"), "email": a.get("Email"), "status": a.get("Status")}
                        for a in page.get("Accounts", [])]
                token = page.get("NextToken")
                if not token:
                    return sorted(out, key=lambda a: (a["name"] or "", a["id"]))
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise MintError(f"AWS refused listing the organization's accounts: {err.get('Code', 'error')} "
                            f"{err.get('Message', '')}".strip()) from exc
        except BotoCoreError as exc:
            raise MintError(f"AWS call failed: {exc}") from exc

    def _hub(self, hub_role_arn: str, audience: str, agent: str) -> dict:
        """First hop: bab's identity into the organization's hub role, briefly, no policy."""
        if not _ROLE_ARN.match(hub_role_arn):
            raise MintError(f"{hub_role_arn!r} is not an IAM role ARN")
        token = self.token_source(audience)
        return self.assume(hub_role_arn, token, session_name("bab-", agent), MIN_SECONDS, None)["Credentials"]

    def mint(self, agent, integration_id, spec, permissions, seconds):
        audience = str(spec.get("audience") or DEFAULT_AUDIENCE)
        seconds = max(MIN_SECONDS, min(MAX_SECONDS, seconds))
        policy = session_policy(permissions)
        hub, spoke = str(spec.get("hub_role_arn", "")).strip(), str(spec.get("spoke_role_arn", "")).strip()
        if hub and spoke:
            if not _ROLE_ARN.match(spoke):
                raise MintError(f"integration {integration_id!r} has no IAM role ARN to assume")
            hub_creds = self._hub(hub, audience, agent)
            # Role chaining caps a session at an hour; the lease is an hour anyway.
            resp = self.assume_role(hub_creds, spoke, session_name("bab-", agent), min(seconds, 3600), policy,
                                    str(spec.get("external_id") or "") or None)
        else:
            role_arn = str(spec.get("role_arn", "")).strip()
            if not _ROLE_ARN.match(role_arn):
                raise MintError(f"integration {integration_id!r} has no IAM role ARN to assume")
            token = self.token_source(audience)
            resp = self.assume(role_arn, token, session_name("bab-", agent), seconds, policy)
        creds = resp["Credentials"]
        exp = creds["Expiration"]
        expires = exp.timestamp() if hasattr(exp, "timestamp") else float(exp)
        return Minted(
            credential={"aws_access_key_id": creds["AccessKeyId"], "aws_secret_access_key": creds["SecretAccessKey"],
                        "aws_session_token": creds["SessionToken"], "assumed_role_arn": resp["AssumedRoleUser"]["Arn"]},
            expires_at=expires, handle={},
            note="session policy narrows to the granted permissions" if policy else "the role's own policy is the wall",
        )

    def end(self, handle):  # AWS cannot recall a session; the lease length is the revocation.
        return None

    def identity(self, audience: str = DEFAULT_AUDIENCE) -> dict:
        """Who bab is to AWS: the claims of its own identity token (the `sub` an account
        owner writes into a role's trust policy, with `oaud` = the audience)."""
        token = self.token_source(audience)
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (IndexError, ValueError) as exc:
            raise MintError("bab's identity token is not a JWT") from exc
        return {"subject": str(claims.get("sub", "")), "email": claims.get("email"), "audience": audience,
                "issuer": claims.get("iss")}

    def probe(self, role_arn: str, audience: str = DEFAULT_AUDIENCE, hub_role_arn: str | None = None,
              external_id: str | None = None) -> dict:
        """Assume the role once, briefly, with no policy: does its trust admit bab (a hub or a
        flat role), or the hub (a spoke, when `hub_role_arn` is given)?"""
        if not _ROLE_ARN.match(role_arn):
            raise MintError(f"{role_arn!r} is not an IAM role ARN")
        if hub_role_arn:
            hub_creds = self._hub(hub_role_arn, audience, "probe")
            resp = self.assume_role(hub_creds, role_arn, "bab-probe", MIN_SECONDS, None, external_id or None)
            hops = 2
        else:
            token = self.token_source(audience)
            resp = self.assume(role_arn, token, "bab-probe", MIN_SECONDS, None)
            hops = 1
        arn = resp["AssumedRoleUser"]["Arn"]
        return {"account": arn.split(":")[4], "assumed_arn": arn, "hops": hops}

    def list_accounts(self, hub_role_arn: str, audience: str = DEFAULT_AUDIENCE) -> list[dict]:
        """The organization's accounts, as the hub can see them."""
        return self.list_org_accounts(self._hub(hub_role_arn, audience, "discover"))


# ---- Datadog: a scoped application key on bab's service account, per lease -------

DD_SITE_ENV, DD_API_KEY_ENV = "DD_SITE", "DD_API_KEY"
DD_MGMT_APP_KEY_ENV, DD_SERVICE_ACCOUNT_ID_ENV = "DD_MGMT_APP_KEY", "DD_SERVICE_ACCOUNT_ID"
DD_DIR_ENV, DD_DEFAULT_DIR = "BAB_DATADOG_DIR", "/etc/bab/datadog"
DD_DEFAULT_SITE = "datadoghq.com"
DD_NOT_CONFIGURED = "Datadog is not configured on the permission service yet: connect it under Admin > Integrations"
DD_MAX_SECONDS = 3600  # Datadog keys do not expire; bab deletes them, so a lease stays short
# A Datadog key with no scopes carries everything its owner may do, so a probe key is
# scoped to the narrowest read the owner's role holds anyway (the first thing the room grants).
DD_PROBE_SCOPES = ("monitors_read",)
_DD_KEY_NAME_BAD = re.compile(r"[^\w.-]")


# Datadog's hosted MCP server admits a key only if it carries `mcp_read` (every tool) and
# `mcp_write` (the tools that create or change something) on top of the resource
# permissions, so every lease carries them: the resource scopes still decide what the key
# may touch, and a read-only lease stays read-only there too.
DD_MCP_READ = "mcp_read"
DD_MCP_WRITE = "mcp_write"


def dd_scopes(permissions: list[Action]) -> list[str]:
    """The union of the granted permissions' `extra.scopes`, plus the MCP scope(s) that let
    the key be used through Datadog's MCP server: what the key may do."""
    scopes = {s for p in permissions for s in (p.extra.get("scopes") or [])}
    if scopes:
        scopes.add(DD_MCP_READ)
        if any(p.tier == "mutate" for p in permissions):
            scopes.add(DD_MCP_WRITE)
    return sorted(scopes)


@dataclass(frozen=True)
class DatadogConfig:
    service_account_id: str
    site: str
    api_key: str = field(repr=False)
    mgmt_app_key: str = field(repr=False)


class DatadogMinter:
    """Datadog has no short-lived tokens, but an application key on a service account can
    carry exactly the permissions a lease needs, is created and deleted by API, and names
    itself in Datadog's audit trail. A lease is one such key, `bab-<agent>-<minute>`, scoped
    to the granted permissions' scopes and deleted when the lease ends (expiry, revoke, sweep).
    bab holds one management application key (`service_account_write`) to do that with.

    Its configuration is read on every call, never at boot: the room writes the Secret the
    moment an admin connects Datadog and probes at once, and a disconnect removes it again,
    so a value cached at boot would be absent first and stale afterwards."""

    name = "datadog"

    def __init__(self, directory: str | None = None, env: Mapping[str, str] | None = None, http=None, now=time.time):
        self.directory = directory
        self.env: Mapping[str, str] = {} if env is None else env
        self.http = http or self._http
        self.now = now

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ, **kwargs) -> DatadogMinter:
        """Environment only (tests, single-process runs)."""
        return cls(None, env, **kwargs)

    @classmethod
    def from_dir(cls, directory: str, env: Mapping[str, str] = os.environ, **kwargs) -> DatadogMinter:
        """A mounted Secret: one file per key under `directory`, the environment behind it."""
        return cls(directory, env, **kwargs)

    def _read(self, key: str) -> str:
        """The file named `key` in the directory (a Secret key mounted by Kubernetes, trailing
        newline and all), else the environment variable of the same name, else empty."""
        value = ""
        if self.directory:
            try:
                with open(os.path.join(self.directory, key)) as fh:
                    value = fh.read()
            except OSError:  # no directory, or no such file: fall back
                value = ""
        return (value or self.env.get(key, "") or "").strip()

    def config(self) -> DatadogConfig:
        """Resolved per call so a connect, a rotation or a disconnect takes effect without a
        restart. Nothing configured is NotConfigured (the room's probe treats it as waiting);
        a service account id without both keys is a plain refusal, never a boot failure."""
        sa, api, mgmt, site = (self._read(k) for k in (DD_SERVICE_ACCOUNT_ID_ENV, DD_API_KEY_ENV,
                                                       DD_MGMT_APP_KEY_ENV, DD_SITE_ENV))
        if not sa:
            raise NotConfigured(DD_NOT_CONFIGURED)
        missing = [k for k, v in ((DD_API_KEY_ENV, api), (DD_MGMT_APP_KEY_ENV, mgmt)) if not v]
        if missing:
            raise MintError(f"Datadog is half configured on the permission service: {DD_SERVICE_ACCOUNT_ID_ENV} "
                            f"is set but {' and '.join(missing)} missing")
        return DatadogConfig(sa, site or DD_DEFAULT_SITE, api, mgmt)

    @staticmethod
    def _http(method: str, url: str, headers: dict, body: dict | None) -> tuple[int, dict]:
        try:
            resp = httpx.request(method, url, headers=headers, json=body, timeout=10.0)
        except httpx.HTTPError as exc:
            raise MintError(f"Datadog did not answer: {exc.__class__.__name__}") from exc
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = {}
        return resp.status_code, data if isinstance(data, dict) else {}

    def _call(self, cfg: DatadogConfig, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        headers = {"DD-API-KEY": cfg.api_key, "DD-APPLICATION-KEY": cfg.mgmt_app_key, "Accept": "application/json"}
        return self.http(method, f"https://api.{cfg.site}{path}", headers, body)

    @staticmethod
    def _error(status: int, data: dict) -> str:
        """Datadog's own sentence (v1 `errors: [str]` or v2 `errors: [{title, detail}]`), never a key."""
        parts = []
        for e in data.get("errors") or []:
            parts.append(e if isinstance(e, str) else " ".join(str(e.get(k)) for k in ("title", "detail") if e.get(k)))
        return f"HTTP {status}" + (f" {'; '.join(parts)}" if parts else "")

    @staticmethod
    def _keys_path(cfg: DatadogConfig, key_id: str = "") -> str:
        return f"/api/v2/service_accounts/{cfg.service_account_id}/application_keys" + (f"/{key_id}" if key_id else "")

    def _create_key(self, cfg: DatadogConfig, name: str, scopes: list[str]) -> tuple[str, str]:
        body = {"data": {"type": "application_keys", "attributes": {"name": name, "scopes": list(scopes)}}}
        status, data = self._call(cfg, "POST", self._keys_path(cfg), body)
        if status not in (200, 201):
            raise MintError(f"Datadog refused creating an application key: {self._error(status, data)}")
        d = data.get("data") or {}
        key_id, key = str(d.get("id") or ""), str((d.get("attributes") or {}).get("key") or "")
        if not (key_id and key):
            raise MintError("Datadog answered without the application key")
        return key_id, key

    def _delete_key(self, cfg: DatadogConfig, key_id: str) -> None:
        status, data = self._call(cfg, "DELETE", self._keys_path(cfg, key_id))
        if status not in (200, 204, 404):  # 404: already gone, which is what we wanted
            raise MintError(f"Datadog refused deleting application key {key_id}: {self._error(status, data)}")

    def mint(self, agent, integration_id, spec, permissions, seconds):
        cfg = self.config()
        scopes = dd_scopes(permissions)
        if not scopes:  # an unscoped key would be everything the service account may do
            raise MintError("none of the granted permissions names a Datadog scope; nothing to mint")
        now = self.now()
        name = _DD_KEY_NAME_BAD.sub("-", f"bab-{agent}-{time.strftime('%Y%m%d%H%M', time.gmtime(now))}")
        key_id, key = self._create_key(cfg, name, scopes)
        return Minted(credential={"dd_api_key": cfg.api_key, "dd_app_key": key, "dd_site": cfg.site},
                      expires_at=now + max(1, min(int(seconds), DD_MAX_SECONDS)), handle={"key_id": key_id},
                      note="application key scoped to the granted permissions")

    def end(self, handle):
        key_id = str((handle or {}).get("key_id") or "")
        if key_id:
            self._delete_key(self.config(), key_id)

    def identity(self, audience: str | None = None) -> dict:
        """Who bab is to Datadog: the service account whose keys it mints."""
        cfg = self.config()
        return {"subject": cfg.service_account_id, "site": cfg.site, "kind": "datadog_service_account"}

    def probe(self, role_arn: str = "", audience: str | None = None, hub_role_arn: str | None = None,
              external_id: str | None = None) -> dict:
        """Create and delete a key named `bab-probe`: can the management key mint on the service
        account? The AWS-shaped first argument, when given, is the service account id a console
        was handed, and it must be the one bab is configured for; the rest is ignored."""
        cfg = self.config()
        if role_arn and role_arn.strip() != cfg.service_account_id:
            raise MintError(f"bab mints for Datadog service account {cfg.service_account_id}, not {role_arn.strip()}")
        key_id, _ = self._create_key(cfg, "bab-probe", list(DD_PROBE_SCOPES))
        self._delete_key(cfg, key_id)
        return {"subject": cfg.service_account_id, "site": cfg.site, "probe_key_id": key_id}


def default_minters() -> dict[str, Minter]:
    """Datadog is always registered; whether it can mint is decided per call from the mounted
    Secret (`BAB_DATADOG_DIR`, default /etc/bab/datadog) or, failing that, the environment."""
    return {"aws": AwsMinter(),
            "datadog": DatadogMinter.from_dir(os.environ.get(DD_DIR_ENV, "").strip() or DD_DEFAULT_DIR)}
