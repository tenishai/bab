"""Minters: one per credential family. Each turns a granted permission set into a
short-lived vendor credential, scoped as far as the vendor allows, and can end
one early where the vendor allows that too.

bab is the only principal the vendor trusts; agents never hold anything standing.
"""

from __future__ import annotations

import base64
import calendar
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


class Unreachable(MintError):
    """The identity is granted on the connection but a vendor surface it should reach did not answer
    (a probe's second step); the console shows it as the vendor's failure, not the connection's."""


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


def jwt_claims(token: str) -> dict:
    """The claims of an unverified JWT bab was handed by its own metadata server."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise MintError("bab's identity token is not a JWT") from exc


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
        claims = jwt_claims(self.token_source(audience))
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


# ---- github -----------------------------------------------------------------

GH_DIR_ENV = "BAB_GITHUB_DIR"
GH_DEFAULT_DIR = "/etc/bab/github"
GH_APP_ID_ENV = "GITHUB_APP_ID"
GH_INSTALLATION_ID_ENV = "GITHUB_APP_INSTALLATION_ID"
GH_PRIVATE_KEY_ENV = "GITHUB_APP_PRIVATE_KEY"
GH_API_URL_ENV = "GITHUB_API_URL"
GH_DEFAULT_API_URL = "https://api.github.com"
GH_NOT_CONFIGURED = "GitHub is not configured on the permission service yet: connect it under Admin > Integrations"
GH_MAX_SECONDS = 3600  # an installation token lives an hour on GitHub's clock and cannot be shortened
GH_PROBE_PERMISSIONS = {"metadata": "read"}
_GH_RANK = {"read": 1, "write": 2, "admin": 3}


def gh_permissions(permissions: list[Action]) -> dict[str, str]:
    """The union of the granted permissions' `extra.permissions` (GitHub App fine-grained
    permission -> read|write|admin), the stronger access winning per permission: what the
    installation token may do."""
    out: dict[str, str] = {}
    for p in permissions:
        for name, access in (p.extra.get("permissions") or {}).items():
            access = str(access).lower()
            if _GH_RANK.get(access, 0) > _GH_RANK.get(out.get(str(name), ""), 0):
                out[str(name)] = access
    return dict(sorted(out.items()))


@dataclass(frozen=True)
class GitHubConfig:
    app_id: str
    installation_id: str
    api_url: str
    private_key: str = field(repr=False)


class GitHubMinter:
    """A GitHub App installation token is the vendor's own short-lived credential: an hour,
    narrowed at creation to a subset of the app's permissions and, when asked, to named
    repositories, and attributed to the app in GitHub's audit log. A lease is one such token,
    narrowed to the granted permissions' union (and to the integration's `repositories` when
    the connection names some); it ends on GitHub's clock, so bab keeps no handle. bab holds
    the app's id, one installation id and its private key, read on every call from the
    mounted Secret the room writes on connect (never cached at boot, as for Datadog)."""

    name = "github"

    def __init__(self, directory: str | None = None, env: Mapping[str, str] | None = None, http=None, now=time.time):
        self.directory = directory
        self.env: Mapping[str, str] = {} if env is None else env
        self.http = http or self._http
        self.now = now

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ, **kwargs) -> GitHubMinter:
        return cls(None, env, **kwargs)

    @classmethod
    def from_dir(cls, directory: str, env: Mapping[str, str] = os.environ, **kwargs) -> GitHubMinter:
        return cls(directory, env, **kwargs)

    def _read(self, key: str) -> str:
        value = ""
        if self.directory:
            try:
                with open(os.path.join(self.directory, key)) as fh:
                    value = fh.read()
            except OSError:
                value = ""
        return (value or self.env.get(key, "") or "").strip()

    def config(self) -> GitHubConfig:
        app_id, inst, key, api = (self._read(k) for k in (GH_APP_ID_ENV, GH_INSTALLATION_ID_ENV,
                                                          GH_PRIVATE_KEY_ENV, GH_API_URL_ENV))
        if not app_id:
            raise NotConfigured(GH_NOT_CONFIGURED)
        missing = [k for k, v in ((GH_INSTALLATION_ID_ENV, inst), (GH_PRIVATE_KEY_ENV, key)) if not v]
        if missing:
            raise MintError(f"GitHub is half configured on the permission service: {GH_APP_ID_ENV} is set "
                            f"but {' and '.join(missing)} missing")
        # A PEM that travelled through an environment variable carries literal backslash-n.
        key = key.replace("\\n", "\n")
        return GitHubConfig(app_id, inst, (api or GH_DEFAULT_API_URL).rstrip("/"), key)

    @staticmethod
    def _http(method: str, url: str, headers: dict, body: dict | None) -> tuple[int, dict]:
        try:
            resp = httpx.request(method, url, headers=headers, json=body, timeout=10.0)
        except httpx.HTTPError as exc:
            raise MintError(f"GitHub did not answer: {exc.__class__.__name__}") from exc
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = {}
        return resp.status_code, data if isinstance(data, dict) else {}

    def _jwt(self, cfg: GitHubConfig) -> str:
        """The app's own short JWT (RS256, ten minutes): what mints installation tokens."""
        import jwt  # PyJWT[crypto], in the service extra

        now = int(self.now())
        try:
            return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": cfg.app_id}, cfg.private_key, algorithm="RS256")
        except (ValueError, TypeError) as exc:
            raise MintError(f"the GitHub App private key did not sign: {exc.__class__.__name__}") from exc

    def _call(self, cfg: GitHubConfig, method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        return self.http(method, f"{cfg.api_url}{path}", headers, body)

    @staticmethod
    def _error(status: int, data: dict) -> str:
        """GitHub's own sentence (`message`, plus any `errors`), never a token."""
        parts = [str(data["message"])] if data.get("message") else []
        for e in data.get("errors") or []:
            parts.append(e if isinstance(e, str) else str(e.get("message") or e.get("code") or ""))
        return f"HTTP {status}" + (f" {'; '.join(p for p in parts if p)}" if parts else "")

    def _token(self, cfg: GitHubConfig, permissions: dict[str, str], repositories: list[str]) -> tuple[str, float]:
        body: dict[str, Any] = {"permissions": dict(permissions)}
        if repositories:
            body["repositories"] = list(repositories)
        status, data = self._call(cfg, "POST", f"/app/installations/{cfg.installation_id}/access_tokens",
                                  self._jwt(cfg), body)
        if status != 201:
            raise MintError(f"GitHub refused an installation token: {self._error(status, data)}")
        token = str(data.get("token") or "")
        if not token:
            raise MintError("GitHub answered without the token")
        return token, _iso_epoch(str(data.get("expires_at") or ""))

    def mint(self, agent, integration_id, spec, permissions, seconds):
        cfg = self.config()
        perms = gh_permissions(permissions)
        if not perms:  # a token with no permissions named would be the app's whole set
            raise MintError("none of the granted permissions names a GitHub App permission; nothing to mint")
        # GitHub's installation-token API narrows by repository NAME, never
        # `owner/name`: the owner is the installation's. A console that stores
        # the full name (the room's picker does) would get a 422 "repository
        # does not exist" for every lease, so the owner is dropped here.
        repos = [str(r).strip().rsplit("/", 1)[-1] for r in ((spec or {}).get("repositories") or []) if str(r).strip()]
        now = self.now()
        token, github_ends = self._token(cfg, perms, repos)
        ends = now + max(1, min(int(seconds), GH_MAX_SECONDS))
        if github_ends:
            ends = min(ends, github_ends)
        note = "installation token narrowed to the granted permissions"
        if repos:
            note += f" and {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'}"
        return Minted(credential={"github_token": token, "github_api_url": cfg.api_url},
                      expires_at=ends, handle={}, note=note)

    def end(self, handle):
        """Nothing to end: an installation token cannot be revoked without holding it, and bab
        keeps no copy. It dies on GitHub's clock within the hour; the lease's end stops the
        hand-out at once."""
        return

    def identity(self, audience: str | None = None) -> dict:
        """Who bab is to GitHub: the app whose installation it mints from."""
        cfg = self.config()
        status, data = self._call(cfg, "GET", "/app", self._jwt(cfg))
        if status != 200:
            raise MintError(f"GitHub did not recognise the app: {self._error(status, data)}")
        return {"subject": str(data.get("slug") or cfg.app_id), "app_id": cfg.app_id,
                "installation_id": cfg.installation_id, "kind": "github_app"}

    def probe(self, role_arn: str = "", audience: str | None = None, hub_role_arn: str | None = None,
              external_id: str | None = None) -> dict:
        """Can the app mint on its installation? Reads the installation with the app's JWT,
        then mints a metadata-only token and counts the repositories it can see. The
        AWS-shaped first argument, when given, is the installation id a console was handed,
        and it must be the one bab is configured for."""
        cfg = self.config()
        if role_arn and role_arn.strip() != cfg.installation_id:
            raise MintError(f"bab mints for GitHub App installation {cfg.installation_id}, not {role_arn.strip()}")
        status, inst = self._call(cfg, "GET", f"/app/installations/{cfg.installation_id}", self._jwt(cfg))
        if status != 200:
            raise MintError(f"GitHub did not show installation {cfg.installation_id} to the app: {self._error(status, inst)}")
        token, _ = self._token(cfg, dict(GH_PROBE_PERMISSIONS), [])
        status, repos = self._call(cfg, "GET", "/installation/repositories?per_page=1", token)
        if status != 200:
            raise MintError(f"the probe token could not list repositories: {self._error(status, repos)}")
        return {"subject": str(inst.get("app_slug") or cfg.app_id), "installation_id": cfg.installation_id,
                "account": str(((inst.get("account") or {}).get("login")) or ""),
                "repositories": int(repos.get("total_count") or 0)}



# ---- Google Cloud: an access token for bab's own identity, or for a narrower one -------

GCP_METADATA_SA_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default"
GCP_CREDENTIALS_URL = "https://iamcredentials.googleapis.com/v1"
GCP_RESOURCE_MANAGER_URL = "https://cloudresourcemanager.googleapis.com"
GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
GCP_MAX_SECONDS = 3600  # generateAccessToken's ceiling without an org policy change; the lease is an hour anyway
GCP_PROBE_SECONDS = 600
GCP_IDENTITY_AUDIENCE = "bab"  # the identity token is read for its claims, never presented anywhere
GCP_OWN = "bab's own identity"
_GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_GCP_PARENT = re.compile(r"^(folders|organizations)/\d+$")
_GCP_SA = re.compile(r"^[\w.+-]+@[\w.-]+\.gserviceaccount\.com$")
_GCP_LOCATION = re.compile(r"^(global|[a-z]+-[a-z]+\d+)$")


def vertex_models_url(project: str, location: str) -> str:
    """Vertex AI's model list for a project and location: the regional host, or the plain host
    for `global`. The project's own models (an empty list is a fine answer): listing them needs
    the Vertex AI role in that project and proves the API is on there, which is what a model
    call needs. The publisher catalogue is not project-scoped and answers 404 under a project
    (seen live 2026-11-02), so it is not the probe. Built here, never taken from a caller: a
    probe presents a token for bab's identity to this URL, so the host is bab's choice."""
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    return f"https://{host}/v1/projects/{project}/locations/{location}/models?pageSize=1"


class GcpMinter:
    """Google Cloud has no session policy: a token carries whatever roles its identity holds.
    So an admin grants bab's own service account the role pack on the project (or on a folder
    or organization above it), and a lease is an access token for that identity, narrowed by
    bab's verdict before minting rather than by Google during the hour. When a connection names
    a `service_account`, bab impersonates it instead (`generateAccessToken`, which needs
    roles/iam.serviceAccountTokenCreator on that account) and the lease carries that narrower
    identity's roles. bab's own token comes from the metadata server (workload identity), the
    same source as its AWS web identity token; nothing is stored. Cloud Audit Logs record the
    identity, not the agent: the ledger is the attribution."""

    name = "gcp"

    def __init__(self, http=None, now=time.time):
        self.http = http or self._http
        self.now = now

    @staticmethod
    def _http(method: str, url: str, headers: dict, body: dict | None) -> tuple[int, dict]:
        try:
            resp = httpx.request(method, url, headers=headers, json=body, timeout=10.0)
        except httpx.HTTPError as exc:
            raise MintError(f"Google did not answer: {exc.__class__.__name__}") from exc
        try:
            data = resp.json() if resp.content else {}
        except ValueError:  # the metadata server's identity endpoint answers a bare JWT
            data = {"text": resp.text}
        return resp.status_code, data if isinstance(data, dict) else {}

    @staticmethod
    def _error(status: int, data: dict) -> str:
        """Google's own sentence (`error.message`), never a token."""
        err = data.get("error") or {}
        msg = str(err.get("message") or "") if isinstance(err, dict) else str(err)
        return f"HTTP {status}" + (f" {msg}" if msg else "")

    @staticmethod
    def _bearer(token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _metadata(self, path: str) -> tuple[int, dict]:
        return self.http("GET", f"{GCP_METADATA_SA_URL}{path}", {"Metadata-Flavor": "Google"}, None)

    def _own_token(self) -> tuple[str, float]:
        """bab's own access token from the metadata server, and when Google ends it."""
        status, data = self._metadata("/token")
        token = str(data.get("access_token") or "")
        if status != 200 or not token:
            raise MintError("no access token: the metadata server did not hand one to bab's service account")
        return token, self.now() + float(data.get("expires_in") or GCP_MAX_SECONDS)

    def _email(self) -> str:
        """bab's own service account email, from the metadata server."""
        status, data = self._metadata("/?recursive=true")
        if status != 200 or not data.get("email"):
            raise MintError("the metadata server did not name bab's service account")
        return str(data["email"])

    def _impersonate(self, bearer: str, service_account: str, seconds: int) -> tuple[str, float]:
        """`generateAccessToken` on the connection's service account, with bab's own token."""
        if not _GCP_SA.match(service_account):
            raise MintError(f"{service_account!r} is not a service account email")
        url = f"{GCP_CREDENTIALS_URL}/projects/-/serviceAccounts/{service_account}:generateAccessToken"
        status, data = self.http("POST", url, self._bearer(bearer), {"scope": [GCP_SCOPE], "lifetime": f"{seconds}s"})
        if status != 200:
            raise MintError(f"Google refused a token for {service_account}: {self._error(status, data)}")
        token = str(data.get("accessToken") or "")
        if not token:
            raise MintError("Google answered without the token")
        return token, _iso_epoch(str(data.get("expireTime") or "")) or self.now() + seconds

    def _token_for(self, service_account: str | None, seconds: int) -> tuple[str, float, str]:
        """A token for the connection's identity: the service account it names, impersonated with
        bab's own token, or bab's own token itself, which ends when the metadata server says."""
        seconds = max(1, min(int(seconds), GCP_MAX_SECONDS))
        own, own_ends = self._own_token()
        if service_account:
            token, ends = self._impersonate(own, service_account, seconds)
            return token, min(ends, self.now() + seconds), service_account
        return own, min(own_ends, self.now() + seconds), GCP_OWN

    def mint(self, agent, integration_id, spec, permissions, seconds):
        project = str((spec or {}).get("project") or "").strip()
        if not project:
            raise MintError(f"integration {integration_id!r} names no Google Cloud project")
        sa = str((spec or {}).get("service_account") or "").strip() or None
        token, ends, who = self._token_for(sa, seconds)
        return Minted(credential={"gcp_access_token": token, "gcp_project": project}, expires_at=ends, handle={},
                      note=f"access token for {who}; narrowing is bab's check only, the token carries the role pack")

    def end(self, handle):
        """Nothing to end: Google cannot recall an access token before it expires, and bab keeps
        no copy. The lease length is the revocation; the lease's end stops the hand-out at once."""
        return

    def identity(self, audience: str | None = None) -> dict:
        """Who bab is to Google Cloud: its own service account, the principal an admin grants the
        role pack to. Email and unique id (`sub`, which survives a delete-and-recreate of the
        email) come from the metadata server's identity token, as for AWS."""
        status, data = self._metadata(f"/identity?audience={audience or GCP_IDENTITY_AUDIENCE}&format=full")
        token = str(data.get("text") or "")
        if status != 200 or not token:
            raise MintError("no identity token: bab's service account has no Google identity linked")
        claims = jwt_claims(token)
        return {"subject": str(claims.get("sub", "")), "email": claims.get("email"), "kind": "google_service_account"}

    def probe(self, project: str | None = None, service_account: str | None = None, parent: str | None = None,
              vertex_location: str | None = None) -> dict:
        """Mint once and read the project: is bab's identity (or the service account it would
        impersonate) granted anything there? With `parent` and no project: can bab list the
        folder's or organization's projects? Google answers 403 for a project that does not
        exist too, so the sentence covers both. With `vertex_location`, the same token then lists
        Vertex AI's publisher models there (a project that serves models): `vertex.ok` in the
        answer, or Unreachable naming the location."""
        if parent and not project:
            projects = self.list_accounts(parent)
            return {"parent": parent, "projects": len(projects), "subject": self._email(), "hops": 1}
        project = str(project or "").strip()
        if not project:
            raise MintError("a Google Cloud probe names a project, or a folder or organization")
        if not _GCP_PROJECT.match(project):
            raise MintError(f"{project!r} is not a Google Cloud project id")
        token, _, who = self._token_for(service_account or None, GCP_PROBE_SECONDS)
        if who == GCP_OWN:
            who = self._email()
        status, data = self.http("GET", f"{GCP_RESOURCE_MANAGER_URL}/v1/projects/{project}", self._bearer(token), None)
        if status in (403, 404):
            raise MintError(f"{who} has no access on project {project} (or there is no such project): grant it "
                            "the role pack there, or on a folder or organization above it")
        if status != 200:
            raise MintError(f"Google did not show project {project}: {self._error(status, data)}")
        out = {"project": str(data.get("projectId") or project), "project_number": str(data.get("projectNumber") or ""),
               "subject": who, "hops": 2 if service_account else 1}
        if vertex_location:
            location = str(vertex_location).strip()
            if not _GCP_LOCATION.match(location):
                raise MintError(f"{location!r} is not a Vertex AI location")
            status, data = self.http("GET", vertex_models_url(out["project"], location), self._bearer(token), None)
            if status != 200:
                raise Unreachable(f"{who} cannot reach Vertex AI in {location} for project {out['project']}: "
                                  f"{self._error(status, data)}")
            out["vertex"] = {"location": location, "ok": True}
        return out

    def list_accounts(self, parent: str) -> list[dict]:
        """The active projects directly under a folder or organization, as bab's own identity
        can see them (`resourcemanager.projects.list` on the parent). Projects inside a
        sub-folder are not listed; connect that folder."""
        parent = str(parent or "").strip()
        if not _GCP_PARENT.match(parent):
            raise MintError(f"{parent!r} is not a folder or organization (folders/<number> or organizations/<number>)")
        token, _ = self._own_token()
        out: list[dict] = []
        page = ""
        while True:
            url = f"{GCP_RESOURCE_MANAGER_URL}/v3/projects?parent={parent}&pageSize=500" + (f"&pageToken={page}" if page else "")
            status, data = self.http("GET", url, self._bearer(token), None)
            if status != 200:
                raise MintError(f"Google refused listing the projects under {parent}: {self._error(status, data)}")
            out += [{"id": str(p.get("projectId") or ""), "name": str(p.get("displayName") or p.get("projectId") or ""),
                     "status": str(p.get("state") or "")}
                    for p in (data.get("projects") or []) if p.get("state") == "ACTIVE" and p.get("projectId")]
            page = str(data.get("nextPageToken") or "")
            if not page:
                return sorted(out, key=lambda p: (p["name"], p["id"]))


def _iso_epoch(iso: str) -> float:
    """An RFC 3339 instant (`2026-10-31T17:00:00Z`, Google's `...00.123456Z` too) as an epoch,
    0 when absent or odd."""
    if not iso:
        return 0.0
    try:
        return float(calendar.timegm(time.strptime(re.sub(r"\.\d+Z$", "Z", iso), "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError:
        return 0.0


def default_minters() -> dict[str, Minter]:
    """Datadog and GitHub are always registered; whether each can mint is decided per call
    from its mounted Secret (`BAB_DATADOG_DIR` /etc/bab/datadog, `BAB_GITHUB_DIR`
    /etc/bab/github) or, failing that, the environment. AWS and Google Cloud mint with bab's
    own identity from the metadata server and need nothing mounted."""
    return {"aws": AwsMinter(),
            "gcp": GcpMinter(),
            "datadog": DatadogMinter.from_dir(os.environ.get(DD_DIR_ENV, "").strip() or DD_DEFAULT_DIR),
            "github": GitHubMinter.from_dir(os.environ.get(GH_DIR_ENV, "").strip() or GH_DEFAULT_DIR)}
