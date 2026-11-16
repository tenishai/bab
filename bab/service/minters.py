"""Minters: one per credential family. Each turns a granted permission set into a
short-lived vendor credential, scoped as far as the vendor allows, and can end
one early where the vendor allows that too.

bab is the only principal the vendor trusts; agents never hold anything standing.
Where a vendor's own key does not expire (Datadog), bab may keep one per agent and
hand it out lease after lease: the lease is still the hour, and the key goes when
what the agent may do changes (see DatadogMinter.mint_standing).
"""

from __future__ import annotations

import base64
import calendar
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from bab.catalogue import Action
from bab.service import models as discovery
from bab.service.keys import NAME_OK, KeyStore, KeyStoreError, sero_keys_from_env

log = logging.getLogger(__name__)


class MintError(RuntimeError):
    """The vendor refused, or the integration is not set up for minting."""


class NotConfigured(MintError):
    """bab holds nothing for this vendor yet; connecting it is what is missing, not a retry."""


class NameTaken(MintError):
    """The vendor already has a credential under the name asked for."""


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
    """A minter may also offer `mint_standing` (the same arguments as `mint`: a lease on
    everything the agent holds, which may hand out a key kept across leases) and
    `drop(agent, integration_id)` (what the agent may do there changed or ended: a kept
    key goes). The service calls them when they are there."""

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
_AWS_REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
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

    def __init__(self, token_source=web_identity_token, assume=None, assume_role=None, list_org_accounts=None,
                 list_bedrock=None):
        self.token_source = token_source
        self.assume = assume or self._assume
        self.assume_role = assume_role or self._assume_role
        self.list_org_accounts = list_org_accounts or self._list_org_accounts
        self.list_bedrock = list_bedrock or self._list_bedrock

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

    @staticmethod
    def _list_bedrock(creds: dict, region: str) -> tuple[list[dict], list[dict]]:
        """Bedrock's foundation models and system inference profiles in a region, as the
        session sees them (`ListFoundationModels`, `ListInferenceProfiles`), raw."""
        try:
            import botocore.session
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:  # pragma: no cover
            raise MintError("botocore is not installed; install bab with the [aws] extra") from exc
        bedrock = botocore.session.get_session().create_client(
            "bedrock", region_name=region, aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        profiles: list[dict] = []
        token = None
        try:
            models = list(bedrock.list_foundation_models().get("modelSummaries") or [])
            while True:
                kwargs = {"typeEquals": "SYSTEM_DEFINED", "maxResults": 1000}
                if token:
                    kwargs["nextToken"] = token
                page = bedrock.list_inference_profiles(**kwargs)
                profiles += list(page.get("inferenceProfileSummaries") or [])
                token = page.get("nextToken")
                if not token:
                    return models, profiles
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise MintError(f"AWS refused listing Bedrock models in {region}: {err.get('Code', 'error')} "
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

    def list_models(self, region: str = "us-east-1", role_arn: str | None = None, spoke_role_arn: str | None = None,
                    hub_role_arn: str | None = None, external_id: str | None = None,
                    audience: str = DEFAULT_AUDIENCE) -> list[dict]:
        """Bedrock's chat text models in `region`, as the connection's role sees them: the
        role is assumed briefly with no policy, the way a probe assumes it (through the hub
        for an account under an organization), then `ListFoundationModels` and
        `ListInferenceProfiles` are read and cut down by `discovery.bedrock_models`."""
        region = str(region or "").strip()
        if not _AWS_REGION.match(region):
            raise MintError(f"{region!r} is not an AWS region")
        hub, spoke = str(hub_role_arn or "").strip(), str(spoke_role_arn or "").strip()
        if hub and spoke:
            if not _ROLE_ARN.match(spoke):
                raise MintError(f"{spoke!r} is not an IAM role ARN")
            resp = self.assume_role(self._hub(hub, audience, "models"), spoke, "bab-models", MIN_SECONDS, None,
                                    str(external_id or "") or None)
        else:
            flat = str(role_arn or spoke or "").strip()
            if not _ROLE_ARN.match(flat):
                raise MintError("the connection names no IAM role to list Bedrock models with")
            resp = self.assume(flat, self.token_source(audience), "bab-models", MIN_SECONDS, None)
        models, profiles = self.list_bedrock(resp["Credentials"], region)
        return discovery.bedrock_models(models, profiles, region)


# ---- Datadog: a scoped application key on bab's service account ------------------

DD_SITE_ENV, DD_API_KEY_ENV = "DD_SITE", "DD_API_KEY"
DD_MGMT_APP_KEY_ENV, DD_SERVICE_ACCOUNT_ID_ENV = "DD_MGMT_APP_KEY", "DD_SERVICE_ACCOUNT_ID"
DD_DIR_ENV, DD_DEFAULT_DIR = "BAB_DATADOG_DIR", "/etc/bab/datadog"
DD_DEFAULT_SITE = "datadoghq.com"
DD_NOT_CONFIGURED = "Datadog is not configured on the permission service yet: connect it under Admin > Integrations"
DD_KEYS_DIR_ENV, DD_DEFAULT_KEYS_DIR = "BAB_DATADOG_KEYS_DIR", "/etc/bab/datadog-keys"
DD_MAX_SECONDS = 3600  # Datadog keys do not expire; the lease is what ends, so a lease stays short
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


# Datadog refuses a new application key for a moment after it creates it. Measured on
# 2026-11-16 from the permission service's own pod: five keys of five answered 403 for 0.7
# to 1.8 seconds after the create returned, then 200, and never 403 again. A lease handed
# out inside that moment failed the agent's first call, and the refusal read like a missing
# permission. So a key is read with before it is handed out.
#
# A key can only be read with on a scope it carries, and a read on the wrong scope is
# refused for good, so each row here is a pairing the tool gateway's own Datadog reads have
# proven. Add a row when another is proven; a key that carries none of them is held for the
# usual delay instead.
DD_KEY_READS = (
    ("monitors_read", "/api/v1/monitor?page=0&page_size=1"),
    ("events_read", "/api/v1/events?start={then}&end={now}"),
    ("timeseries_query", "/api/v1/query?from={then}&to={now}&query=avg%3Asystem.cpu.idle%7B%2A%7D"),
)
# The longest a mint waits for its key: three times the slowest one measured, and inside
# the ten seconds the tool gateway gives a lease it has none of.
DD_KEY_WAIT_SECONDS = 6.0
DD_KEY_STEP_SECONDS = 0.2
DD_KEY_SETTLE_SECONDS = 2.5
DD_KEY_NOTE = "application key scoped to the granted permissions"
DD_KEY_LATE_NOTE = DD_KEY_NOTE + "; Datadog had not accepted it yet when it was handed out"
DD_STANDING_NOTE = "the agent's own application key, scoped to the granted permissions and kept until they change"


@dataclass(frozen=True)
class DatadogConfig:
    service_account_id: str
    site: str
    api_key: str = field(repr=False)
    mgmt_app_key: str = field(repr=False)


@dataclass
class _Standing:
    """One agent's kept key on one Datadog connection, in memory and as stored."""

    key_id: str
    key: str = field(repr=False)
    scopes: tuple[str, ...]
    service_account_id: str
    site: str
    agent: str = ""
    integration: str = ""
    proven: bool = True  # False for one read back from the store: Datadog is asked whether it is still there
    dropped: bool = False  # its access changed and Datadog would not delete it then: never handed out again


class DatadogMinter:
    """Datadog has no short-lived tokens, but an application key on a service account can
    carry exactly the permissions a lease needs, is created and deleted by API, and names
    itself in Datadog's audit trail. bab holds one management application key
    (`service_account_write`) to make and delete them with.

    With no key store, a lease is one such key, `bab-<agent>-<minute>`, scoped to the
    granted permissions' scopes and deleted when the lease ends (expiry, revoke, sweep).

    With a key store (`keys`), an agent has one key per connection, `bab-<agent>`, and every
    lease on everything it holds there hands out that same key (`mint_standing`). The lease
    is still an hour and still what the ledger records; the key is deleted, and the next
    one made, only when what the agent may do there changes or ends (`drop`, or a lease
    asked with a different set of scopes). A key an hour made Datadog write to its audit
    trail and to the service account's owner every hour for every agent. The store is what
    lets a restart find the key again; a key the store would not take is kept for its one
    lease, like the keys above.

    A kept key is only made when no other can be standing under its name. The store is asked
    what it has first, and while it holds a key this process cannot read (the mount is
    behind, or missing), or Datadog will not say whether a key read back is still there, a
    lease gets a key of its own. Datadog is the last word: it keeps one key per name, so a
    create it answers 409 means a key named `bab-<agent>` stands that nothing here holds
    (another room on the same service account, or one whose delete never went through), and
    the lease gets a key of its own then too. `kept` and `settle` let the service check
    every kept key against what its agent holds now, which is what retries a delete Datadog
    refused and takes a key whose access ran out while its agent was not asking.

    Its configuration is read on every call, never at boot: the room writes the Secret the
    moment an admin connects Datadog and probes at once, and a disconnect removes it again,
    so a value cached at boot would be absent first and stale afterwards."""

    name = "datadog"

    def __init__(self, directory: str | None = None, env: Mapping[str, str] | None = None, http=None, now=time.time,
                 sleep=time.sleep, clock=time.monotonic, keys: KeyStore | None = None):
        self.directory = directory
        self.env: Mapping[str, str] = {} if env is None else env
        self.http = http or self._http
        self.now = now
        self.sleep = sleep  # the wait for a new key, between reads
        self.clock = clock
        self.keys = keys  # where a kept key lives between restarts; None: every lease has a key of its own
        self._standing: dict[str, _Standing] = {}  # by `<integration>.<agent>`
        self._gone: set[str] = set()  # key ids this process saw deleted: a store record still naming one is stale
        # One lock per name, held across Datadog and the store: a slow answer holds up that
        # agent's key and nobody else's lease.
        self._locks: dict[str, threading.RLock] = {}
        self._mu = threading.Lock()
        self._told: set[str] = set()  # what was already said once in the log

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
        except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
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
    def _keys_path(cfg: DatadogConfig, key_id: str = "", service_account_id: str = "") -> str:
        account = service_account_id or cfg.service_account_id
        return f"/api/v2/service_accounts/{account}/application_keys" + (f"/{key_id}" if key_id else "")

    def _create_key(self, cfg: DatadogConfig, name: str, scopes: list[str]) -> tuple[str, str]:
        body = {"data": {"type": "application_keys", "attributes": {"name": name, "scopes": list(scopes)}}}
        status, data = self._call(cfg, "POST", self._keys_path(cfg), body)
        if status == 409:  # Datadog keeps one application key per name
            raise NameTaken(f"Datadog refused creating an application key: {self._error(status, data)}")
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

    @staticmethod
    def _credential(cfg: DatadogConfig, key: str) -> dict:
        return {"dd_api_key": cfg.api_key, "dd_app_key": key, "dd_site": cfg.site}

    def mint(self, agent, integration_id, spec, permissions, seconds):
        cfg = self.config()
        scopes = dd_scopes(permissions)
        if not scopes:  # an unscoped key would be everything the service account may do
            raise MintError("none of the granted permissions names a Datadog scope; nothing to mint")
        now = self.now()
        name = _DD_KEY_NAME_BAD.sub("-", f"bab-{agent}-{time.strftime('%Y%m%d%H%M', time.gmtime(now))}")
        try:
            key_id, key = self._create_key(cfg, name, scopes)
        except NameTaken:  # a second key for this agent within the minute
            name = f"{name}-{secrets.token_hex(2)}"
            key_id, key = self._create_key(cfg, name, scopes)
        accepted = self._await_key(cfg, name, key, scopes)
        return Minted(credential=self._credential(cfg, key),
                      expires_at=now + max(1, min(int(seconds), DD_MAX_SECONDS)), handle={"key_id": key_id},
                      note=DD_KEY_NOTE if accepted else DD_KEY_LATE_NOTE)

    # ---- the kept key: one per agent per connection, for as long as its access stands ----

    @staticmethod
    def _standing_name(agent: str, integration_id: str) -> str | None:
        """`<integration>.<agent>`, or None for a pair the store cannot name. An agent with a
        dot in its name has no kept key: the name must split one way, and `datadog.eu` with
        `fred` would be `datadog` with `eu.fred`."""
        name = f"{integration_id}.{agent}"
        return name if "." not in agent and NAME_OK.match(name) else None

    def _lock_for(self, name: str) -> threading.RLock:
        with self._mu:
            return self._locks.setdefault(name, threading.RLock())

    def _once(self, what: str, message: str, *args) -> None:
        """A warning that would otherwise repeat with every lease or every check."""
        if what not in self._told:
            self._told.add(what)
            log.warning(message, *args)

    @staticmethod
    def _parse(name: str, record: dict | None) -> _Standing | None:
        """One of the store's records as a kept key not yet checked with Datadog, or None for
        one that is not a key."""
        if not record:
            return None
        key_id, key, scopes = str(record.get("key_id") or ""), str(record.get("key") or ""), record.get("scopes")
        if not (key_id and key) or not isinstance(scopes, list):
            return None
        integration, _, agent = name.rpartition(".")
        return _Standing(key_id, key, tuple(str(s) for s in scopes), str(record.get("service_account_id") or ""),
                         str(record.get("site") or ""), agent=str(record.get("agent") or agent),
                         integration=str(record.get("integration") or integration), proven=False)

    def _adopt(self) -> None:
        """Take up every key the store holds and memory does not. A record whose key this
        process saw deleted is the store catching up, and is left."""
        for name, record in self.keys.all().items():
            with self._lock_for(name):
                read = None if name in self._standing else self._parse(name, record)
                if read is not None and read.key_id not in self._gone:
                    self._standing[name] = read

    def _exists(self, cfg: DatadogConfig, key_id: str) -> bool | None:
        """Whether Datadog still has this key, asked with the management key so the answer
        does not depend on the key's own scopes. None when Datadog did not say."""
        try:
            status, _ = self._call(cfg, "GET", self._keys_path(cfg, key_id))
        except MintError:
            return None
        return True if status == 200 else False if status == 404 else None

    def _leave(self, cfg: DatadogConfig, name: str, held: _Standing) -> None:
        """The connection names another service account or site than the one this key was made
        on. It is deleted where it was made when this connection's management key can still
        reach it, and named in the log for a person when it cannot: nothing here will hold its
        id again."""
        try:
            if held.site != cfg.site:
                raise MintError(f"it is on {held.site or 'another site'}")
            status, data = self._call(cfg, "DELETE", self._keys_path(cfg, held.key_id, held.service_account_id))
            if status not in (200, 204):
                raise MintError(self._error(status, data))
        except MintError as exc:
            log.warning("datadog key %s of %s, made on service account %s, could not be deleted from here (%s): "
                        "delete it in Datadog if it is still there", held.key_id, name, held.service_account_id, exc)
        self._gone.add(held.key_id)
        self._standing.pop(name, None)

    def _held(self, cfg: DatadogConfig, name: str) -> tuple[_Standing | None, str]:
        """The key kept under `name`, from memory or else the store, and when there is none,
        why: "" the store showed no key, "stale" it showed one that is no longer a key,
        "unsure" Datadog did not say. One made on another service account or site is not this
        connection's. One read back from the store is checked with Datadog first: the store
        lags a delete by a minute or so, and a key Datadog no longer has would fail every call
        made with it."""
        held = self._standing.get(name)
        if held is None:
            read = self._parse(name, self.keys.get(name))
            if read is None:
                return None, ""
            if read.key_id in self._gone:
                return None, "stale"
            held = self._standing[name] = read
        if (held.service_account_id, held.site) != (cfg.service_account_id, cfg.site):
            self._leave(cfg, name, held)
            return None, "stale"
        if not held.proven:
            there = self._exists(cfg, held.key_id)
            if there is None:
                return None, "unsure"
            if there is False:
                self._gone.add(held.key_id)
                self._standing.pop(name, None)
                return None, "stale"
            held.proven = True
        return held, ""

    def _free(self, name: str, why: str) -> bool:
        """Whether to ask Datadog for a kept key under `name` now. Yes when the store's record
        was read and is no longer a key ("stale"): if the store holds a newer one the mount has
        not shown yet, Datadog refuses the name and nothing is overwritten. Otherwise only when
        the store, asked directly, holds nothing under the name: a record there that the mount
        does not show is a key this process cannot read."""
        if why == "stale":
            return True
        if why == "unsure":
            self._once(f"unsure:{name}", "datadog did not say whether the kept key of %s is still there: "
                                         "its leases get a key of their own until it does", name)
            return False
        try:
            stored = name in self.keys.names()
        except Exception as exc:  # noqa: BLE001 - whatever the store raised, it did not answer
            self._once(f"names:{name}", "the store did not say whether it holds a datadog key for %s (%s): "
                                        "its leases get a key of their own until it does", name,
                       exc if isinstance(exc, KeyStoreError) else exc.__class__.__name__)
            return False
        if stored:
            self._once(f"unseen:{name}", "the store holds a datadog key for %s that this process cannot read yet: "
                                         "its leases get a key of their own until the mounted Secret shows it", name)
            self._redeliver()
        return not stored

    def _redeliver(self) -> None:
        """The mount does not show what the store holds. A delivery that was refused is asked
        for again only with a write, and a process that cannot read a kept key never writes
        one: so ask here. The store paces it."""
        try:
            self.keys.redeliver()
        except Exception as exc:  # noqa: BLE001 - asked again with the next lease
            log.warning("%s", exc if isinstance(exc, KeyStoreError) else exc.__class__.__name__)

    def _forget(self, name: str, key_id: str) -> None:
        """A kept key Datadog has deleted: out of memory, and out of the store when it answers."""
        self._gone.add(key_id)
        self._standing.pop(name, None)
        try:
            self.keys.remove(name)
        except Exception as exc:  # noqa: BLE001 - the record names a key that is gone; `_held` settles that
            log.warning("%s", exc if isinstance(exc, KeyStoreError) else exc.__class__.__name__)

    def mint_standing(self, agent, integration_id, spec, permissions, seconds):
        """A lease on everything the agent holds on this connection: its kept key when the
        scopes are the ones that key carries, else a new key after the old one is deleted.
        With no store, a name the store cannot hold, or a kept key that may be standing
        unseen (`_free`, or Datadog refusing the name), this is `mint`."""
        name = self._standing_name(agent, integration_id)
        if self.keys is None or name is None:
            return self.mint(agent, integration_id, spec, permissions, seconds)
        cfg = self.config()
        scopes = dd_scopes(permissions)
        if not scopes:
            raise MintError("none of the granted permissions names a Datadog scope; nothing to mint")
        now = self.now()
        expires_at = now + max(1, min(int(seconds), DD_MAX_SECONDS))
        with self._lock_for(name):
            held, why = self._held(cfg, name)
            if held is not None and not held.dropped and held.scopes == tuple(scopes):
                return Minted(credential=self._credential(cfg, held.key), expires_at=expires_at,
                              handle={"key_id": held.key_id}, note=DD_STANDING_NOTE)
            if held is not None or self._free(name, why):
                if held is not None:
                    # What the agent may do changed. The key that carried the old set goes before
                    # the new one is made, so a refused delete fails this lease and is tried again
                    # with the next, never left behind a key that replaced it.
                    held.dropped = True
                    self._delete_key(cfg, held.key_id)
                    self._gone.add(held.key_id)
                    self._standing.pop(name, None)
                key_name = _DD_KEY_NAME_BAD.sub("-", f"bab-{agent}")
                try:
                    key_id, key = self._create_key(cfg, key_name, scopes)
                except NameTaken:
                    key_id = key = ""
                    self._once(f"taken:{name}", "datadog already has a key named %s on service account %s that this "
                                                "process does not hold (a kept key the mounted Secret does not show yet, "
                                                "or one bab did not make): the agent's leases get a key of their own "
                                                "until it can read it or it is gone", key_name, cfg.service_account_id)
                if key_id:
                    return self._keep(cfg, name, agent, integration_id, key_name, key_id, key, scopes, now, expires_at)
        return self.mint(agent, integration_id, spec, permissions, seconds)

    def _keep(self, cfg, name, agent, integration_id, key_name, key_id, key, scopes, now, expires_at) -> Minted:
        """Store a key just made and hold it until Datadog accepts it. Under the name's lock: a
        second lease for the same agent must not take the key up before then."""
        try:
            self.keys.put(name, {"agent": agent, "integration": integration_id, "key_id": key_id, "key": key,
                                 "scopes": list(scopes), "service_account_id": cfg.service_account_id,
                                 "site": cfg.site, "created_at": int(now)})
        except Exception as exc:  # noqa: BLE001 - whatever the store raised, the key exists and has to end
            # Not kept: this lease's `end` deletes it, and the next lease tries the store again.
            log.warning("datadog key %s is for one lease only, the store would not take it: %s", key_name,
                        exc if isinstance(exc, KeyStoreError) else exc.__class__.__name__)
        else:
            self._standing[name] = _Standing(key_id, key, tuple(scopes), cfg.service_account_id, cfg.site,
                                             agent=agent, integration=integration_id)
        accepted = self._await_key(cfg, key_name, key, scopes)
        return Minted(credential=self._credential(cfg, key), expires_at=expires_at, handle={"key_id": key_id},
                      note=DD_STANDING_NOTE if accepted else DD_KEY_LATE_NOTE)

    def drop(self, agent: str, integration_id: str) -> None:
        """What `agent` may do on this connection changed or ended: its kept key goes, whether
        or not a lease is live. Never raises. A delete Datadog refuses leaves the key marked,
        so it is not handed out again, and `settle`, the next `end` or the next lease tries
        the delete again."""
        name = self._standing_name(agent, integration_id)
        if self.keys is None or name is None:
            return
        with self._lock_for(name):
            held = self._standing.get(name)
            if held is None:
                held = self._parse(name, self.keys.get(name))
                if held is None:
                    self._unreachable(name)
                    return
                if held.key_id in self._gone:
                    return
                self._standing[name] = held
            held.dropped = True
            try:
                cfg = self.config()
                if (held.service_account_id, held.site) != (cfg.service_account_id, cfg.site):
                    self._leave(cfg, name, held)
                else:
                    self._delete_key(cfg, held.key_id)
            except Exception as exc:  # noqa: BLE001 - never raises; the key stays marked and is tried again
                self._once(f"kept:{held.key_id}", "datadog key %s of %s is still there, and the delete is tried again: %s",
                           held.key_id, name, exc if isinstance(exc, MintError) else exc.__class__.__name__)
                return
            self._forget(name, held.key_id)

    def _unreachable(self, name: str) -> None:
        """`drop` found no record in the mount. When the store holds one, a key is standing in
        Datadog that this process cannot read: said, and the delivery asked for again, so the
        ledger check deletes it once the mount shows it."""
        try:
            stored = name in self.keys.names()
        except Exception:  # noqa: BLE001 - the store did not say; nothing to add
            return
        if stored:
            log.warning("the store holds a datadog key for %s that this process cannot read, so it was not deleted: "
                        "it goes once the mounted Secret shows it", name)
            self._redeliver()

    def kept(self) -> list[tuple[str, str]]:
        """(agent, integration) of every key kept here, what a restart left in the store included."""
        if self.keys is None:
            return []
        self._adopt()
        return sorted({(k.agent, k.integration) for k in list(self._standing.values())})

    def settle(self, agent: str, integration_id: str, permissions: list[Action] | None) -> None:
        """Check one kept key against what its agent holds on the connection now (`permissions`;
        None or empty when it holds nothing there, or the connection is gone). A key whose
        delete was refused, or that carries a scope the agent no longer holds, goes (`drop`).
        One that carries less is left for the agent's next lease to replace. Never raises."""
        name = self._standing_name(agent, integration_id)
        if self.keys is None or name is None:
            return
        with self._lock_for(name):  # the key judged is the key dropped, not one that replaced it
            held = self._standing.get(name)
            if held is not None and (held.dropped or not set(held.scopes) <= set(dd_scopes(permissions or []))):
                self.drop(agent, integration_id)

    def _await_key(self, cfg: DatadogConfig, name: str, key: str, scopes: list[str]) -> bool:
        """Hold a new key until Datadog answers a read made with it (see DD_KEY_READS). True
        when it answered, or when it carries no scope there is a proven read for and was held
        for the usual delay instead. False when Datadog still refused it after
        DD_KEY_WAIT_SECONDS: the key is handed out all the same, as every key was before this,
        because it is real and its lease is about to be recorded, and a late key is likelier
        than a dead one. Never raises, and logs the key's name, never the key."""
        path = next((p for scope, p in DD_KEY_READS if scope in scopes), None)
        if path is None:
            self.sleep(DD_KEY_SETTLE_SECONDS)
            return True
        headers = {"DD-API-KEY": cfg.api_key, "DD-APPLICATION-KEY": key, "Accept": "application/json"}
        started, reads, status = self.clock(), 0, 0
        while True:
            at = int(self.now())
            try:
                status, _ = self.http("GET", f"https://api.{cfg.site}{path.format(then=at - 1, now=at)}", headers, None)
            except MintError:  # Datadog did not answer this read: not a word about the key
                status = 0
            reads += 1
            waited = self.clock() - started
            if status == 200:
                log.info("datadog key %s answered after %.1fs (%d reads)", name, waited, reads)
                return True
            # 429 is Datadog asking for fewer reads, so this stops asking.
            if status == 429 or waited + DD_KEY_STEP_SECONDS > DD_KEY_WAIT_SECONDS:
                log.warning("datadog key %s handed out unanswered: HTTP %d after %.1fs (%d reads)",
                            name, status, waited, reads)
                return False
            self.sleep(DD_KEY_STEP_SECONDS)

    def end(self, handle):
        """A lease ended. A key of its own is deleted. A kept key is not: the lease was the
        hour, and the key stands until the agent's access changes."""
        key_id = str((handle or {}).get("key_id") or "")
        if not key_id:
            return
        if self.keys is None:
            self._delete_key(self.config(), key_id)
            return
        if key_id in self._gone:
            return
        name = self._name_of(key_id)
        if name is None:  # after a restart a kept key is in the store before it is in memory
            self._adopt()
            name = self._name_of(key_id)
        if name is None:  # a key of this lease's own
            self._delete_key(self.config(), key_id)
            self._gone.add(key_id)
            return
        with self._lock_for(name):
            held = self._standing.get(name)
            if key_id in self._gone or (held is not None and held.key_id == key_id and not held.dropped):
                return  # deleted while this waited, or the agent's kept key
            self._delete_key(self.config(), key_id)
            if held is not None and held.key_id == key_id:
                self._forget(name, key_id)
            else:
                self._gone.add(key_id)

    def _name_of(self, key_id: str) -> str | None:
        return next((n for n, k in list(self._standing.items()) if k.key_id == key_id), None)

    def holds(self, handle) -> bool:
        """Whether the key a lease was just given is still one to hand out: not deleted since,
        and not a kept key marked to go. An approval that lands while a lease is made drops the
        key without taking anything away, so the grant check alone would pass it."""
        key_id = str((handle or {}).get("key_id") or "")
        name = self._name_of(key_id) if key_id else None
        if name is None:
            return key_id not in self._gone
        with self._lock_for(name):
            held = self._standing.get(name)
            return key_id not in self._gone and not (held is not None and held.key_id == key_id and held.dropped)

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
# The tree walk under a folder or organization: how deep, how many folders in all, and the page size.
# A folder tree is read with two searches (every project and every folder bab may see), not a
# walk of two calls per folder: a 2026-11-09 walk of a 100-folder tree hit Resource Manager's
# rate limit (429) and held bab's workers until its liveness probe killed it. The answer is
# kept GCP_TREE_TTL_SEC per parent, and one walk at a time runs per parent, so a console that
# asks twice (or retries) does not ask Google twice.
GCP_SEARCH_PAGE_SIZE = 500
GCP_FOLDER_PAGE_SIZE = 300
GCP_TREE_TTL_SEC = 120
GCP_RETRY_PAUSES_SEC = (1.0, 2.0, 4.0)
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
        self.sleep = time.sleep
        self._tree_cache: dict[str, tuple[float, list[dict]]] = {}
        self._tree_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

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

    def list_models(self, project: str, location: str = "global", service_account: str | None = None) -> list[dict]:
        """Vertex AI's chat text models for a project: the publisher models of google and
        anthropic from the global endpoint (the one that lists them; the regional hosts answer
        an empty list), billed to `project` through `x-goog-user-project`, read with the same
        token a probe presents (bab's own, or the connection's service account impersonated),
        and cut down by `discovery.vertex_models`. `location` is checked and kept for the
        console's row; the listing itself has no location."""
        project = str(project or "").strip()
        if not _GCP_PROJECT.match(project):
            raise MintError(f"{project!r} is not a Google Cloud project id")
        location = str(location or "").strip()
        if not _GCP_LOCATION.match(location):
            raise MintError(f"{location!r} is not a Vertex AI location")
        token, _, who = self._token_for(service_account or None, GCP_PROBE_SECONDS)
        headers = {**self._bearer(token), "x-goog-user-project": project}
        listed: list[tuple[str, dict]] = []
        for publisher in discovery.VERTEX_PUBLISHERS:
            page = ""
            while True:
                status, data = self.http("GET", discovery.vertex_publisher_models_url(publisher, page), headers, None)
                if status != 200:
                    if who == GCP_OWN:
                        who = self._email()
                    raise Unreachable(f"{who} cannot list Vertex AI's {publisher} models for project {project}: "
                                      f"{self._error(status, data)}")
                listed += [(publisher, m) for m in (data.get("publisherModels") or []) if isinstance(m, dict)]
                page = str(data.get("nextPageToken") or "")
                if not page:
                    break
        return discovery.vertex_models(listed)

    def list_accounts(self, parent: str) -> list[dict]:
        """The active projects under a folder or organization, the whole tree down, as bab's
        own identity can see them: Resource Manager v3's `projects:search` and `folders:search`
        (what roles/browser lets the caller see), two paged reads for the whole organization
        instead of two calls per folder, then the tree is assembled here. Each project names the
        folders between the parent and itself (`folder_path`, display names, the parent
        excluded) and its number; the list is sorted by that path, then by name. A project whose
        chain of folders bab cannot see is left out: nothing can be granted under it anyway.
        The answer is kept GCP_TREE_TTL_SEC per parent and one read runs per parent at a time."""
        parent = str(parent or "").strip()
        if not _GCP_PARENT.match(parent):
            raise MintError(f"{parent!r} is not a folder or organization (folders/<number> or organizations/<number>)")
        with self._locks_guard:
            lock = self._tree_locks.setdefault(parent, threading.Lock())
        with lock:
            hit = self._tree_cache.get(parent)
            if hit is not None and self.now() < hit[0]:
                return [dict(p, folder_path=list(p["folder_path"])) for p in hit[1]]
            out = self._tree(parent)
            self._tree_cache[parent] = (self.now() + GCP_TREE_TTL_SEC, out)
            return [dict(p, folder_path=list(p["folder_path"])) for p in out]

    def _tree(self, parent: str) -> list[dict]:
        token, _ = self._own_token()
        folders = {str(f["name"]): f for f in self._search(token, "folders", GCP_FOLDER_PAGE_SIZE)
                   if f.get("name") and f.get("state", "ACTIVE") == "ACTIVE"}
        out: list[dict] = []
        for p in self._search(token, "projects", GCP_SEARCH_PAGE_SIZE):
            if p.get("state") != "ACTIVE" or not p.get("projectId"):
                continue
            path = self._path_to(parent, str(p.get("parent") or ""), folders)
            if path is None:
                continue
            out.append({"id": str(p["projectId"]), "name": str(p.get("displayName") or p["projectId"]),
                        "status": "ACTIVE", "project_number": str(p.get("name") or "").rsplit("/", 1)[-1],
                        "folder": str(p.get("parent") or parent), "folder_path": path})
        return sorted(out, key=lambda p: (p["folder_path"], p["name"], p["id"]))

    @staticmethod
    def _path_to(parent: str, node: str, folders: dict[str, dict]) -> list[str] | None:
        """The display names of the folders from just under `parent` down to `node`, or None
        when `node` is not under `parent` (or a folder on the way is not visible)."""
        names: list[str] = []
        seen = 0
        while node != parent:
            f = folders.get(node)
            if f is None or seen > 64:
                return None
            names.append(str(f.get("displayName") or node))
            node = str(f.get("parent") or "")
            seen += 1
        names.reverse()
        return names

    def _search(self, token: str, what: str, page_size: int) -> list[dict]:
        """Every page of Resource Manager v3's `projects:search` or `folders:search`. A 429 or
        a 5xx is retried after GCP_RETRY_PAUSES_SEC, then given up with Google's sentence."""
        rows: list[dict] = []
        page = ""
        while True:
            url = f"{GCP_RESOURCE_MANAGER_URL}/v3/{what}:search?pageSize={page_size}" + (f"&pageToken={page}" if page else "")
            status, data = self._read_with_patience(url, token)
            if status != 200:
                raise MintError(f"Google refused searching the {what}: {self._error(status, data)}")
            rows += [r for r in (data.get(what) or []) if isinstance(r, dict)]
            page = str(data.get("nextPageToken") or "")
            if not page:
                return rows

    def _read_with_patience(self, url: str, token: str) -> tuple[int, dict]:
        pauses = iter(GCP_RETRY_PAUSES_SEC)
        while True:
            status, data = self.http("GET", url, self._bearer(token), None)
            if status != 429 and status < 500:
                return status, data
            pause = next(pauses, None)
            if pause is None:
                return status, data
            self.sleep(pause)


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
    own identity from the metadata server and need nothing mounted. Datadog keeps one key
    per agent when the secret store is named (`BAB_SERO_*`, see bab/service/keys.py), read
    back from `BAB_DATADOG_KEYS_DIR` /etc/bab/datadog-keys after a restart."""
    dd_keys = sero_keys_from_env(os.environ, os.environ.get(DD_KEYS_DIR_ENV, "").strip() or DD_DEFAULT_KEYS_DIR,
                                 web_identity_token)
    return {"aws": AwsMinter(),
            "gcp": GcpMinter(),
            "datadog": DatadogMinter.from_dir(os.environ.get(DD_DIR_ENV, "").strip() or DD_DEFAULT_DIR, keys=dd_keys),
            "github": GitHubMinter.from_dir(os.environ.get(GH_DIR_ENV, "").strip() or GH_DEFAULT_DIR)}
