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
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from bab.catalogue import Action

log = logging.getLogger(__name__)


class MintError(RuntimeError):
    """The vendor refused, or the integration is not set up for minting."""


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

    def mint(self, agent, integration_id, spec, permissions, seconds):
        token = base64.urlsafe_b64encode(json.dumps({
            "agent": agent, "integration": integration_id, "permissions": [p.name for p in permissions],
        }).encode()).decode()
        return Minted({"token": token}, self.now() + seconds, {"token": token}, "a test credential")

    def end(self, handle):
        self.ended.append(handle)

    def identity(self, audience: str = "sts.amazonaws.com") -> dict:
        return {"subject": "static-minter", "email": None, "audience": audience}

    def probe(self, role_arn: str, audience: str = "sts.amazonaws.com") -> dict:
        if "refuse" in role_arn:
            raise MintError(f"AWS refused {role_arn}: AccessDenied")
        return {"account": role_arn.split(":")[4], "assumed_arn": role_arn.replace(":role/", ":assumed-role/") + "/bab-probe"}


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
    name = "aws"

    def __init__(self, token_source=web_identity_token, assume=None):
        self.token_source = token_source
        self.assume = assume or self._assume

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

    def mint(self, agent, integration_id, spec, permissions, seconds):
        role_arn = str(spec.get("role_arn", "")).strip()
        if not _ROLE_ARN.match(role_arn):
            raise MintError(f"integration {integration_id!r} has no IAM role ARN to assume")
        audience = str(spec.get("audience") or DEFAULT_AUDIENCE)
        seconds = max(MIN_SECONDS, min(MAX_SECONDS, seconds))
        policy = session_policy(permissions)
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

    def probe(self, role_arn: str, audience: str = DEFAULT_AUDIENCE) -> dict:
        """Assume the role once, briefly, with no policy: does its trust admit bab?"""
        if not _ROLE_ARN.match(role_arn):
            raise MintError(f"{role_arn!r} is not an IAM role ARN")
        token = self.token_source(audience)
        resp = self.assume(role_arn, token, "bab-probe", MIN_SECONDS, None)
        arn = resp["AssumedRoleUser"]["Arn"]
        return {"account": arn.split(":")[4], "assumed_arn": arn}


def default_minters() -> dict[str, Minter]:
    return {"aws": AwsMinter()}
