"""Who is calling: an agent by its pod's service account token, or the console.

An agent proves itself with the Kubernetes service account token its pod
already carries, projected with audience `bab`. Two verifiers exist: the
TokenReview API when bab runs in the same cluster, and OIDC discovery + JWKS
when it does not. Either way the agent's name is the service account's name.

The console (kobo) calls with a shared token and names the signed-in person.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

SA_PREFIX = "system:serviceaccount:"


class IdentityError(PermissionError):
    """The caller could not be verified."""


@dataclass(frozen=True)
class Caller:
    kind: str  # "agent" | "console"
    name: str  # agent name, or the console's name
    actor: str | None = None  # the signed-in person, for console calls
    namespace: str | None = None


def agent_from_username(username: str) -> tuple[str, str]:
    """`system:serviceaccount:<ns>:<sa>` -> (agent, namespace). The agent is the service account."""
    if not username.startswith(SA_PREFIX):
        raise IdentityError("the token is not a Kubernetes service account token")
    ns, _, sa = username[len(SA_PREFIX):].partition(":")
    if not ns or not sa:
        raise IdentityError("the service account username is malformed")
    return sa, ns


class TokenReviewVerifier:
    """Ask the cluster: POST authentication.k8s.io/v1 TokenReview with our audience."""

    def __init__(self, api_url: str, bearer: str, audience: str = "bab", ca_path: str | None = None,
                 client: httpx.Client | None = None):
        self.api_url = api_url.rstrip("/")
        self.audience = audience
        self.client = client or httpx.Client(timeout=5.0, verify=ca_path or True,
                                             headers={"Authorization": f"Bearer {bearer}"})

    def verify(self, token: str) -> Caller:
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                "spec": {"token": token, "audiences": [self.audience]}}
        try:
            resp = self.client.post(f"{self.api_url}/apis/authentication.k8s.io/v1/tokenreviews", json=body)
        except httpx.HTTPError as exc:
            raise IdentityError(f"token review unreachable: {exc}") from exc
        if resp.status_code != 201:
            raise IdentityError(f"token review answered {resp.status_code}")
        status = resp.json().get("status") or {}
        if not status.get("authenticated"):
            raise IdentityError(f"token not accepted: {status.get('error', 'unauthenticated')}")
        if self.audience not in (status.get("audiences") or [self.audience]):
            raise IdentityError("token was not issued for bab")
        agent, ns = agent_from_username(str(status.get("user", {}).get("username", "")))
        return Caller("agent", agent, namespace=ns)


class JwksVerifier:
    """Verify the projected token against the cluster issuer's JWKS (bab outside the cluster)."""

    def __init__(self, issuer: str, audience: str = "bab", jwks_uri: str | None = None):
        import jwt

        self.issuer = issuer.rstrip("/")
        self.audience = audience
        if jwks_uri is None:
            conf = httpx.get(f"{self.issuer}/.well-known/openid-configuration", timeout=5.0)
            conf.raise_for_status()
            jwks_uri = conf.json()["jwks_uri"]
        self._jwks = jwt.PyJWKClient(jwks_uri)

    def verify(self, token: str) -> Caller:
        import jwt

        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256", "ES256"], audience=self.audience,
                                issuer=self.issuer)
        except jwt.PyJWTError as exc:
            raise IdentityError(f"token rejected: {exc}") from exc
        agent, ns = agent_from_username(str(claims.get("sub", "")))
        return Caller("agent", agent, namespace=ns)


class StaticVerifier:
    """Tests and local runs: a table of token -> agent."""

    def __init__(self, agents: dict[str, str]):
        self.agents = dict(agents)

    def verify(self, token: str) -> Caller:
        try:
            return Caller("agent", self.agents[token], namespace=self.agents[token])
        except KeyError as exc:
            raise IdentityError("unknown token") from exc


class ConsoleAuth:
    """The console's shared token, plus the signed-in person it is acting for."""

    def __init__(self, token: str, name: str = "console"):
        if not token:
            raise ValueError("the console token must not be empty")
        self.token = token
        self.name = name

    def verify(self, token: str, actor: str) -> Caller:
        import hmac

        if not hmac.compare_digest(token, self.token):
            raise IdentityError("console token rejected")
        actor = actor.strip().lower()
        if not actor or "@" not in actor:
            raise IdentityError("the console must say who is acting (X-Bab-Actor: an email)")
        return Caller("console", self.name, actor=actor)
