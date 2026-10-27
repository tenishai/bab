"""Store protocol + the OpenFGA adapter. Everything above this talks to `Store`.

A tuple may carry an expiry. In the store that is OpenFGA's `grant_window`
condition with `expires_at` in the tuple's context; a check passes
`current_time` in its context and the tuple stops answering yes at that instant.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger(__name__)

CONDITION = "grant_window"  # the one condition the generated model defines


@dataclass(frozen=True)
class Tuple:
    user: str
    relation: str
    object: str
    expires_at: str | None = None  # RFC 3339 UTC ("2026-10-27T15:04:00Z"); None = standing

    def __str__(self) -> str:
        base = f"{self.user} {self.relation} {self.object}"
        return f"{base} until {self.expires_at}" if self.expires_at else base

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.user, self.relation, self.object)


class StoreError(RuntimeError):
    """The store could not answer. Callers fail closed."""


class Store(Protocol):
    def check(self, user: str, relation: str, object: str, context: dict | None = None) -> bool: ...
    def list_users(self, object: str, relation: str, user_type: str = "user") -> list[str]: ...
    def list_objects(self, user: str, relation: str, object_type: str) -> list[str]: ...
    def write(self, tuples: Iterable[Tuple]) -> None: ...
    def delete(self, tuples: Iterable[Tuple]) -> None: ...
    def read_all(self) -> list[Tuple]: ...


class OpenFgaStore:
    """Thin sync adapter over openfga_sdk. Any SDK/network failure becomes StoreError."""

    def __init__(self, api_url: str, store_id: str, model_id: str | None = None, api_token: str | None = None):
        from openfga_sdk import ClientConfiguration
        from openfga_sdk.sync import OpenFgaClient

        cfg = ClientConfiguration(api_url=api_url, store_id=store_id, authorization_model_id=model_id)
        if api_token:  # OpenFGA's preshared-key authn
            from openfga_sdk.credentials import CredentialConfiguration, Credentials

            cfg.credentials = Credentials(method="api_token",
                                          configuration=CredentialConfiguration(api_token=api_token))
        self._client = OpenFgaClient(cfg)
        log.debug("openfga store: url=%s store=%s model=%s", api_url, store_id, model_id)

    def check(self, user: str, relation: str, object: str, context: dict | None = None) -> bool:
        from openfga_sdk.client.models import ClientCheckRequest

        try:
            resp = self._client.check(
                ClientCheckRequest(user=user, relation=relation, object=object, context=context)
            )
        except Exception as exc:
            raise StoreError(f"check {user} {relation} {object}: {exc}") from exc
        log.debug("check %s %s %s %s -> %s", user, relation, object, context or "", resp.allowed)
        return bool(resp.allowed)

    def list_users(self, object: str, relation: str, user_type: str = "user") -> list[str]:
        from openfga_sdk.models import FgaObject, ListUsersRequest, UserTypeFilter

        typ, _, ident = object.partition(":")
        req = ListUsersRequest(
            object=FgaObject(type=typ, id=ident), relation=relation,
            user_filters=[UserTypeFilter(type=user_type)],
        )
        try:
            resp = self._client.list_users(req)
        except Exception as exc:
            raise StoreError(f"list_users {object} {relation}: {exc}") from exc
        return sorted(f"{u.object.type}:{u.object.id}" for u in resp.users if u.object)

    def list_objects(self, user: str, relation: str, object_type: str) -> list[str]:
        from openfga_sdk.client.models import ClientListObjectsRequest

        try:
            resp = self._client.list_objects(
                ClientListObjectsRequest(user=user, relation=relation, type=object_type)
            )
        except Exception as exc:
            raise StoreError(f"list_objects {user} {relation} {object_type}: {exc}") from exc
        return sorted(resp.objects)

    def write(self, tuples: Iterable[Tuple]) -> None:
        from openfga_sdk.client.models import ClientTuple
        from openfga_sdk.models import RelationshipCondition

        body = [
            ClientTuple(
                user=t.user, relation=t.relation, object=t.object,
                condition=RelationshipCondition(name=CONDITION, context={"expires_at": t.expires_at})
                if t.expires_at else None,
            )
            for t in tuples
        ]
        if body:
            self._client.write_tuples(body)
            log.info("wrote %d tuples", len(body))

    def delete(self, tuples: Iterable[Tuple]) -> None:
        from openfga_sdk.client.models import ClientTuple

        # Deletes name the key only; a conditional tuple is deleted by the same key.
        body = [ClientTuple(user=t.user, relation=t.relation, object=t.object) for t in tuples]
        if body:
            self._client.delete_tuples(body)
            log.info("deleted %d tuples", len(body))

    def read_all(self) -> list[Tuple]:
        from openfga_sdk.models import ReadRequestTupleKey

        out: list[Tuple] = []
        token = None
        while True:
            resp = self._client.read(ReadRequestTupleKey(), {"continuation_token": token} if token else None)
            for t in resp.tuples:
                cond = getattr(t.key, "condition", None)
                expires = (cond.context or {}).get("expires_at") if cond and cond.name == CONDITION else None
                out.append(Tuple(t.key.user, t.key.relation, t.key.object, expires))
            token = resp.continuation_token
            if not token:
                return out
