"""The HTTP surface: requests, decisions, grants, leases, the catalogue, a check.

Two kinds of caller. An agent (its pod's service account token) may mint a lease
for itself and nothing else. The console (shared token, naming the signed-in
person) asks, decides, revokes and reads. bab decides; nothing here trusts the
caller's claim about what it holds.
"""

import inspect
import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import object_session

from bab import ceiling, grants
from bab.catalogue import Catalogue
from bab.door import Door, Verdict, rfc3339
from bab.service.identity import Caller, ConsoleAuth, IdentityError
from bab.service.ledger import AgentRow, Event, GrantRow, Integration, Lease, Ledger, Request
from bab.service.minters import DEFAULT_AUDIENCE, Minter, MintError, NotConfigured, Unreachable
from bab.service.models import PROVIDER_FOR
from bab.store import Store, StoreError, Tuple
from bab.sync import reconcile, topology

log = logging.getLogger(__name__)

LEASE_REQUEST_HOURS = 1  # an approved gated lease request becomes a grant this long
# The vendor whose integrations are other agents (one per agent, id = its name) and the one
# permission on them. Talking is a grant the switchboard reads; nothing is ever minted for it.
AGENTS_VENDOR = "agents"
# Vendors whose credential is narrowed to an integration's `repositories`: the only ones where
# a child under the connection is a smaller thing than the connection, and so an owner's to pick.
REPOSITORY_SET_VENDORS = frozenset({"github"})
# A repository set may instead be every repository the connection can see (`spec.all_repositories`),
# for Read alone: an agent that reads code across the organization needs no list kept up to date,
# and nothing it holds there can change a repository.
ALL_REPOSITORIES = "all_repositories"
EVERY = "every repository"
A2A_ASK = "a2a_ask"
NO_BORROWING = "a credential is never borrowed for another agent's task"
NOT_GRANTED = "not granted"


def accepted(fn: Callable, given: dict, what: str) -> dict:
    """The keyword arguments `fn` accepts, taken from `given` with the Nones dropped: how one
    route hands every vendor's minter its own fields. A required one that is missing is a 422
    naming it; a minter taking `**kwargs` gets everything."""
    params = inspect.signature(fn).parameters
    present = {k: v for k, v in given.items() if v is not None}
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return present
    out = {k: v for k, v in present.items() if k in params}
    missing = [n for n, p in params.items() if p.default is inspect.Parameter.empty and n not in out
               and p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)]
    if missing:
        raise HTTPException(422, f"{what} needs {', '.join(missing)}")
    return out


def org_scope(spec: dict) -> dict:
    """What an organization row hands its minter to list the accounts under it: AWS's hub role
    (and audience), Google Cloud's folder or organization. The minter takes the ones it knows."""
    return {"hub_role_arn": spec.get("hub_role_arn"), "audience": spec.get("audience"),
            "parent": spec.get("parent_resource")}


def child_key(spec: dict) -> str:
    """What names a cloud account row among its organization's accounts: the AWS account id,
    the Google Cloud project id."""
    return str(spec.get("account_id") or spec.get("project") or "")


@dataclass
class Settings:
    room: str  # the root object: room:<name>
    admin_team: str  # team:<name> whose members decide
    security_team: str  # team:<name> required for the destroy tier
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    # The tool gateway's pod identity, `<namespace>/<service account>` (e.g. `liminal/liminal`): the one caller that
    # may lease for a named agent (POST /leases/for-agent). None: that lane is closed.
    gateway_service_account: str | None = None

    def team(self, name: str) -> str:
        return name if ":" in name else f"team:{name}"

    @property
    def room_actor(self) -> str:
        """Who the room is when it acts for itself and not for a person: the actor its console
        sends on the calls nobody clicked (the topology push, an agent's default at birth)."""
        return f"room@{self.room}"


class RequestBody(BaseModel):
    agent: str = Field(min_length=1, max_length=100)
    integration: str = Field(min_length=1, max_length=64)
    permissions: list[str] = Field(min_length=1, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class DecideBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    verdict: str = Field(pattern="^(approve|deny)$")
    reason: str | None = Field(default=None, max_length=2000)


class LeaseBody(BaseModel):
    integration: str = Field(min_length=1, max_length=64)
    permissions: list[str] | None = Field(default=None, max_length=500)
    task: str | None = Field(default=None, max_length=500)
    # The agents whose task this lease would serve. Naming any is refused: a consulted
    # agent answers from what it knows and never borrows a credential for the asker.
    on_behalf_of: list[str] | None = Field(default=None, max_length=100)


class ForAgentLeaseBody(LeaseBody):
    """The gateway's lease: the same request, naming the agent whose call it is serving."""

    agent: str = Field(min_length=1, max_length=100)


class CheckBody(BaseModel):
    agent: str
    action: str
    object: str


class IntegrationBody(BaseModel):
    vendor: str = Field(min_length=1, max_length=32)
    spec: dict = Field(default_factory=dict)
    ceiling: list[str] = Field(default_factory=list)
    # A cloud account under its organization's row: the parent holds the hub role.
    parent: str | None = Field(default=None, max_length=64)


class ProbeBody(BaseModel):
    """Every vendor's probe fields together; the route hands each minter the ones its `probe` accepts."""

    # AWS: the role to try. A service vendor (datadog) is configured on bab itself; the field
    # may then be omitted, or carry the account id a console was handed for bab to confirm.
    role_arn: str | None = Field(default=None, min_length=1, max_length=2048)
    audience: str | None = Field(default=None, max_length=256)
    # Given: `role_arn` is a spoke, reached from this hub (with this external id).
    hub_role_arn: str | None = Field(default=None, max_length=2048)
    external_id: str | None = Field(default=None, max_length=1224)
    # Google Cloud: the project to read with bab's own identity, or with `service_account`
    # impersonated; `parent` (folders/<n> or organizations/<n>) instead asks whether bab can
    # list its projects.
    project: str | None = Field(default=None, min_length=1, max_length=64)
    service_account: str | None = Field(default=None, min_length=1, max_length=256)
    parent: str | None = Field(default=None, min_length=1, max_length=64)
    # Google Cloud, a project that serves models: after the project answers, list Vertex AI's
    # publisher models in this location with the same token. `vertex_url` is accepted so a
    # console that sends it validates, and never fetched: the probe presents a token for bab's
    # identity, so the URL is built by bab from the location and the project, not taken from a caller.
    vertex_location: str | None = Field(default=None, min_length=1, max_length=32)
    vertex_url: str | None = Field(default=None, max_length=512)


class DiscoverBody(BaseModel):
    # AWS: the spoke role's name, the same in every member account (one template, one StackSet).
    # A Google Cloud organization has no role to look for; a project is connected when bab's
    # own identity can read it, and this field is ignored.
    role_name: str = Field(default="KoboAccess-Role", min_length=1, max_length=64, pattern=r"^[\w+=,.@-]+$")


class TopologyAgent(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    team: str = Field(min_length=1, max_length=100)
    namespace: str | None = Field(default=None, max_length=63)
    service_account: str | None = Field(default=None, max_length=253)


class TopologyRoot(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    team: str | None = Field(default=None, max_length=100)


class TopologyBody(BaseModel):
    """What the room knows: its agents (with the pod identity that is each one) and its teams.
    The same shape `bab sync topology` reads from a file; here the room pushes it."""

    agents: list[TopologyAgent] = Field(default_factory=list, max_length=5000)
    # Omitted (None) = the pusher has no opinion on who owns the root and the
    # `owner` relation is left alone; given (even empty) = it is owned here.
    rooms: list[TopologyRoot] | None = Field(default=None, max_length=100)


def create_app(store: Store, cat: Catalogue, ledger: Ledger, agent_verifier, console: ConsoleAuth,
               minters: dict[str, Minter], settings: Settings) -> FastAPI:
    from importlib.metadata import version as _v

    app = FastAPI(title="bab", version=_v("tenish-bab"))
    door = Door(store, cat)

    # ---- callers -----------------------------------------------------------

    def agent_caller(authorization: str = Header(default="")) -> Caller:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "an agent proves itself with its service account token")
        try:
            caller = agent_verifier.verify(token)
        except IdentityError as exc:
            raise HTTPException(401, str(exc)) from exc
        # The token names a service account; the room's topology says which agent that is.
        with ledger.session() as s:
            agent = ledger.resolve_agent(s, caller.name, caller.namespace)
        if agent is None:
            raise HTTPException(401, f"{caller.namespace}/{caller.name} is not an agent this room knows")
        return Caller(caller.kind, agent, actor=caller.actor, namespace=caller.namespace)

    def console_caller(x_bab_console_token: str = Header(default=""),
                       x_bab_actor: str = Header(default="")) -> Caller:
        try:
            return console.verify(x_bab_console_token, x_bab_actor)
        except IdentityError as exc:
            raise HTTPException(401, str(exc)) from exc

    def gateway_caller(authorization: str = Header(default="")) -> Caller:
        """The tool gateway, by its own pod identity: the same TokenReview path an agent takes,
        then the service account must be the one Settings names. Nothing else is admitted."""
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "the gateway proves itself with its service account token")
        if not settings.gateway_service_account:
            raise HTTPException(501, "no tool gateway is configured to lease for agents (BAB_GATEWAY_SERVICE_ACCOUNT)")
        try:
            caller = agent_verifier.verify(token)
        except IdentityError as exc:
            raise HTTPException(401, str(exc)) from exc
        if f"{caller.namespace}/{caller.name}" != settings.gateway_service_account:
            raise HTTPException(403, f"{caller.namespace}/{caller.name} is not the tool gateway")
        return Caller("gateway", caller.name, namespace=caller.namespace)

    Console = Annotated[Caller, Depends(console_caller)]
    Agent = Annotated[Caller, Depends(agent_caller)]
    Gateway = Annotated[Caller, Depends(gateway_caller)]

    # A credential still good for the same agent, integration and permissions: handed back
    # instead of minted again, so a runtime may ask on every call (and a revoke bites on
    # the next one, since the grant is checked before this cache is consulted) without a
    # new vendor session each time. Memory only; a restart simply mints afresh.
    live: dict[tuple[str, str, tuple[str, ...]], tuple[int, dict, float, str]] = {}
    LIVE_MARGIN_S = 120
    checking: set[int] = set()  # leases cached but not yet past their second check: never a cache hit
    # How often a lease also checks every kept key against the ledger (`settle_kept`).
    SETTLE_EVERY_S = 300
    settled = {"at": 0.0}
    settling = threading.Lock()

    def is_member(actor: str, team: str) -> bool:
        try:
            return store.check(f"user:{actor}", "member", settings.team(team))
        except StoreError as exc:
            raise HTTPException(503, f"the store cannot answer: {exc}") from exc

    def reviewer(caller: Caller) -> dict[str, bool]:
        admin = is_member(caller.actor, settings.admin_team)
        security = is_member(caller.actor, settings.security_team)
        if not (admin or security):
            raise HTTPException(403, f"{caller.actor} is not on the admin or security team")
        return {"admin": admin, "security": security}

    def is_reviewer(caller: Caller) -> bool:
        return is_member(caller.actor, settings.admin_team) or is_member(caller.actor, settings.security_team)

    def asked_levels(s, integration: str) -> list[Request]:
        """Level requests still waiting on an integration: what a reviewer may be about to allow."""
        return list(s.scalars(select(Request).where(Request.integration == integration, Request.kind != "repositories",
                                                    Request.status == "pending").order_by(Request.id)))

    def levels_on(s, integration: str) -> list[str]:
        """The levels a repository added to this set would be reached with: the ones held on it
        and the ones asked for, since a reviewer may allow both in one sitting."""
        return sorted({g.permission for g in ledger.active_grants_on(s, integration)}
                      | {p for r in asked_levels(s, integration) for p in r.permissions})

    def every_repository(spec: dict | None) -> bool:
        return (spec or {}).get(ALL_REPOSITORIES) is True

    def with_set(spec: dict | None, pick: dict) -> dict:
        """`spec` with its repository set replaced by `pick`: a list, or every repository."""
        return {**{k: v for k, v in (spec or {}).items() if k not in ("repositories", ALL_REPOSITORIES)}, **pick}

    def beyond_read(names) -> list[str]:
        """Of these permissions, the ones that are more than Read: none may reach every repository."""
        return sorted({p for p in names if cat.action(p) is None or cat.action(p).tier != "read"})

    def read_alone_or_409(s, integration: str, levels: list[str] | None = None) -> None:
        """Every repository is for Read alone: a set that holds or is asked for more stays named."""
        over = beyond_read(levels_on(s, integration) if levels is None else levels)
        if over:
            raise HTTPException(409, f"{EVERY} is for Read alone, and this set holds or is asked for "
                                     f"{', '.join(over)}: take that back first, or keep a picked set")

    def repository_set_or_403(s, integration: str, body: IntegrationBody, caller: Caller) -> tuple[dict, bool]:
        """The one integration a caller who is no reviewer may write: an agent's repository set
        under a service connection (github-<agent> under github), and of it the set alone:
        named repositories, or every repository the connection can see (`all_repositories`),
        which is for Read alone. Picking grants nothing: a level on the set is still a
        reviewer's decision, made looking at the set. So the set must name repositories or say
        every one (an empty list is the whole connection by accident, not by choice), and once
        it carries a grant, or a level request a reviewer has yet to decide, what widens it (a
        repository added, or every repository) is what no reviewer looked at: that waits for
        one (`ask_for_repositories`) instead of landing. Narrowing needs nobody, so every
        repository back to a named set lands. Returns the set asked for, as a spec fragment
        (names trimmed, each once), and whether it waits. A new set's ceiling is not held to
        the connection's: that one bounds a grant on the whole connection, and a level on a set
        is asked for and decided like any other."""
        no = f"{caller.actor} is not on the admin or security team"
        parent = s.get(Integration, body.parent) if body.parent else None
        every = every_repository(body.spec)
        repos = body.spec.get("repositories")
        # A name is what is left after the owner (the minter drops it): "acme/" names nothing.
        named = isinstance(repos, list) and bool(repos) and all(
            isinstance(r, str) and r.strip().rsplit("/", 1)[-1] for r in repos)
        if (body.vendor not in REPOSITORY_SET_VENDORS or parent is None or parent.vendor != body.vendor
                or parent.kind != "connection" or not (named or every)):
            raise HTTPException(403, no)
        # Locked: two picks, or a pick and an approval, decide one after the other.
        row = s.get(Integration, integration, with_for_update=True)
        if row is not None and (row.parent != body.parent or row.vendor != body.vendor):
            raise HTTPException(403, no)
        # A set is watched when a level is held on it or asked for: what widens it waits for a reviewer.
        levels = levels_on(s, integration) if row is not None else []
        watched = bool(levels)
        if every:
            read_alone_or_409(s, integration, levels)
            return {ALL_REPOSITORIES: True}, watched and not every_repository(row.spec)
        wanted = list(dict.fromkeys(r.strip() for r in repos))
        if row is None or every_repository(row.spec):
            return {"repositories": wanted}, False
        before = set((row.spec or {}).get("repositories") or [])
        return {"repositories": wanted}, bool(before and watched and set(wanted) - before)

    def ask_for_repositories(s, row: Integration, pick: dict, caller: Caller, now: datetime) -> tuple[Request, bool]:
        """An owner's pick that widens a set already carrying grants. What the pick drops leaves
        the set now (narrowing needs nobody); what it adds, or every repository, waits as one
        request of kind `repositories` that a reviewer decides, a later pick replacing it. A
        pick that keeps nothing of the set is not applied in part (it would empty the set,
        which means the whole connection): the request then carries what to remove as well.
        Returns the request and whether the set narrowed."""
        before = list((row.spec or {}).get("repositories") or [])
        if every_repository(pick):
            added, narrowed = [], False
            proposal: dict = {"all": True, "added": [], "removed": []}
        else:
            wanted = pick["repositories"]
            added = sorted(set(wanted) - set(before))
            kept = [r for r in before if r in wanted]
            narrowed = bool(kept) and len(kept) != len(before)
            if narrowed:
                row.spec, row.updated_at = with_set(row.spec, {"repositories": kept}), now
            proposal = {"added": added, "removed": [] if kept else sorted(before)}
        # The levels the new repositories would be reached with: what a reviewer is saying yes to.
        # Read again whenever the request is shown (`request_summary`), frozen when it is decided.
        holders = [g.agent for g in ledger.active_grants_on(s, row.id)] + [r.agent for r in asked_levels(s, row.id)]
        levels = levels_on(s, row.id)
        req = s.scalar(select(Request).where(Request.integration == row.id, Request.kind == "repositories",
                                             Request.status == "pending"))
        if req is None:
            req = Request(integration=row.id, kind="repositories", created_at=now)
            s.add(req)
        req.agent, req.permissions = min(holders), levels
        req.requested_by, req.proposal = caller.actor, proposal
        ledger.event(s, now, "request.created", caller.actor, agent=req.agent, integration=row.id,
                     repositories=len(added), every=bool(proposal.get("all")))
        return req, narrowed

    def withdraw_repositories(s, integration: str, actor: str, now: datetime) -> None:
        """The set was written whole: a pick still waiting on it is moot."""
        for req in s.scalars(select(Request).where(Request.integration == integration, Request.kind == "repositories",
                                                   Request.status == "pending")):
            req.permissions = levels_on(s, integration)
            req.status, req.decided_at, req.decided_by = "withdrawn", now, actor
            req.reason = "the set was saved again before this was decided"

    def withdraw_all(s, integration: str, actor: str, now: datetime) -> int:
        """The integration is gone: nothing asked of it can be decided, and a row that later takes
        its name is not the one these were asked of. Returns how many were taken back."""
        waiting = list(s.scalars(select(Request).where(Request.integration == integration, Request.status == "pending")))
        for req in waiting:
            req.status, req.decided_at, req.decided_by = "withdrawn", now, actor
            req.reason = "the integration was disconnected before this was decided"
        return len(waiting)

    def disconnect(s, row: Integration, actor: str, now: datetime) -> tuple[int, int]:
        """Take one integration out of the ledger: every active grant on it revoked, every request
        still waiting on it withdrawn, the row deleted. The tuples naming it are the caller's to
        delete from the store. Every key a minter kept there goes, whether or not its agent
        still holds a grant: one whose delete was refused earlier would otherwise outlive the
        connection that could delete it. Returns how many grants and requests that was."""
        revoked, holders = 0, set()
        for g in ledger.active_grants_on(s, row.id):
            g.revoked_at, g.revoked_by = now, actor
            revoked += 1
            holders.add(g.agent)
        for agent in sorted(holders | {agent for _, agent, integration in kept_keys() if integration == row.id}):
            drop_standing(agent, row.id, row.vendor)
        withdrawn = withdraw_all(s, row.id, actor, now)
        s.delete(row)
        return revoked, withdrawn

    def room_default_or_403(s, body: DecideBody, caller: Caller) -> None:
        """The one decision a caller who is no reviewer may make: the room allowing its own
        default. The room asks for it as itself (`Settings.room_actor`) when an agent is born,
        and nobody is there to click yes, so it may approve exactly what it asked for and only
        where the catalogue says a default is safe: every permission in the request is marked
        `room_default`, and the request is on that agent's own repository set (a child of a service
        connection that names its repositories), never on the connection itself. Anything else
        in the batch refuses the whole batch with the sentence every non-reviewer gets: a
        denial, a request a person raised, one already decided, a pick of repositories, a level
        the catalogue does not mark, a set that names nothing, another agent's set."""
        no = HTTPException(403, f"{caller.actor} is not on the admin or security team")
        if caller.actor != settings.room_actor or body.verdict != "approve":
            raise no
        for rid in body.ids:
            req = s.get(Request, rid)
            if (req is None or req.status != "pending" or req.kind == "repositories"
                    or req.requested_by != settings.room_actor or not req.permissions):
                raise no
            if not all(cat.action(p) and cat.action(p).room_default for p in req.permissions):
                raise no
            row = s.get(Integration, req.integration)
            parent = s.get(Integration, row.parent) if row is not None and row.parent else None
            if (parent is None or row.vendor not in REPOSITORY_SET_VENDORS or parent.vendor != row.vendor
                    or parent.kind != "connection" or not (row.spec or {}).get("repositories")):
                raise no
            # The agent's OWN set: `<connection>-<agent>`, never another agent's.
            if row.id != f"{row.parent}-{req.agent}":
                raise no

    def apply_repositories(s, req: Request, who: dict[str, bool], actor: str, now: datetime) -> set[str]:
        """Approve a `repositories` request: the set takes what was asked. The reviewer is saying
        yes to every level held on the set reaching the new repositories, so the destroy tier
        takes the security team here as it does on a grant, and every repository is refused
        while the set holds or is asked for more than Read. Returns the agents holding grants
        on the set, whose credential in hand no longer matches it."""
        row = s.get(Integration, req.integration, with_for_update=True)
        change = req.proposal or {}
        every = change.get("all") is True
        added, removed = list(change.get("added") or []), list(change.get("removed") or [])
        held = ledger.active_grants_on(s, req.integration) if row is not None else []
        why = None
        if row is None:
            why = "the repository set is gone"
        elif not who["security"] and any(cat.action(g.permission) and cat.action(g.permission).tier == "destroy" for g in held):
            why = "the destroy tier needs the security team"
        elif every and beyond_read(levels_on(s, req.integration)):
            why = f"{EVERY} is for Read alone, and the set holds or is asked for more"
        if why:
            req.status, req.outcome = "refused", {r: f"refused: {why}" for r in ([EVERY] if every else added)}
            return set()
        req.permissions = sorted({g.permission for g in held})  # what the yes was said to
        if every:
            row.spec, row.updated_at = with_set(row.spec, {ALL_REPOSITORIES: True}), now
            req.status, req.outcome = "approved", {EVERY: "added"}
            return {g.agent for g in held}
        before = set((row.spec or {}).get("repositories") or [])
        row.spec, row.updated_at = with_set(row.spec, {"repositories": sorted((before - set(removed)) | set(added))}), now
        req.status, req.outcome = "approved", {**{r: "removed" for r in removed}, **{r: "added" for r in added}}
        return {g.agent for g in held}

    # ---- helpers -----------------------------------------------------------

    def obj(integration: str) -> str:
        return f"integration:{integration}"

    def integration_or_404(s, integration: str) -> Integration:
        row = s.get(Integration, integration)
        if row is None:
            raise HTTPException(404, f"no integration {integration!r}")
        return row

    def permissions_or_422(names: list[str], vendor: str | None = None) -> list:
        acts = []
        for n in dict.fromkeys(names):
            a = cat.action(n)
            if a is None:
                raise HTTPException(422, f"{n!r} is not a permission in the catalogue")
            if vendor and a.vendor and a.vendor != vendor:
                raise HTTPException(422, f"{n!r} belongs to {a.vendor}, not {vendor}")
            acts.append(a)
        return acts

    def grant_summary(g: GrantRow) -> dict:
        return {"id": g.id, "agent": g.agent, "integration": g.integration, "permission": g.permission,
                "tier": (cat.action(g.permission).tier if cat.action(g.permission) else None),
                "gated": g.gated, "expires_at": g.expires_at, "granted_by": g.granted_by,
                "created_at": g.created_at.isoformat(), "request_id": g.request_id}

    def request_summary(r: Request) -> dict:
        permissions = r.permissions
        s = object_session(r)
        if r.kind == "repositories" and r.status == "pending" and s is not None:
            # A pick is read against the levels on its set now, not the ones it was asked under:
            # a level granted or asked for since would reach the new repositories too.
            permissions = levels_on(s, r.integration)
        tiers: dict[str, int] = {}
        for p in permissions:
            a = cat.action(p)
            if a:
                tiers[a.tier] = tiers.get(a.tier, 0) + 1
        return {"id": r.id, "agent": r.agent, "integration": r.integration, "permissions": permissions,
                "tiers": tiers, "kind": r.kind, "status": r.status, "requested_by": r.requested_by,
                "note": r.note, "created_at": r.created_at.isoformat(),
                "decided_at": r.decided_at.isoformat() if r.decided_at else None,
                "decided_by": r.decided_by, "reason": r.reason, "outcome": r.outcome, "proposal": r.proposal}

    def write_grants(s, req: Request, actor: str, now: datetime, expires: datetime | None | str) -> dict:
        """Approve one request: ceiling-checked grant per permission; a refusal is recorded, not fatal."""
        team = ceiling.team_of(store, req.agent)
        outcome: dict[str, str] = {}
        if team is None:
            return {p: "refused: the agent has no team (topology sync)" for p in req.permissions}
        for p in req.permissions:
            try:
                t = grants.grant(store, cat, team, ceiling.Grant(req.agent, p, obj(req.integration)), now, expires)
            except grants.CeilingError as exc:
                outcome[p] = f"refused: {exc}"
                continue
            s.add(GrantRow(request_id=req.id, agent=req.agent, integration=req.integration, permission=p,
                           expires_at=t.expires_at, granted_by=actor, created_at=now))
            outcome[p] = "granted"
        return outcome

    def end_leases(s, rows, now: datetime) -> int:
        """Delete the vendor-side credential of each lease whose minter can (Datadog deletes
        the key; AWS cannot recall a session and left no handle). A refusal is recorded and
        the handle kept, so the next pass tries again."""
        ended = 0
        for lease in rows:
            m = minters.get(lease.minter)
            if not lease.handle or m is None:  # a JSON column compares badly; filter here
                continue
            try:
                m.end(lease.handle)
            except MintError as exc:
                ledger.event(s, now, "lease.end_failed", None, lease=lease.id, error=str(exc))
                continue
            lease.handle = {}
            lease.expires_at = min(lease.expires_at, now.replace(tzinfo=None))  # ended now, if early
            ended += 1
        return ended

    def end_expired(s, now: datetime) -> int:
        return end_leases(s, s.scalars(select(Lease).where(Lease.expires_at <= now.replace(tzinfo=None))), now)

    def drop_standing(agent: str, integration: str, vendor: str | None) -> None:
        """A key a minter keeps for `agent` across leases goes when what the agent may do on
        `integration` changes or ends, live lease or none. Only the vendor's own minter is
        told, so a change on one vendor never waits on another's store; with no vendor known
        (the row is gone), every minter is."""
        for m in [minters.get(vendor)] if vendor else list(minters.values()):
            drop = getattr(m, "drop", None)
            if drop is not None:
                drop(agent, integration)

    def kept_keys() -> list[tuple[Minter, str, str]]:
        """(minter, agent, integration) of every key a minter keeps across leases."""
        found = []
        for m in minters.values():
            kept = getattr(m, "kept", None)
            if kept is not None:
                found.extend((m, agent, integration) for agent, integration in kept())
        return found

    def settle_kept(now: datetime, force: bool = False) -> None:
        """Check every kept key against what the ledger says its agent holds now, at most every
        SETTLE_EVERY_S unless forced, one pass at a time, in a session of its own. A lease runs
        it after its answer is sent, so a slow vendor never slows a lease. `drop_standing` is
        told of a change once, when it happens; this is what tries again a delete the vendor
        refused then, and what takes a key whose grant ran out, or whose connection went, while
        its agent was not asking."""
        if not settling.acquire(blocking=force):
            return
        try:
            if not force and now.timestamp() - settled["at"] < SETTLE_EVERY_S:
                return
            settled["at"] = now.timestamp()
            cutoff = rfc3339(now)
            with ledger.session() as s:
                for m, agent, integration in kept_keys():
                    holds = None
                    if s.get(Integration, integration) is not None:
                        names = [g.permission for g in ledger.active_grants(s, agent, integration)
                                 if not g.gated and not (g.expires_at and g.expires_at <= cutoff)]
                        holds = [a for a in map(cat.action, names) if a]
                    try:
                        m.settle(agent, integration, holds)
                    except Exception as exc:  # noqa: BLE001 - one key's trouble is not the next key's
                        log.warning("could not check the key kept for %s on %s: %s", agent, integration, exc)
        finally:
            settling.release()

    def end_live(s, agent: str, integration: str, now: datetime) -> int:
        """End what `agent` holds on `integration` right now. A grant or a revoke changes
        what the next credential may carry, so the one in hand is ended where the vendor
        allows it rather than left to run out its hour beside the new one."""
        row = s.get(Integration, integration)
        drop_standing(agent, integration, row.vendor if row is not None else None)
        return end_leases(s, s.scalars(select(Lease).where(
            Lease.agent == agent, Lease.integration == integration,
            Lease.expires_at > now.replace(tzinfo=None))), now)

    def forget_live(pairs) -> None:
        """Drop the cached credential of each (agent, integration): the next ask mints afresh."""
        pairs = set(pairs)
        for key in [k for k in live if (k[0], k[1]) in pairs]:
            live.pop(key, None)

    # ---- routes ------------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "room": settings.room}

    @app.get("/catalogue")
    def catalogue_vendors(_: Console):
        """Every vendor the catalogue knows: its kind (cloud or service), label, and how many
        permissions it offers per tier."""
        out = []
        for name in cat.vendor_names():
            v = cat.vendor(name)
            tiers: dict[str, int] = {}
            for a in cat.for_vendor(name):
                tiers[a.tier] = tiers.get(a.tier, 0) + 1
            out.append({"vendor": name, "kind": v.kind, "label": v.label, "account": v.account or None,
                        "permissions": tiers})
        return {"vendors": out}

    @app.get("/catalogue/{vendor}")
    def catalogue(vendor: str, _: Console):
        groups: dict[str, list] = {}
        for a in cat.for_vendor(vendor):
            groups.setdefault(a.group or "General", []).append(
                {"name": a.name, "tier": a.tier, "label": a.label or None, "description": a.description,
                 "room_default": a.room_default})
        if not groups:
            raise HTTPException(404, f"the catalogue has no permissions for {vendor!r}")
        v = cat.vendor(vendor)
        return {"vendor": vendor, "kind": v.kind, "label": v.label, "account": v.account or None,
                "groups": [{"name": g, "permissions": ps} for g, ps in groups.items()],
                "tiers": [{"name": t.name, "lease_seconds": t.lease_seconds, "validity_days": t.validity_days}
                          for t in cat.tiers]}

    @app.put("/integrations/{integration}")
    def put_integration(integration: str, body: IntegrationBody, caller: Console):
        """Connect (or re-describe) an integration and set its ceiling: the most any agent may hold there.
        An `agents` integration is the room's own fact (which agents exist), like the topology: the console
        token is the authority and any actor may write it; every other vendor takes a reviewer, but for
        an agent's repository set under a service connection, which the room lets the agent's owner pick
        (`repository_set_or_403`: it grants nothing by itself). Of such a write only the repositories are
        taken: an existing set keeps its ceiling and the rest of its spec, a new one starts with the
        repositories alone. An owner's pick that adds to a set already carrying grants (or a level
        request not yet decided) answers 202 with the request a reviewer decides under `pending`; the
        set keeps what it had, less what the pick dropped. The `agents` lane is for rows that are, or
        are about to be, `agents` rows: it does not re-describe another vendor's.
        A set that changes under grants drops the credential cached for it, so the next lease carries
        the new set.
        A `parent` hangs this row under an organization (a cloud account under its hub) or under a
        service connection (a repository set under the GitHub connection), one level deep: the parent
        must be the same vendor and must not have a parent of its own."""
        acts = permissions_or_422(body.ceiling, body.vendor)
        names = [a.name for a in acts]
        now = settings.now()
        stale: set[tuple[str, str]] = set()
        with ledger.session() as s:
            there = s.get(Integration, integration)
            room_fact = body.vendor == AGENTS_VENDOR and (there is None or there.vendor == AGENTS_VENDOR)
            if every_repository(body.spec):
                # Only an agent's set under a service connection: on the connection itself every child's
                # credential would inherit it, and a list beside it would say two things at once.
                home = s.get(Integration, body.parent) if body.parent else None
                if (body.vendor not in REPOSITORY_SET_VENDORS or home is None or home.vendor != body.vendor
                        or home.kind != "connection"):
                    raise HTTPException(422, f"{EVERY} is for an agent's repository set under a service connection")
                if body.spec.get("repositories"):
                    raise HTTPException(422, f"name repositories or ask for {EVERY}, not both")
            picked: dict | None = None  # an owner's pick: the repository set, and nothing else of the body
            waits = False
            if not (room_fact or is_reviewer(caller)):
                picked, waits = repository_set_or_403(s, integration, body, caller)
            elif every_repository(body.spec) and s.get(Integration, integration) is not None:
                read_alone_or_409(s, integration)  # a reviewer's write is held to the same rule
            if waits:
                row = s.get(Integration, integration)
                req, narrowed = ask_for_repositories(s, row, picked, caller, now)
                if narrowed:
                    stale = {(g.agent, integration) for g in ledger.active_grants_on(s, integration)}
                    for agent, _ in sorted(stale):
                        end_live(s, agent, integration, now)
                    ledger.event(s, now, "integration.put", caller.actor, integration=integration, vendor=row.vendor,
                                 repositories=len(row.spec["repositories"]))
                s.commit()
                forget_live(stale)
                return JSONResponse(status_code=202, content={
                    "integration": integration, "vendor": row.vendor, "ceiling": list(row.ceiling),
                    "parent": row.parent, "kind": row.kind, "repositories": list((row.spec or {}).get("repositories") or []),
                    "all_repositories": every_repository(row.spec), "pending": request_summary(req)})
            if body.parent:
                if body.parent == integration:
                    raise HTTPException(422, "an integration cannot be its own parent")
                parent = s.get(Integration, body.parent)
                if parent is not None and parent.parent:
                    raise HTTPException(422, f"{body.parent!r} is itself under {parent.parent!r}; an integration hangs one level deep")
                if parent is None or parent.vendor != body.vendor or parent.kind not in ("org", "connection"):
                    raise HTTPException(422, f"{body.parent!r} is not a connected {body.vendor} organization or service connection")
            row = s.get(Integration, integration)
            spec = body.spec if picked is None else picked
            if row is None:
                row = Integration(id=integration, vendor=body.vendor, created_at=now)
                s.add(row)
            else:
                if picked is not None:
                    spec, names = with_set(row.spec, picked), list(row.ceiling)
                # The set stated whole, changed or not: a pick still waiting on it is taken back.
                withdraw_repositories(s, integration, caller.actor, now)
                if ((row.spec or {}).get("repositories"), every_repository(row.spec)) != (
                        spec.get("repositories"), every_repository(spec)):
                    # The set an agent's credential is narrowed to changed: the one in hand is for the old set.
                    stale = {(g.agent, integration) for g in ledger.active_grants_on(s, integration)}
                    for agent, _ in sorted(stale):
                        end_live(s, agent, integration, now)
            row.vendor, row.spec, row.ceiling, row.updated_at = body.vendor, spec, names, now
            row.parent = body.parent
            try:
                teams = sorted({t.user for t in store.read_all() if t.relation == "team"})
                tuples = [Tuple(f"room:{settings.room}", "room", obj(integration))]
                tuples += [Tuple(team, f"ceiling_{name}", obj(integration)) for team in teams for name in names]
                store.write(tuples)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            ledger.event(s, now, "integration.put", caller.actor, integration=integration, vendor=body.vendor,
                         ceiling=len(names), teams=len(teams))
            s.commit()
        forget_live(stale)
        return {"integration": integration, "vendor": body.vendor, "ceiling": names, "teams": teams,
                "parent": body.parent, "kind": row.kind}

    @app.put("/topology")
    def put_topology(body: TopologyBody, caller: Console):
        """The room pushes its agents and teams. Owns the `team` and `owner` relations and the
        agents table; everything else in the store is untouched. The console token is the
        authority here (the topology is the room's own fact, not a person's decision); the
        actor is recorded, and may be the room itself."""
        now = settings.now()
        topo = body.model_dump()
        rooms = topo.pop("rooms")
        topo[f"{cat.root}s"] = rooms or []
        owned = topology.relations(cat) if rooms is not None else {"team"}
        with ledger.session() as s:
            try:
                written, deleted = reconcile(store, topology.tuples(topo, cat), owned)
                # A team that appears after an integration was connected has no
                # ceiling there yet; connect gives every team the same one, so
                # give it the same one now (the same tuples connect writes).
                have = set(store.read_all())
                teams = sorted({f"team:{a['team']}" for a in topology.agents(topo)})
                extend = [Tuple(team, f"ceiling_{p}", obj(i.id)) for i in s.scalars(select(Integration))
                          for team in teams for p in i.ceiling
                          if Tuple(team, f"ceiling_{p}", obj(i.id)) not in have]
                if extend:
                    store.write(extend)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            keep = set()
            for a in topology.agents(topo):
                keep.add(a["name"])
                row = s.get(AgentRow, a["name"]) or AgentRow(name=a["name"], team=a["team"], updated_at=now)
                row.team, row.namespace, row.service_account, row.updated_at = (
                    a["team"], a["namespace"], a["service_account"], now)
                s.add(row)
            gone = [r for r in s.scalars(select(AgentRow)) if r.name not in keep]
            for r in gone:
                s.delete(r)
            ledger.event(s, now, "topology.put", caller.actor, agents=len(keep), removed=len(gone),
                         tuples_written=len(written) + len(extend), tuples_deleted=len(deleted))
            s.commit()
        log.info("topology from %s: %d agents (%d removed), tuples +%d -%d, ceilings +%d", caller.actor,
                 len(keep), len(gone), len(written), len(deleted), len(extend))
        return {"agents": len(keep), "removed": len(gone), "tuples_written": len(written) + len(extend),
                "tuples_deleted": len(deleted)}

    @app.get("/identity/{vendor}")
    def identity(vendor: str, _: Console):
        """Who bab is to a vendor: what an account owner writes into a trust policy."""
        minter = minters.get(vendor)
        if minter is None or not hasattr(minter, "identity"):
            raise HTTPException(501, f"bab cannot mint for {vendor!r} yet")
        try:
            return minter.identity()
        except NotConfigured as exc:  # nothing to ask the vendor yet; the console shows the sentence
            raise HTTPException(409, str(exc)) from exc
        except MintError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/probe/{vendor}")
    def probe(vendor: str, body: ProbeBody, caller: Console):
        """Try a connection before saving it, the vendor's way: AWS assumes the role (does its
        trust admit bab?), Google Cloud reads the project with bab's identity (is it granted
        there?), a service vendor confirms its own configuration. The body carries every vendor's
        fields; the minter is handed the ones its probe accepts."""
        reviewer(caller)
        minter = minters.get(vendor)
        if minter is None or not hasattr(minter, "probe"):
            raise HTTPException(501, f"bab cannot mint for {vendor!r} yet")
        try:
            out = minter.probe(**accepted(minter.probe, body.model_dump(), f"a probe for {vendor!r}"))
        except Unreachable as exc:  # the connection admits bab; a surface behind it did not answer
            raise HTTPException(502, str(exc)) from exc
        except MintError as exc:
            raise HTTPException(409, str(exc)) from exc
        return out

    @app.get("/integrations/{integration}/accounts")
    def org_accounts(integration: str, caller: Console):
        """An organization's accounts as the vendor shows them to bab (AWS: through the hub
        role; Google Cloud: the projects under the folder or organization), each marked
        connected when a row under this organization names it. What a console offers next."""
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            if row.kind != "org":
                raise HTTPException(409, f"{integration!r} is not an organization")
            minter = minters.get(row.vendor)
            if minter is None or not hasattr(minter, "list_accounts"):
                raise HTTPException(501, f"bab cannot list accounts for {row.vendor!r}")
            children = {child_key(c.spec or {}): c.id
                        for c in s.scalars(select(Integration).where(Integration.parent == integration))}
            try:
                accounts = minter.list_accounts(**accepted(minter.list_accounts, org_scope(row.spec or {}),
                                                           f"listing accounts for {row.vendor!r}"))
            except MintError as exc:
                raise HTTPException(502, str(exc)) from exc
        return {"organization": integration,
                "accounts": [{**a, "integration": children.get(a["id"]), "connected": a["id"] in children} for a in accounts]}

    @app.post("/integrations/{integration}/discover")
    def org_discover(integration: str, body: DiscoverBody, caller: Console):
        """Which of an organization's accounts bab can already reach, probed the vendor's way.
        AWS: every active account the hub can see is probed through the hub for the spoke role
        with the organization's external id (one id per organization, so one template deploys
        the role everywhere). Google Cloud: every active project under the folder or organization
        is read with bab's own identity; the ones granted the role pack answer. What a console
        registers next, without a person adding accounts one at a time."""
        reviewer(caller)
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            if row.kind != "org":
                raise HTTPException(409, f"{integration!r} is not an organization")
            spec = dict(row.spec or {})
            minter = minters.get(row.vendor)
            if minter is None or not hasattr(minter, "list_accounts") or not hasattr(minter, "probe"):
                raise HTTPException(501, f"bab cannot discover accounts for {row.vendor!r}")
            hub = str(spec.get("hub_role_arn") or "")
            external_id = str(spec.get("external_id") or "")
            if hub and not external_id:
                raise HTTPException(409, f"{integration!r} has no external id; connect it again from a console that sets one")
            children = {child_key(c.spec or {}): c.id
                        for c in s.scalars(select(Integration).where(Integration.parent == integration))}
            try:
                accounts = minter.list_accounts(**accepted(minter.list_accounts, org_scope(spec),
                                                           f"listing accounts for {row.vendor!r}"))
            except MintError as exc:
                raise HTTPException(502, str(exc)) from exc
            now = settings.now()
            ledger.event(s, now, "integration.discover", caller.actor, integration=integration, accounts=len(accounts))
            s.commit()
        # The catalogue's noun for this cloud's unit (account, project, subscription) is the
        # probe's keyword on every lane but AWS's hub-and-spoke one.
        noun = cat.vendor(row.vendor).account or "account"

        def look(a: dict) -> dict:
            out = {**a, "integration": children.get(a["id"]), "connected": a["id"] in children,
                   "reachable": None, "reason": None}
            if hub:
                out["role_arn"] = f"arn:aws:iam::{a['id']}:role/{body.role_name}"
                ask = {"role_arn": out["role_arn"], "audience": spec.get("audience"), "hub_role_arn": hub,
                       "external_id": external_id}
            else:
                ask = {noun: a["id"]}
            if a.get("status") not in (None, "ACTIVE"):
                out["reason"] = f"{noun} is {a.get('status')}"
                return out
            if not hub:
                # Google Cloud: the tree came from `projects:search`, which lists only what bab's
                # identity may read, so every project here is reachable by construction. Probing
                # each one again (737 projects on 2026-11-09) took minutes and tripped Resource
                # Manager's rate limit, which marked readable projects "not granted".
                out["reachable"] = True
                return out
            try:
                minter.probe(**accepted(minter.probe, ask, f"a probe for {row.vendor!r}"))
                out["reachable"] = True
            except MintError as exc:
                out["reachable"], out["reason"] = False, str(exc)
            return out

        with ThreadPoolExecutor(max_workers=8) as pool:
            looked = list(pool.map(look, accounts))
        lane = ({"external_id": external_id, "role_name": body.role_name} if hub
                else {"parent": spec.get("parent_resource")})
        return {"organization": integration, **lane, "accounts": looked}

    @app.get("/integrations/{integration}/models")
    def integration_models(integration: str, caller: Console, location: str | None = None,
                           region: str | None = None):
        """The chat models a connected cloud offers, listed with the identity the probes use
        and cut to chat text models that are generally available: what an admin ticks for New
        agent. A Google Cloud row lists Vertex AI's publisher models for its Vertex project
        (`spec.models.project`, then `spec.identity.project`, then `spec.project`; `location`
        default global, the row's `spec.models.location` when set); an AWS row lists Bedrock's
        models in `region` (default us-east-1) through its role, the hub lane for an account
        under an organization. Any other vendor is 501; the vendor refusing is 502 with its
        own sentence."""
        reviewer(caller)
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            spec = {k: v for k, v in dict(row.spec or {}).items() if v is not None}
            parent = s.get(Integration, row.parent) if row.parent else None
            if parent is not None and parent.kind == "org":
                spec = {"hub_role_arn": parent.spec.get("hub_role_arn"), "audience": parent.spec.get("audience"),
                        "external_id": parent.spec.get("external_id"), **spec}
        provider = PROVIDER_FOR.get(row.vendor)
        minter = minters.get(row.vendor)
        if provider is None or minter is None or not hasattr(minter, "list_models"):
            raise HTTPException(501, f"bab cannot list models for {row.vendor!r}")
        models_spec = spec.get("models") if isinstance(spec.get("models"), dict) else {}
        identity_spec = spec.get("identity") if isinstance(spec.get("identity"), dict) else {}
        try:
            if provider == "vertex_ai":
                project = str(models_spec.get("project") or identity_spec.get("project") or spec.get("project") or "").strip()
                if not project:
                    raise HTTPException(409, f"{integration!r} names no Vertex AI project; connect it again naming one")
                where = str(location or models_spec.get("location") or "global").strip()
                listed = minter.list_models(project=project, location=where,
                                            service_account=str(spec.get("service_account") or "") or None)
            else:
                if row.kind == "org":
                    raise HTTPException(409, f"{integration!r} is an organization; ask for one of its accounts' models")
                where = str(region or models_spec.get("region") or "us-east-1").strip()
                listed = minter.list_models(region=where, role_arn=spec.get("role_arn"),
                                            spoke_role_arn=spec.get("spoke_role_arn"), hub_role_arn=spec.get("hub_role_arn"),
                                            external_id=spec.get("external_id"),
                                            audience=str(spec.get("audience") or "") or DEFAULT_AUDIENCE)
        except MintError as exc:  # the vendor's sentence, whether it refused or did not answer
            raise HTTPException(502, str(exc)) from exc
        return {"integration": integration, "provider": provider, "models": listed,
                "fetched_at": rfc3339(settings.now())}

    @app.delete("/integrations/{integration}")
    def delete_integration(integration: str, caller: Console):
        """Disconnect: the row, every active grant on it (revoked), every request still waiting
        on it (withdrawn), and every tuple naming it (room link, ceilings, grants). Leases already
        minted run out on their own; a key kept across leases is deleted. A row that is not
        there is 404 whoever asks: that it is absent is no secret from a caller holding the
        console token."""
        with ledger.session() as s0:
            row0 = integration_or_404(s0, integration)
        if row0.vendor != AGENTS_VENDOR:
            reviewer(caller)
        now = settings.now()
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            children = list(s.scalars(select(Integration.id).where(Integration.parent == integration)))
            if children:
                what = "accounts" if row.kind == "org" else "integrations"
                raise HTTPException(409, f"{integration!r} still has {what} under it: {', '.join(children)}; disconnect those first")
            revoked, _ = disconnect(s, row, caller.actor, now)
            try:
                gone = [t for t in store.read_all() if t.object == obj(integration)]
                store.delete(gone)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            ledger.event(s, now, "integration.removed", caller.actor, integration=integration,
                         grants_revoked=revoked, tuples_deleted=len(gone))
            s.commit()
        return {"removed": integration, "grants_revoked": revoked, "tuples_deleted": len(gone)}

    @app.get("/integrations")
    def list_integrations(caller: Console):
        """Every connected integration and its ceiling: what a picker may offer. A child row (an
        account under its organization, a repository set under its connection) names its `parent`
        and is kind `account`; a console lists it under that parent."""
        with ledger.session() as s:
            rows = list(s.scalars(select(Integration).order_by(Integration.id)))
        return {"integrations": [{"integration": r.id, "vendor": r.vendor, "ceiling": list(r.ceiling),
                                  "kind": r.kind, "parent": r.parent,
                                  "name": str((r.spec or {}).get("name") or r.id),
                                  "account_id": (r.spec or {}).get("account_id"),
                                  # A Google Cloud project row names its project; an organization row its
                                  # folder or organization, which a console shows next to the grant to make.
                                  "project": (r.spec or {}).get("project"),
                                  "parent_resource": (r.spec or {}).get("parent_resource") if r.kind == "org" else None,
                                  # A service child's repository set, so a console can show what it narrows to.
                                  "repositories": list((r.spec or {}).get("repositories") or []) or None,
                                  # Or every repository the connection can see, for Read alone.
                                  "all_repositories": every_repository(r.spec),
                                  # An organization's hub ARN is not a secret; a console needs it to
                                  # render the trust a member account's role must carry.
                                  "hub_role_arn": (r.spec or {}).get("hub_role_arn") if r.kind == "org" else None,
                                  "external_id": (r.spec or {}).get("external_id") if r.kind == "org" else None,
                                  "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()}
                                 for r in rows]}

    @app.get("/agents")
    def list_agents(caller: Console):
        with ledger.session() as s:
            rows = list(s.scalars(select(AgentRow).order_by(AgentRow.name)))
        return {"agents": [{"name": r.name, "team": r.team, "namespace": r.namespace,
                            "service_account": r.service_account} for r in rows]}

    @app.delete("/agents/{agent}")
    def delete_agent(agent: str, caller: Console):
        """The room says an agent is gone, and everything it held goes with it: every active
        grant it holds on any integration (revoked, the tuples deleted, a credential in hand
        ended where the vendor allows it), every request still waiting for it (withdrawn), its
        repository sets (the child named `<connection>-<agent>` under a service connection) and
        its `agents` integration (so nobody is left allowed to talk to it). Like the topology,
        this is the room's own fact: the console token is the authority and the actor is
        recorded. It is refused while the topology still lists the agent (409: push the
        topology without it first), so it cannot take a living agent's grants. A set another
        agent still holds a level on, or is waiting for one on, is kept and named. Calling it
        again finds nothing and answers zeros."""
        now = settings.now()
        with ledger.session() as s:
            if s.get(AgentRow, agent) is not None:
                raise HTTPException(409, f"{agent!r} is still one of the room's agents; push the topology without it first")
            held = ledger.active_grants(s, agent)
            for g in held:
                g.revoked_at, g.revoked_by = now, caller.actor
            revoked = len(held)
            withdrawn = 0
            for req in s.scalars(select(Request).where(Request.agent == agent, Request.kind != "repositories",
                                                       Request.status == "pending")):
                req.status, req.decided_at, req.decided_by = "withdrawn", now, caller.actor
                req.reason = "the agent was removed before this was decided"
                withdrawn += 1
            s.flush()

            def others(integration: str) -> list[str]:
                """Who else holds a level on an integration, or waits for one."""
                return sorted(({g.agent for g in ledger.active_grants_on(s, integration)}
                               | {r.agent for r in asked_levels(s, integration)}) - {agent})

            going: list[Integration] = []
            kept: list[str] = []
            for row in s.scalars(select(Integration).where(Integration.parent.is_not(None)).order_by(Integration.id)):
                if row.vendor not in REPOSITORY_SET_VENDORS or row.id != f"{row.parent}-{agent}":
                    continue
                if others(row.id):
                    kept.append(row.id)
                else:
                    going.append(row)
            own = s.get(Integration, agent)
            if own is not None and own.vendor == AGENTS_VENDOR:
                # Nothing hangs under an agent's row; one that somehow does is left for a person.
                if s.scalar(select(Integration.id).where(Integration.parent == own.id).limit(1)) is None:
                    going.append(own)
                else:
                    kept.append(own.id)
            removed = sorted(r.id for r in going)
            # A pick of repositories names the first agent on its set. On a set that stays, it
            # is handed to whoever is left there, or taken back when nobody is.
            for req in s.scalars(select(Request).where(Request.agent == agent, Request.kind == "repositories",
                                                       Request.status == "pending")):
                if req.integration in removed:
                    continue
                left = others(req.integration)
                if left:
                    req.agent = left[0]
                    continue
                req.status, req.decided_at, req.decided_by = "withdrawn", now, caller.actor
                req.reason = "the agent was removed before this was decided"
                withdrawn += 1
            for row in going:
                more, taken = disconnect(s, row, caller.actor, now)
                revoked, withdrawn = revoked + more, withdrawn + taken
            objects = {obj(i) for i in removed}
            try:
                gone = [t for t in store.read_all()
                        if t.object in objects or (t.user == f"agent:{agent}" and t.object.startswith("integration:"))]
                store.delete(gone)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            pairs = sorted({(g.agent, g.integration) for g in held})
            ended = sum(end_live(s, a, i, now) for a, i in pairs)
            out = {"agent": agent, "grants_revoked": revoked, "requests_withdrawn": withdrawn,
                   "integrations_removed": len(removed), "tuples_deleted": len(gone), "leases_ended": ended,
                   "removed": removed, "kept": sorted(kept)}
            if revoked or withdrawn or removed or gone or ended:
                ledger.event(s, now, "agent.removed", caller.actor, **out)
            s.commit()
        forget_live(pairs)
        log.info("agent %s removed by %s: grants -%d, requests -%d, integrations -%d, tuples -%d", agent,
                 caller.actor, revoked, withdrawn, len(removed), len(gone))
        return out

    @app.post("/requests", status_code=201)
    def post_request(body: RequestBody, caller: Console):
        now = settings.now()
        with ledger.session() as s:
            # Locked, as a pick is: the set cannot become every repository between this read and the commit.
            integ = s.get(Integration, body.integration, with_for_update=True)
            if integ is None:
                raise HTTPException(404, f"no integration {body.integration!r}")
            acts = permissions_or_422(body.permissions, integ.vendor)
            over = beyond_read(a.name for a in acts) if every_repository(integ.spec) else []
            if over:
                raise HTTPException(409, f"{EVERY} is for Read alone: {', '.join(over)} needs a picked set of repositories")
            req = Request(agent=body.agent, integration=body.integration, permissions=[a.name for a in acts],
                          requested_by=caller.actor, note=body.note, created_at=now)
            s.add(req)
            ledger.event(s, now, "request.created", caller.actor, agent=body.agent, integration=body.integration,
                         permissions=len(acts))
            s.commit()
            return request_summary(req)

    @app.get("/requests")
    def list_requests(_: Console, status: str = Query(default="pending"), agent: str | None = None):
        with ledger.session() as s:
            q = select(Request).where(Request.status == status) if status != "all" else select(Request)
            if agent:
                q = q.where(Request.agent == agent)
            return {"requests": [request_summary(r) for r in s.scalars(q.order_by(Request.id))]}

    @app.post("/requests/decide")
    def decide(body: DecideBody, caller: Console):
        """A reviewer's verdict on a batch of requests. One caller on no team may approve: the
        room, deciding the default it asked for itself (`room_default_or_403`). It holds neither
        flag below, so nothing a reviewer's team opens (the destroy tier, a pick of
        repositories) is open to it even if the gate were wrong."""
        who = {"admin": is_member(caller.actor, settings.admin_team),
               "security": is_member(caller.actor, settings.security_team)}
        by_room = not (who["admin"] or who["security"])
        if body.verdict == "deny" and not (body.reason or "").strip() and not by_room:
            raise HTTPException(422, "a denial needs a reason")
        now = settings.now()
        results = []
        changed: set[tuple[str, str]] = set()
        with ledger.session() as s:
            if by_room:
                room_default_or_403(s, body, caller)
            for rid in body.ids:
                req = s.get(Request, rid)
                if req is None or req.status != "pending":
                    results.append({"id": rid, "status": "skipped", "reason": "not a pending request"})
                    continue
                if body.verdict == "deny":
                    req.status, req.decided_at, req.decided_by, req.reason = "denied", now, caller.actor, body.reason
                    results.append({"id": rid, "status": "denied"})
                    continue
                if req.kind == "repositories":
                    holders = apply_repositories(s, req, who, caller.actor, now)
                    req.decided_at, req.decided_by, req.reason = now, caller.actor, body.reason
                    result = {"id": rid, "status": req.status, "outcome": req.outcome}
                    if req.status == "approved":
                        every = bool((req.proposal or {}).get("all"))
                        ledger.event(s, now, "integration.put", caller.actor, integration=req.integration,
                                     request=req.id, repositories=0 if every else len(req.outcome), every=every)
                        fresh = {(a, req.integration) for a in holders} - changed
                        result["leases_ended"] = sum(end_live(s, a, i, now) for a, i in sorted(fresh))
                        changed |= fresh
                    results.append(result)
                    continue
                on = s.get(Integration, req.integration)
                over = beyond_read(req.permissions) if on is not None and every_repository(on.spec) else []
                if over:  # asked before the set became every repository
                    req.outcome = {p: f"refused: {EVERY} is for Read alone" for p in over}
                    req.permissions = [p for p in req.permissions if p not in over]
                destroy = [p for p in req.permissions if (cat.action(p) and cat.action(p).tier == "destroy")]
                if destroy and not who["security"]:
                    req.outcome = {**(req.outcome or {}), **{p: "refused: the destroy tier needs the security team" for p in destroy}}
                    req.permissions = [p for p in req.permissions if p not in destroy]
                expires = (now + timedelta(hours=LEASE_REQUEST_HOURS)) if req.kind == "lease" else "tier"
                outcome = write_grants(s, req, caller.actor, now, expires)
                req.outcome = {**(req.outcome or {}), **outcome}
                granted = [p for p, o in req.outcome.items() if o == "granted"]
                req.status = "approved" if granted else "refused"
                req.decided_at, req.decided_by, req.reason = now, caller.actor, body.reason
                result = {"id": rid, "status": req.status, "outcome": req.outcome}
                if granted and (req.agent, req.integration) not in changed:
                    # The agent now holds more here than the credential in its hand carries:
                    # that one is ended, so the next call gets one with the new access instead
                    # of failing on the old one until its hour is up.
                    changed.add((req.agent, req.integration))
                    result["leases_ended"] = end_live(s, req.agent, req.integration, now)
                results.append(result)
            ledger.event(s, now, "request.decided", caller.actor, verdict=body.verdict, ids=body.ids,
                         **({"room_default": True} if by_room else {}))
            s.commit()
        forget_live(changed)
        return {"results": results}

    @app.get("/agents/{agent}/grants")
    def agent_grants(agent: str, _: Console):
        cutoff = rfc3339(settings.now())
        with ledger.session() as s:
            rows = ledger.active_grants(s, agent)
        return {"agent": agent, "grants": [
            {**grant_summary(g), "state": "expired" if (g.expires_at and g.expires_at <= cutoff) else "active"}
            for g in rows]}

    @app.get("/agents/{agent}/talks-to")
    def agent_talks_to(agent: str, _: Console):
        """The agents this one may ask for help: every active, ungated `a2a_ask` grant it holds
        on an `agents` integration (one per target agent, id = its name). What the switchboard
        reads to build its dispatch pairs; one query, no store round trip."""
        cutoff = rfc3339(settings.now())
        with ledger.session() as s:
            names = s.scalars(
                select(GrantRow.integration).join(Integration, Integration.id == GrantRow.integration)
                .where(Integration.vendor == AGENTS_VENDOR, GrantRow.agent == agent, GrantRow.permission == A2A_ASK,
                       GrantRow.gated.is_(False), GrantRow.revoked_at.is_(None),
                       or_(GrantRow.expires_at.is_(None), GrantRow.expires_at > cutoff))
                .distinct().order_by(GrantRow.integration))
            return {"agent": agent, "talks_to": list(names)}

    @app.delete("/grants/{grant_id}")
    def revoke(grant_id: int, caller: Console):
        reviewer(caller)
        now = settings.now()
        with ledger.session() as s:
            g = s.get(GrantRow, grant_id)
            if g is None or g.revoked_at is not None:
                raise HTTPException(404, "no such active grant")
            rel = f"{g.permission}_gated" if g.gated else g.permission
            try:
                store.delete([Tuple(f"agent:{g.agent}", rel, obj(g.integration), g.expires_at)])
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            g.revoked_at, g.revoked_by = now, caller.actor
            # A credential the agent still holds there is ended where the vendor allows it:
            # the next call mints afresh, narrower, or gets nothing.
            ended = end_live(s, g.agent, g.integration, now)
            ledger.event(s, now, "grant.revoked", caller.actor, grant=grant_id, agent=g.agent,
                         permission=g.permission, leases_ended=ended)
            s.commit()
        forget_live([(g.agent, g.integration)])
        return {"revoked": grant_id, "leases_ended": ended}

    def lease_for(agent: str, body: LeaseBody, via: str | None, after: BackgroundTasks | None = None) -> dict:
        """One lease, for `agent`: the grant checks, the live-credential cache, the mint and the
        ledger row are the same whether the agent asked with its own token (via None) or the
        tool gateway asked for it (via "gateway"). The caller is settled before this runs."""
        now = settings.now()
        context = {"current_time": rfc3339(now)}
        if after is not None:
            after.add_task(settle_kept, now)
        with ledger.session() as s:
            end_expired(s, now)
            if body.on_behalf_of:
                # The second wall (the runtime is the first): whatever either side holds, a
                # task that arrived from another agent gets no credential. Recorded, refused.
                ledger.event(s, now, "lease.refused", agent, agent=agent, integration=body.integration,
                             permissions=list(body.permissions or []), on_behalf_of=body.on_behalf_of,
                             reason=NO_BORROWING, via=via)
                s.commit()
                raise HTTPException(403, NO_BORROWING)
            integ = integration_or_404(s, body.integration)
            if integ.vendor == AGENTS_VENDOR:
                raise HTTPException(409, "talking is granted, not leased: the switchboard reads the grant")
            if integ.kind == "org":
                raise HTTPException(409, f"{body.integration!r} is an organization; a lease is for one of its accounts")
            integ = resolve_child(s, agent, integ)
            iid = integ.id
            minter = minters.get(integ.vendor)
            if minter is None:
                raise HTTPException(501, f"bab cannot mint for {integ.vendor!r} yet")
            mint_spec = dict(integ.spec or {})
            if integ.parent:
                parent = s.get(Integration, integ.parent)
                if parent is not None and parent.kind == "org":
                    # The organization's external id is every spoke's unless the account was
                    # connected with one of its own (the per-account shape, kept working).
                    mint_spec = {"hub_role_arn": parent.spec.get("hub_role_arn"), "audience": parent.spec.get("audience"),
                                 "external_id": parent.spec.get("external_id"),
                                 **{k: v for k, v in mint_spec.items() if v is not None}}
                elif parent is not None:
                    # A child of a service connection: the connection's spec, narrowed by the child's own
                    # (its `repositories`); the minter's credentials come from bab's mounted Secret either way.
                    mint_spec = {**{k: v for k, v in (parent.spec or {}).items() if k != ALL_REPOSITORIES},
                                 **{k: v for k, v in mint_spec.items() if v is not None}}
            wanted = permissions_or_422(body.permissions, integ.vendor) if body.permissions else [
                cat.action(g.permission) for g in ledger.active_grants(s, agent, iid)
                if cat.action(g.permission) and not g.gated]
            if not wanted:
                drop_standing(agent, iid, integ.vendor)  # every grant lapsed or was taken back: nothing is left to carry
                ledger.event(s, now, "lease.refused", agent, agent=agent, integration=iid, permissions=[],
                             reason=NOT_GRANTED, via=via)
                s.commit()
                raise HTTPException(403, f"{agent} holds nothing on {iid}")
            granted, gated, refused = [], [], []
            try:
                for a in wanted:
                    if store.check(f"agent:{agent}", a.name, obj(iid), context):
                        granted.append(a)
                    elif store.check(f"agent:{agent}", a.gated, obj(iid), context):
                        gated.append(a)
                    else:
                        refused.append(a.name)
            except StoreError as exc:
                raise HTTPException(503, f"no lease: the store cannot answer ({exc})") from exc
            if every_repository(integ.spec):
                # Every repository is for Read alone: what else the agent holds there is not leased,
                # so the lease's ledger row and answer name only what the credential can do.
                refused += [a.name for a in granted if a.tier != "read"]
                granted = [a for a in granted if a.tier == "read"]
            pending = None
            if gated:
                pending = Request(agent=agent, integration=iid, permissions=[a.name for a in gated],
                                  requested_by=f"agent:{agent}", note=body.task, kind="lease", created_at=now)
                s.add(pending)
            if not granted:
                if not body.permissions:
                    drop_standing(agent, iid, integ.vendor)
                if not gated:
                    # Nothing held and nothing waiting: a refusal, recorded like the borrowing one so
                    # the room's Agents audit can show it next to the leases that did mint.
                    ledger.event(s, now, "lease.refused", agent, agent=agent, integration=iid, permissions=refused,
                                 reason=NOT_GRANTED, via=via)
                s.commit()
                detail = {"granted": [], "refused": refused, "waiting_for_approval": [a.name for a in gated],
                          "request_id": pending.id if pending else None}
                raise HTTPException(202 if gated else 403, detail)
            seconds = min(cat.tier(a.tier).lease_seconds for a in granted)
            key = (agent, iid, tuple(sorted(a.name for a in granted)))
            resolved = {"resolved_from": body.integration} if iid != body.integration else {}
            held = live.get(key)
            if held and held[0] not in checking and held[2] - now.timestamp() > LIVE_MARGIN_S:
                lease_id, credential, expires_ts, note = held
                if pending is not None:
                    s.commit()
                return {"lease_id": lease_id, "integration": iid, "vendor": integ.vendor, **resolved,
                        "granted": list(key[2]), "refused": refused,
                        "waiting_for_approval": [a.name for a in gated], "request_id": pending.id if pending else None,
                        "credential": credential, "expires_at": rfc3339(datetime.fromtimestamp(expires_ts, tz=UTC)),
                        "note": note, "reused": True}
            # A lease on everything the agent holds may be the key the minter keeps for it;
            # one that names its permissions is a credential of its own.
            mint = minter.mint if body.permissions else getattr(minter, "mint_standing", minter.mint)
            try:
                minted = mint(agent, iid, mint_spec, granted, seconds)
            except MintError as exc:
                ledger.event(s, now, "lease.failed", agent, agent=agent, integration=iid,
                             permissions=[a.name for a in granted], reason=str(exc), error=str(exc), via=via)
                s.commit()
                raise HTTPException(502, f"no lease: {exc}") from exc
            expires = datetime.fromtimestamp(minted.expires_at, tz=UTC)
            lease = Lease(agent=agent, integration=iid, permissions=[a.name for a in granted],
                          task=body.task, minter=integ.vendor, issued_at=now, expires_at=expires, handle=minted.handle,
                          via=via)
            s.add(lease)
            s.commit()
            checking.add(lease.id)
            live[key] = (lease.id, minted.credential, minted.expires_at, minted.note)
            # Asked again now that the lease is on the books. A revoke or an approval that
            # landed while the credential was made found no lease to end; one that lands from
            # here on finds this one. For a kept key the minter is asked too: an approval drops
            # the key without taking a grant away.
            try:
                still = all(store.check(f"agent:{agent}", a.name, obj(iid), context) for a in granted)
            except StoreError:
                still = None
            holds = getattr(minter, "holds", None)
            given = bool(still) and (holds is None or holds(minted.handle))
            checking.discard(lease.id)
            if not given:
                if still is False:
                    drop_standing(agent, iid, integ.vendor)
                lease.expires_at = now.replace(tzinfo=None)  # ended now, whether or not the vendor could
                end_leases(s, [lease], now)
                if live.get(key, (None,))[0] == lease.id:
                    live.pop(key, None)
                reason = "the store cannot answer" if still is None else "access changed while this lease was made"
                ledger.event(s, now, "lease.failed", agent, agent=agent, integration=iid, lease=lease.id,
                             permissions=[a.name for a in granted], reason=reason, error=reason, via=via)
                s.commit()
                raise HTTPException(503 if still is None else 409, f"no lease: {reason}; ask again")
            log.info("lease %s -> %s on %s (%d permissions, %ds%s%s)", lease.id, agent, iid,
                     len(granted), seconds, f", via {via}" if via else "",
                     f", asked for {body.integration}" if resolved else "")
            return {"lease_id": lease.id, "integration": iid, "vendor": integ.vendor, **resolved,
                    "granted": [a.name for a in granted], "refused": refused,
                    "waiting_for_approval": [a.name for a in gated], "request_id": pending.id if pending else None,
                    "credential": minted.credential, "expires_at": rfc3339(expires), "note": minted.note, "reused": False}

    def resolve_child(s, agent: str, integ: Integration) -> Integration:
        """A lease asked for by the parent's name (the gateway asks for "github") lands on the one
        child the agent holds a grant on (its repository set, "github-<agent>"), when the agent holds
        nothing on the parent itself. Two or more such children: the agent must name one. None: the
        parent is leased as asked, and the grant check says what it says. Organizations never reach
        here (a lease on one is refused above); this is the service-connection shape."""
        if integ.kind != "connection" or ledger.active_grants(s, agent, integ.id):
            return integ
        children = list(s.scalars(select(Integration).where(Integration.parent == integ.id).order_by(Integration.id)))
        held = [c for c in children if ledger.active_grants(s, agent, c.id)]
        if not held:
            return integ
        if len(held) > 1:
            names = ", ".join(c.id for c in held)
            raise HTTPException(409, f"{agent} holds {integ.id} on more than one of its integrations ({names}); ask for one by name")
        log.info("lease for %s on %s resolved to %s (the one child %s holds a grant on)", agent, integ.id, held[0].id, agent)
        return held[0]

    @app.post("/leases")
    def post_lease(body: LeaseBody, caller: Agent, after: BackgroundTasks):
        return lease_for(caller.name, body, None, after)

    @app.post("/leases/for-agent")
    def post_lease_for_agent(body: ForAgentLeaseBody, caller: Gateway, after: BackgroundTasks):
        """The tool gateway leases for the agent whose call it is serving. The gateway is its
        own pod identity (Settings.gateway_service_account); the named agent must be one the
        room's topology knows; then the grant checks, cache and ledger are the agent's own,
        with the row marked `via: gateway`. `on_behalf_of` is refused here as everywhere."""
        with ledger.session() as s:
            if s.scalar(select(AgentRow.name).limit(1)) is not None and s.get(AgentRow, body.agent) is None:
                raise HTTPException(403, f"{body.agent} is not an agent this room knows")
        try:
            return lease_for(body.agent, LeaseBody(**body.model_dump(exclude={"agent"})), "gateway", after)
        except HTTPException as exc:
            # The gateway shows a 403's detail to the model as one sentence; 404 stays "not connected".
            if exc.status_code == 403 and isinstance(exc.detail, dict):
                refused = ", ".join(exc.detail.get("refused") or [])
                raise HTTPException(403, f"{body.agent} does not hold {refused} on {body.integration}" if refused
                                    else f"{body.agent} holds nothing on {body.integration}") from exc
            raise

    @app.get("/leases")
    def list_leases(_: Console, agent: str | None = None, integration: str | None = None,
                    since: datetime | None = None, limit: int = Query(default=200, le=1000)):
        with ledger.session() as s:
            q = select(Lease)
            if agent:
                q = q.where(Lease.agent == agent)
            if integration:
                q = q.where(Lease.integration == integration)
            if since:
                q = q.where(Lease.issued_at >= since.replace(tzinfo=None))
            rows = s.scalars(q.order_by(Lease.id.desc()).limit(limit))
            return {"leases": [{"id": r.id, "agent": r.agent, "integration": r.integration,
                                "permissions": r.permissions, "task": r.task, "minter": r.minter, "via": r.via,
                                "issued_at": r.issued_at.isoformat(), "expires_at": r.expires_at.isoformat()}
                               for r in rows]}

    @app.get("/events")
    def list_events(_: Console, since: datetime | None = None, until: datetime | None = None,
                    kind: Annotated[list[str] | None, Query()] = None, agent: str | None = None,
                    limit: int = Query(default=200, ge=1, le=1000)):
        """The ledger's events, newest first, for the room's audit: `kind` repeats or takes a
        comma list; `agent` reads `detail.agent`, which every lease.refused and lease.failed
        row carries; `until` is exclusive. A row is id, at, kind, actor, detail."""
        kinds = [k for raw in (kind or []) for k in raw.split(",") if k.strip()]
        with ledger.session() as s:
            q = select(Event)
            if kinds:
                q = q.where(Event.kind.in_([k.strip() for k in kinds]))
            if agent:
                q = q.where(Event.detail["agent"].as_string() == agent)
            if since:
                q = q.where(Event.at >= since.replace(tzinfo=None))
            if until:
                q = q.where(Event.at < until.replace(tzinfo=None))
            rows = s.scalars(q.order_by(Event.id.desc()).limit(limit))
            return {"events": [{"id": r.id, "at": r.at.isoformat(), "kind": r.kind, "actor": r.actor,
                                "detail": r.detail or {}} for r in rows]}

    @app.post("/check")
    def check(body: CheckBody, _: Console):
        d = door.decide(body.agent, body.action, body.object, now=settings.now())
        return {"verdict": d.verdict.value, "reason": d.reason, "approvers": list(d.approvers),
                "degraded": d.degraded}

    @app.post("/sweep")
    def sweep(caller: Console):
        now = settings.now()
        try:
            dead = grants.sweep(store, now)
        except StoreError as exc:
            raise HTTPException(503, f"the store cannot answer: {exc}") from exc
        settle_kept(now, force=True)
        with ledger.session() as s:
            ended = end_expired(s, now)
            ledger.event(s, now, "sweep", caller.actor, tuples=len(dead), leases_ended=ended)
            s.commit()
        return {"expired_tuples_deleted": len(dead), "leases_ended": ended}

    _ = Verdict  # re-exported through /check's verdict values
    return app
