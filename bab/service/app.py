"""The HTTP surface: requests, decisions, grants, leases, the catalogue, a check.

Two kinds of caller. An agent (its pod's service account token) may mint a lease
for itself and nothing else. The console (shared token, naming the signed-in
person) asks, decides, revokes and reads. bab decides; nothing here trusts the
caller's claim about what it holds.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from bab import ceiling, grants
from bab.catalogue import Catalogue
from bab.door import Door, Verdict, rfc3339
from bab.service.identity import Caller, ConsoleAuth, IdentityError
from bab.service.ledger import AgentRow, GrantRow, Integration, Lease, Ledger, Request
from bab.service.minters import Minter, MintError
from bab.store import Store, StoreError, Tuple
from bab.sync import reconcile, topology

log = logging.getLogger(__name__)

LEASE_REQUEST_HOURS = 1  # an approved gated lease request becomes a grant this long


@dataclass
class Settings:
    room: str  # the root object: room:<name>
    admin_team: str  # team:<name> whose members decide
    security_team: str  # team:<name> required for the destroy tier
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def team(self, name: str) -> str:
        return name if ":" in name else f"team:{name}"


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
    role_arn: str = Field(min_length=20, max_length=2048)
    audience: str | None = Field(default=None, max_length=256)
    # Given: `role_arn` is a spoke, reached from this hub (with this external id).
    hub_role_arn: str | None = Field(default=None, max_length=2048)
    external_id: str | None = Field(default=None, max_length=1224)


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

    Console = Annotated[Caller, Depends(console_caller)]
    Agent = Annotated[Caller, Depends(agent_caller)]

    # A credential still good for the same agent, integration and permissions: handed back
    # instead of minted again, so a runtime may ask on every call (and a revoke bites on
    # the next one, since the grant is checked before this cache is consulted) without a
    # new vendor session each time. Memory only; a restart simply mints afresh.
    live: dict[tuple[str, str, tuple[str, ...]], tuple[int, dict, float, str]] = {}
    LIVE_MARGIN_S = 120

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
        tiers: dict[str, int] = {}
        for p in r.permissions:
            a = cat.action(p)
            if a:
                tiers[a.tier] = tiers.get(a.tier, 0) + 1
        return {"id": r.id, "agent": r.agent, "integration": r.integration, "permissions": r.permissions,
                "tiers": tiers, "kind": r.kind, "status": r.status, "requested_by": r.requested_by,
                "note": r.note, "created_at": r.created_at.isoformat(),
                "decided_at": r.decided_at.isoformat() if r.decided_at else None,
                "decided_by": r.decided_by, "reason": r.reason, "outcome": r.outcome}

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
                {"name": a.name, "tier": a.tier, "description": a.description})
        if not groups:
            raise HTTPException(404, f"the catalogue has no permissions for {vendor!r}")
        v = cat.vendor(vendor)
        return {"vendor": vendor, "kind": v.kind, "label": v.label, "account": v.account or None,
                "groups": [{"name": g, "permissions": ps} for g, ps in groups.items()],
                "tiers": [{"name": t.name, "lease_seconds": t.lease_seconds, "validity_days": t.validity_days}
                          for t in cat.tiers]}

    @app.put("/integrations/{integration}")
    def put_integration(integration: str, body: IntegrationBody, caller: Console):
        """Connect (or re-describe) an integration and set its ceiling: the most any agent may hold there."""
        reviewer(caller)
        acts = permissions_or_422(body.ceiling, body.vendor)
        now = settings.now()
        with ledger.session() as s:
            if body.parent:
                parent = s.get(Integration, body.parent)
                if parent is None or parent.vendor != body.vendor or parent.kind != "org":
                    raise HTTPException(422, f"{body.parent!r} is not a connected {body.vendor} organization")
                if body.parent == integration:
                    raise HTTPException(422, "an integration cannot be its own parent")
            row = s.get(Integration, integration)
            if row is None:
                row = Integration(id=integration, vendor=body.vendor, created_at=now)
                s.add(row)
            row.vendor, row.spec, row.ceiling, row.updated_at = body.vendor, body.spec, [a.name for a in acts], now
            row.parent = body.parent
            try:
                teams = sorted({t.user for t in store.read_all() if t.relation == "team"})
                tuples = [Tuple(f"room:{settings.room}", "room", obj(integration))]
                tuples += [Tuple(team, f"ceiling_{a.name}", obj(integration)) for team in teams for a in acts]
                store.write(tuples)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            ledger.event(s, now, "integration.put", caller.actor, integration=integration, vendor=body.vendor,
                         ceiling=len(acts), teams=len(teams))
            s.commit()
        return {"integration": integration, "vendor": body.vendor, "ceiling": [a.name for a in acts], "teams": teams,
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
        except MintError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/probe/{vendor}")
    def probe(vendor: str, body: ProbeBody, caller: Console):
        """Try a connection before saving it: does the role's trust admit bab?"""
        reviewer(caller)
        minter = minters.get(vendor)
        if minter is None or not hasattr(minter, "probe"):
            raise HTTPException(501, f"bab cannot mint for {vendor!r} yet")
        try:
            out = minter.probe(body.role_arn, body.audience or "sts.amazonaws.com",
                               hub_role_arn=body.hub_role_arn, external_id=body.external_id)
        except MintError as exc:
            raise HTTPException(409, str(exc)) from exc
        return out

    @app.get("/integrations/{integration}/accounts")
    def org_accounts(integration: str, caller: Console):
        """An organization's accounts as its hub sees them, each marked connected when a row
        under this organization names it. What a console offers to connect next."""
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            if row.kind != "org":
                raise HTTPException(409, f"{integration!r} is not an organization")
            minter = minters.get(row.vendor)
            if minter is None or not hasattr(minter, "list_accounts"):
                raise HTTPException(501, f"bab cannot list accounts for {row.vendor!r}")
            children = {str((c.spec or {}).get("account_id", "")): c.id
                        for c in s.scalars(select(Integration).where(Integration.parent == integration))}
            try:
                accounts = minter.list_accounts(str(row.spec.get("hub_role_arn")), str(row.spec.get("audience") or "sts.amazonaws.com"))
            except MintError as exc:
                raise HTTPException(502, str(exc)) from exc
        return {"organization": integration,
                "accounts": [{**a, "integration": children.get(a["id"]), "connected": a["id"] in children} for a in accounts]}

    @app.delete("/integrations/{integration}")
    def delete_integration(integration: str, caller: Console):
        """Disconnect: the row, every active grant on it (revoked), and every tuple
        naming it (room link, ceilings, grants). Leases already minted run out on their own."""
        reviewer(caller)
        now = settings.now()
        with ledger.session() as s:
            row = integration_or_404(s, integration)
            children = list(s.scalars(select(Integration.id).where(Integration.parent == integration)))
            if children:
                raise HTTPException(409, f"{integration!r} still has accounts under it: {', '.join(children)}; disconnect those first")
            revoked = 0
            for g in ledger.active_grants_on(s, integration):
                g.revoked_at, g.revoked_by = now, caller.actor
                revoked += 1
            try:
                gone = [t for t in store.read_all() if t.object == obj(integration)]
                store.delete(gone)
            except StoreError as exc:
                raise HTTPException(503, f"the store cannot answer: {exc}") from exc
            s.delete(row)
            ledger.event(s, now, "integration.removed", caller.actor, integration=integration,
                         grants_revoked=revoked, tuples_deleted=len(gone))
            s.commit()
        return {"removed": integration, "grants_revoked": revoked, "tuples_deleted": len(gone)}

    @app.get("/integrations")
    def list_integrations(caller: Console):
        """Every connected integration and its ceiling: what a picker may offer."""
        with ledger.session() as s:
            rows = list(s.scalars(select(Integration).order_by(Integration.id)))
        return {"integrations": [{"integration": r.id, "vendor": r.vendor, "ceiling": list(r.ceiling),
                                  "kind": r.kind, "parent": r.parent,
                                  "name": str((r.spec or {}).get("name") or r.id),
                                  "account_id": (r.spec or {}).get("account_id"),
                                  # An organization's hub ARN is not a secret; a console needs it to
                                  # render the trust a member account's role must carry.
                                  "hub_role_arn": (r.spec or {}).get("hub_role_arn") if r.kind == "org" else None,
                                  "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()}
                                 for r in rows]}

    @app.get("/agents")
    def list_agents(caller: Console):
        with ledger.session() as s:
            rows = list(s.scalars(select(AgentRow).order_by(AgentRow.name)))
        return {"agents": [{"name": r.name, "team": r.team, "namespace": r.namespace,
                            "service_account": r.service_account} for r in rows]}

    @app.post("/requests", status_code=201)
    def post_request(body: RequestBody, caller: Console):
        now = settings.now()
        with ledger.session() as s:
            integ = integration_or_404(s, body.integration)
            acts = permissions_or_422(body.permissions, integ.vendor)
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
        who = reviewer(caller)
        if body.verdict == "deny" and not (body.reason or "").strip():
            raise HTTPException(422, "a denial needs a reason")
        now = settings.now()
        results = []
        with ledger.session() as s:
            for rid in body.ids:
                req = s.get(Request, rid)
                if req is None or req.status != "pending":
                    results.append({"id": rid, "status": "skipped", "reason": "not a pending request"})
                    continue
                if body.verdict == "deny":
                    req.status, req.decided_at, req.decided_by, req.reason = "denied", now, caller.actor, body.reason
                    results.append({"id": rid, "status": "denied"})
                    continue
                destroy = [p for p in req.permissions if (cat.action(p) and cat.action(p).tier == "destroy")]
                if destroy and not who["security"]:
                    req.outcome = {p: "refused: the destroy tier needs the security team" for p in destroy}
                    req.permissions = [p for p in req.permissions if p not in destroy]
                expires = (now + timedelta(hours=LEASE_REQUEST_HOURS)) if req.kind == "lease" else "tier"
                outcome = write_grants(s, req, caller.actor, now, expires)
                req.outcome = {**(req.outcome or {}), **outcome}
                granted = [p for p, o in req.outcome.items() if o == "granted"]
                req.status = "approved" if granted else "refused"
                req.decided_at, req.decided_by, req.reason = now, caller.actor, body.reason
                results.append({"id": rid, "status": req.status, "outcome": req.outcome})
            ledger.event(s, now, "request.decided", caller.actor, verdict=body.verdict, ids=body.ids)
            s.commit()
        return {"results": results}

    @app.get("/agents/{agent}/grants")
    def agent_grants(agent: str, _: Console):
        cutoff = rfc3339(settings.now())
        with ledger.session() as s:
            rows = ledger.active_grants(s, agent)
        return {"agent": agent, "grants": [
            {**grant_summary(g), "state": "expired" if (g.expires_at and g.expires_at <= cutoff) else "active"}
            for g in rows]}

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
            ledger.event(s, now, "grant.revoked", caller.actor, grant=grant_id, agent=g.agent,
                         permission=g.permission)
            s.commit()
        for key in [k for k in live if k[0] == g.agent and k[1] == g.integration]:
            live.pop(key, None)
        return {"revoked": grant_id}

    @app.post("/leases")
    def post_lease(body: LeaseBody, caller: Agent):
        now = settings.now()
        context = {"current_time": rfc3339(now)}
        with ledger.session() as s:
            integ = integration_or_404(s, body.integration)
            if integ.kind == "org":
                raise HTTPException(409, f"{body.integration!r} is an organization; a lease is for one of its accounts")
            minter = minters.get(integ.vendor)
            if minter is None:
                raise HTTPException(501, f"bab cannot mint for {integ.vendor!r} yet")
            mint_spec = dict(integ.spec or {})
            if integ.parent:
                parent = s.get(Integration, integ.parent)
                if parent is not None:
                    mint_spec = {"hub_role_arn": parent.spec.get("hub_role_arn"), "audience": parent.spec.get("audience"),
                                 **{k: v for k, v in mint_spec.items() if v is not None}}
            wanted = permissions_or_422(body.permissions, integ.vendor) if body.permissions else [
                cat.action(g.permission) for g in ledger.active_grants(s, caller.name, body.integration)
                if cat.action(g.permission) and not g.gated]
            if not wanted:
                raise HTTPException(403, f"{caller.name} holds nothing on {body.integration}")
            granted, gated, refused = [], [], []
            try:
                for a in wanted:
                    if store.check(f"agent:{caller.name}", a.name, obj(body.integration), context):
                        granted.append(a)
                    elif store.check(f"agent:{caller.name}", a.gated, obj(body.integration), context):
                        gated.append(a)
                    else:
                        refused.append(a.name)
            except StoreError as exc:
                raise HTTPException(503, f"no lease: the store cannot answer ({exc})") from exc
            pending = None
            if gated:
                pending = Request(agent=caller.name, integration=body.integration, permissions=[a.name for a in gated],
                                  requested_by=f"agent:{caller.name}", note=body.task, kind="lease", created_at=now)
                s.add(pending)
            if not granted:
                s.commit()
                detail = {"granted": [], "refused": refused, "waiting_for_approval": [a.name for a in gated],
                          "request_id": pending.id if pending else None}
                raise HTTPException(202 if gated else 403, detail)
            seconds = min(cat.tier(a.tier).lease_seconds for a in granted)
            key = (caller.name, body.integration, tuple(sorted(a.name for a in granted)))
            held = live.get(key)
            if held and held[2] - now.timestamp() > LIVE_MARGIN_S:
                lease_id, credential, expires_ts, note = held
                if pending is not None:
                    s.commit()
                return {"lease_id": lease_id, "integration": body.integration, "vendor": integ.vendor,
                        "granted": list(key[2]), "refused": refused,
                        "waiting_for_approval": [a.name for a in gated], "request_id": pending.id if pending else None,
                        "credential": credential, "expires_at": rfc3339(datetime.fromtimestamp(expires_ts, tz=UTC)),
                        "note": note, "reused": True}
            try:
                minted = minter.mint(caller.name, body.integration, mint_spec, granted, seconds)
            except MintError as exc:
                ledger.event(s, now, "lease.failed", caller.name, integration=body.integration, error=str(exc))
                s.commit()
                raise HTTPException(502, f"no lease: {exc}") from exc
            expires = datetime.fromtimestamp(minted.expires_at, tz=UTC)
            lease = Lease(agent=caller.name, integration=body.integration, permissions=[a.name for a in granted],
                          task=body.task, minter=integ.vendor, issued_at=now, expires_at=expires, handle=minted.handle)
            s.add(lease)
            s.commit()
            live[key] = (lease.id, minted.credential, minted.expires_at, minted.note)
            log.info("lease %s -> %s on %s (%d permissions, %ds)", lease.id, caller.name, body.integration,
                     len(granted), seconds)
            return {"lease_id": lease.id, "integration": body.integration, "vendor": integ.vendor,
                    "granted": [a.name for a in granted], "refused": refused,
                    "waiting_for_approval": [a.name for a in gated], "request_id": pending.id if pending else None,
                    "credential": minted.credential, "expires_at": rfc3339(expires), "note": minted.note, "reused": False}

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
                                "permissions": r.permissions, "task": r.task, "minter": r.minter,
                                "issued_at": r.issued_at.isoformat(), "expires_at": r.expires_at.isoformat()}
                               for r in rows]}

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
        ended = 0
        with ledger.session() as s:
            for lease in s.scalars(select(Lease).where(Lease.expires_at <= now.replace(tzinfo=None))):
                m = minters.get(lease.minter)
                if lease.handle and m is not None:  # a JSON column compares badly; filter here
                    m.end(lease.handle)
                    lease.handle = {}
                    ended += 1
            ledger.event(s, now, "sweep", caller.actor, tuples=len(dead), leases_ended=ended)
            s.commit()
        return {"expired_tuples_deleted": len(dead), "leases_ended": ended}

    _ = Verdict  # re-exported through /check's verdict values
    return app
