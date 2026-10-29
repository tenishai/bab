"""The ledger: bab's own record of what was asked, decided, granted and leased.

OpenFGA answers the question; these tables are the audit. In a deployment they
live in a `bab` database on the room's PostgreSQL instance, next to OpenFGA's
own database (BAB_DATABASE_URL, `postgresql+psycopg://...`); `bab serve` refuses
SQLite unless told it is a laptop run. Tests use SQLite in memory. Tables are
created at boot.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Integration(Base):
    """One connected vendor or account: what bab needs to mint for it."""

    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    spec: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # role_arn, audience, ...
    ceiling: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # permissions the connection can honour
    # A cloud account under its organization's row (hub-and-spoke): the parent holds the hub
    # role bab assumes with its own identity, this row the spoke role the hub assumes next.
    parent: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    @property
    def kind(self) -> str:
        """`org` (holds a hub role), `account` (a cloud account, under an org or flat), or `connection`."""
        if self.parent:
            return "account"
        spec = self.spec or {}
        if spec.get("hub_role_arn"):
            return "org"
        if spec.get("role_arn") or spec.get("spoke_role_arn"):
            return "account"
        return "connection"


class AgentRow(Base):
    """One agent the room knows, and which pod identity is that agent (from the topology push)."""

    __tablename__ = "agents"
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    team: Mapped[str] = mapped_column(String(100), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(63), nullable=True, index=True)
    service_account: Mapped[str | None] = mapped_column(String(253), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class Request(Base):
    __tablename__ = "requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    integration: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(320), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="standing")  # standing | lease
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # per permission: granted|refused + why


class GrantRow(Base):
    __tablename__ = "grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    integration: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    permission: Mapped[str] = mapped_column(String(100), nullable=False)
    gated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)  # RFC 3339 or None = standing
    granted_by: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class Lease(Base):
    __tablename__ = "leases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    integration: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False)
    task: Mapped[str | None] = mapped_column(Text, nullable=True)
    minter: Mapped[str] = mapped_column(String(32), nullable=False)  # the vendor key in the minters registry
    issued_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    handle: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # what the minter needs to end it early


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(320), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Ledger:
    def __init__(self, url: str = "sqlite+pysqlite:///:memory:"):
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        from sqlalchemy.pool import StaticPool

        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        self.engine = create_engine(url, **kwargs)
        Base.metadata.create_all(self.engine)
        self._ensure_columns()
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def _ensure_columns(self) -> None:
        """create_all never alters an existing table; a column added after a database was
        born is added here, once, by name. Small enough not to want a migration tool yet."""
        from sqlalchemy import inspect, text

        have = {c["name"] for c in inspect(self.engine).get_columns("integrations")}
        if "parent" not in have:
            with self.engine.begin() as conn:
                conn.execute(text("ALTER TABLE integrations ADD COLUMN parent VARCHAR(64)"))

    def session(self) -> Session:
        return self.sessions()

    def event(self, s: Session, at: datetime, kind: str, actor: str | None, **detail) -> None:
        s.add(Event(at=at, kind=kind, actor=actor, detail=detail))

    def resolve_agent(self, s: Session, name: str, namespace: str | None) -> str | None:
        """Which agent a pod identity is. `name` is the service account; a row whose
        (namespace, service_account) matches wins, then a row named like the service
        account. None when the room's topology knows agents and this is not one of them;
        `name` itself when no topology has been pushed yet."""
        if s.scalar(select(AgentRow.name).limit(1)) is None:
            return name
        if namespace:
            hit = s.scalar(select(AgentRow.name).where(AgentRow.namespace == namespace,
                                                       AgentRow.service_account == name))
            if hit:
                return hit
        return s.scalar(select(AgentRow.name).where(AgentRow.name == name))

    def active_grants_on(self, s: Session, integration: str) -> list[GrantRow]:
        return list(s.scalars(select(GrantRow).where(GrantRow.integration == integration, GrantRow.revoked_at.is_(None))))

    def active_grants(self, s: Session, agent: str, integration: str | None = None) -> list[GrantRow]:
        q = select(GrantRow).where(GrantRow.agent == agent, GrantRow.revoked_at.is_(None))
        if integration:
            q = q.where(GrantRow.integration == integration)
        return list(s.scalars(q.order_by(GrantRow.id)))
