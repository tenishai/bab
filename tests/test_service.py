"""The contract: ask, decide, hold, lease, revoke, sweep. Fake store, in-memory ledger."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from bab import catalogue
from bab.service.app import Settings, create_app
from bab.service.identity import ConsoleAuth, StaticVerifier
from bab.service.ledger import Ledger
from bab.service.minters import StaticMinter
from bab.store import Tuple
from tests.conftest import FakeStore

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
ADMIN = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "kyle@example.com"}
SEC = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "sam@example.com"}
OWNER = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "owner@example.com"}
AGENT = {"Authorization": "Bearer sherlock-token"}


@pytest.fixture
def world():
    clock = {"now": T0}
    store = FakeStore({
        Tuple("user:kyle@example.com", "member", "team:admins"),
        Tuple("user:sam@example.com", "member", "team:security"),
        Tuple("team:sre", "team", "agent:sherlock"),
    })
    cat = catalogue.load("catalogues/room.yaml")
    minter = StaticMinter(now=lambda: clock["now"].timestamp())
    app = create_app(store, cat, Ledger(), StaticVerifier({"sherlock-token": "sherlock"}),
                     ConsoleAuth("console-secret"), {"aws": minter},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"]))
    return TestClient(app), store, clock, minter


def connect(c, ceiling):
    r = c.put("/integrations/aws-prod", json={"vendor": "aws", "spec": {"role_arn": "arn:aws:iam::123456789012:role/KoboAccess-Role"}, "ceiling": ceiling}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def test_connect_writes_the_ceiling_for_every_team_and_the_room_link(world):
    c, store, _, _ = world
    out = connect(c, ["aws_inventory_read", "aws_logs_read"])
    assert out["teams"] == ["team:sre"]
    assert Tuple("room:acme", "room", "integration:aws-prod") in store.tuples
    assert Tuple("team:sre", "ceiling_aws_inventory_read", "integration:aws-prod") in store.tuples
    # The picker's tree, grouped the vendor's way, with the tier as a column.
    tree = c.get("/catalogue/aws", headers=OWNER).json()
    assert {g["name"] for g in tree["groups"]} >= {"Inventory", "Logs and metrics", "Billing"}
    assert tree["tiers"][0] == {"name": "read", "lease_seconds": 3600, "validity_days": None}


def test_ask_decide_hold_lease_revoke_sweep(world):
    c, store, clock, minter = world
    connect(c, ["aws_inventory_read", "aws_logs_read", "aws_ecs_update_service"])

    # The owner asks for four permissions; one is above the ceiling.
    r = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                  "permissions": ["aws_inventory_read", "aws_logs_read", "aws_ecs_update_service", "aws_cost_read"],
                                  "note": "incident work"}, headers=OWNER)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert r.json()["tiers"] == {"read": 3, "mutate": 1}
    assert c.get("/requests", headers=ADMIN).json()["requests"][0]["id"] == rid

    # Only a reviewer decides; the owner is refused.
    assert c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=OWNER).status_code == 403
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["status"] == "approved"
    assert out["outcome"]["aws_cost_read"].startswith("refused: team:sre holds no ceiling")
    assert out["outcome"]["aws_inventory_read"] == "granted"

    # Grants: read-tier standing, mutate-tier expiring in 30 days.
    held = {g["permission"]: g for g in c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"]}
    assert held["aws_inventory_read"]["expires_at"] is None
    assert held["aws_ecs_update_service"]["expires_at"] == "2026-11-26T12:00:00Z"
    assert Tuple("agent:sherlock", "aws_ecs_update_service", "integration:aws-prod", "2026-11-26T12:00:00Z") in store.tuples

    # The agent leases what it holds; an unheld permission is named as refused, not fatal.
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_inventory_read", "aws_cost_read"], "task": "inc 4312"}, headers=AGENT)
    assert r.status_code == 200, r.text
    lease = r.json()
    assert lease["granted"] == ["aws_inventory_read"] and lease["refused"] == ["aws_cost_read"]
    assert lease["expires_at"] == "2026-10-27T13:00:00Z"  # read tier: one hour
    assert "token" in lease["credential"]
    # No permissions named: everything the agent holds, lease as short as the shortest tier.
    r = c.post("/leases", json={"integration": "aws-prod"}, headers=AGENT)
    assert sorted(r.json()["granted"]) == ["aws_ecs_update_service", "aws_inventory_read", "aws_logs_read"]
    assert c.get("/leases?agent=sherlock", headers=ADMIN).json()["leases"][0]["task"] is None
    assert len(c.get("/leases", headers=ADMIN).json()["leases"]) == 2

    # A stranger's token gets nothing; the console cannot lease.
    assert c.post("/leases", json={"integration": "aws-prod"}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/leases", json={"integration": "aws-prod"}, headers=ADMIN).status_code == 401

    # Revoke now: the tuple goes, the next lease refuses that permission.
    gid = held["aws_inventory_read"]["id"]
    assert c.delete(f"/grants/{gid}", headers=ADMIN).status_code == 200
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=AGENT)
    assert r.status_code == 403 and r.json()["detail"]["refused"] == ["aws_inventory_read"]

    # Time passes: the mutate grant expires on the dot; sweep tidies it and ends old leases.
    clock["now"] = T0 + timedelta(days=30)
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_ecs_update_service"]}, headers=AGENT)
    assert r.status_code == 403
    assert c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"][-1]["state"] == "expired"
    out = c.post("/sweep", headers=ADMIN).json()
    assert out == {"expired_tuples_deleted": 1, "leases_ended": 2}
    assert len(minter.ended) == 2


def test_destroy_tier_needs_the_security_team_and_a_denial_needs_a_reason(world):
    c, _store, _, _ = world
    connect(c, ["aws_ec2_stop_instances", "aws_inventory_read"])
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                    "permissions": ["aws_ec2_stop_instances", "aws_inventory_read"]}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["outcome"] == {"aws_ec2_stop_instances": "refused: the destroy tier needs the security team",
                              "aws_inventory_read": "granted"}
    rid2 = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                     "permissions": ["aws_ec2_stop_instances"]}, headers=OWNER).json()["id"]
    assert c.post("/requests/decide", json={"ids": [rid2], "verdict": "deny"}, headers=SEC).status_code == 422
    out = c.post("/requests/decide", json={"ids": [rid2], "verdict": "approve"}, headers=SEC).json()["results"][0]
    assert out["outcome"] == {"aws_ec2_stop_instances": "granted"}
    g = next(g for g in c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"] if g["permission"] == "aws_ec2_stop_instances")
    assert g["expires_at"] == "2026-11-03T12:00:00Z"  # destroy: 7 days


def test_a_gated_permission_turns_a_lease_into_a_one_hour_request(world):
    c, store, _clock, _ = world
    connect(c, ["aws_logs_read"])
    store.write([Tuple("agent:sherlock", "aws_logs_read_gated", "integration:aws-prod")])
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_logs_read"], "task": "look at errors"}, headers=AGENT)
    assert r.status_code == 202, r.text
    rid = r.json()["detail"]["request_id"]
    req = c.get("/requests?agent=sherlock", headers=ADMIN).json()["requests"][0]
    assert req["id"] == rid and req["kind"] == "lease" and req["requested_by"] == "agent:sherlock"
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["outcome"] == {"aws_logs_read": "granted"}
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_logs_read"]}, headers=AGENT)
    assert r.status_code == 200
    held = c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"][0]
    assert held["expires_at"] == "2026-10-27T13:00:00Z"
