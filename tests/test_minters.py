from datetime import UTC, datetime

import pytest

from bab import catalogue
from bab.service.identity import IdentityError, agent_from_username
from bab.service.minters import AwsMinter, session_policy


def test_session_policy_is_the_union_of_the_granted_permissions_iam_actions():
    cat = catalogue.load("catalogues/room.yaml")
    pol = session_policy([cat.action("aws_cloudtrail_read"), cat.action("aws_ecs_update_service")])
    allow, deny = pol["Statement"]
    assert allow["Effect"] == "Allow" and allow["Action"] == [
        "cloudtrail:CancelQuery", "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
        "cloudtrail:LookupEvents", "cloudtrail:StartQuery", "ecs:UpdateService"]
    # Every session carries the data-plane Deny: a read is configuration and listings, never contents.
    assert deny["Effect"] == "Deny" and {"s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt",
                                          "dynamodb:Scan", "sqs:ReceiveMessage"} <= set(deny["Action"])
    assert session_policy([cat.action("datadog_logs_read")]) is None


def test_aws_minter_assumes_with_the_agent_in_the_session_name_and_the_policy():
    calls = []

    def assume(role_arn, token, name, seconds, policy):
        calls.append((role_arn, token, name, seconds, policy))
        return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2026, 10, 27, 13, 0, tzinfo=UTC)},
                "AssumedRoleUser": {"Arn": "arn:aws:sts::123456789012:assumed-role/KoboAccess-Role/bab-sherlock"}}

    cat = catalogue.load("catalogues/room.yaml")
    m = AwsMinter(token_source=lambda aud: f"jwt-for-{aud}", assume=assume)
    out = m.mint("sherlock", "aws-prod", {"role_arn": "arn:aws:iam::123456789012:role/KoboAccess-Role"},
                 [cat.action("aws_logs_read")], 3600)
    assert calls[0][1:4] == ("jwt-for-sts.amazonaws.com", "bab-sherlock", 3600)  # the agent rides in the session name
    assert calls[0][4]["Statement"][0]["Action"][0] == "logs:Describe*"
    assert out.credential["aws_access_key_id"] == "AKIA" and out.handle == {}


def test_agent_is_the_service_account_name():
    assert agent_from_username("system:serviceaccount:sherlock:sherlock") == ("sherlock", "sherlock")
    try:
        agent_from_username("kyle@example.com")
    except IdentityError:
        pass
    else:
        raise AssertionError("a person is not an agent")


def test_aws_minter_hops_through_the_hub_for_an_account_under_an_organization():
    hops = []

    def assume(role_arn, token, name, seconds, policy):
        hops.append(("web-identity", role_arn, name, seconds, policy))
        return {"Credentials": {"AccessKeyId": "HUB", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2026, 10, 27, 13, 0, tzinfo=UTC)},
                "AssumedRoleUser": {"Arn": "arn:aws:sts::999999999999:assumed-role/BabHub/bab-sherlock"}}

    def assume_role(creds, role_arn, name, seconds, policy, external_id):
        hops.append(("assume-role", creds["AccessKeyId"], role_arn, name, seconds, bool(policy), external_id))
        return {"Credentials": {"AccessKeyId": "SPOKE", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2026, 10, 27, 13, 0, tzinfo=UTC)},
                "AssumedRoleUser": {"Arn": "arn:aws:sts::111111111111:assumed-role/BabSpoke/bab-sherlock"}}

    cat = catalogue.load("catalogues/room.yaml")
    m = AwsMinter(token_source=lambda aud: "jwt", assume=assume, assume_role=assume_role)
    out = m.mint("sherlock", "acme-prod",
                 {"hub_role_arn": "arn:aws:iam::999999999999:role/BabHub", "spoke_role_arn": "arn:aws:iam::111111111111:role/BabSpoke",
                  "external_id": "x1"}, [cat.action("aws_s3_read")], 3600)
    # Hop one: bab's identity into the hub, briefly, no policy. Hop two: the hub into the spoke
    # with the external id, the session policy and the agent's name, which CloudTrail records.
    assert hops[0][:3] == ("web-identity", "arn:aws:iam::999999999999:role/BabHub", "bab-sherlock") and hops[0][4] is None
    assert hops[1] == ("assume-role", "HUB", "arn:aws:iam::111111111111:role/BabSpoke", "bab-sherlock", 3600, True, "x1")
    assert out.credential["aws_access_key_id"] == "SPOKE"
    assert out.credential["assumed_role_arn"].endswith("BabSpoke/bab-sherlock")


def test_datadog_minter_mints_a_key_scoped_to_the_union_and_named_for_the_agent():
    from bab.service.minters import DatadogMinter, MintError, dd_scopes
    from tests.conftest import FakeDatadog

    cat = catalogue.load("catalogues/room.yaml")
    dd = FakeDatadog()
    m = DatadogMinter.from_env({"DD_SERVICE_ACCOUNT_ID": "sa-123", "DD_API_KEY": "api-xyz", "DD_MGMT_APP_KEY": "mgmt-abc",
                                "DD_SITE": "datadoghq.eu"}, http=dd,
                               now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp())
    perms = [cat.action("datadog_metrics_read"), cat.action("datadog_monitors_read"), cat.action("datadog_security_read")]
    assert dd_scopes(perms) == ["mcp_read", "metrics_read", "monitors_read", "security_monitoring_rules_read",
                                "security_monitoring_signals_read", "timeseries_query"]
    # A mutate permission adds mcp_write; a read-only lease never carries it; no scopes stay none.
    assert dd_scopes([cat.action("datadog_monitors_write")]) == ["mcp_read", "mcp_write", "monitors_write"]
    assert dd_scopes([]) == []
    out = m.mint("sherlock", "datadog", {}, perms, 7200)
    method, url, body = dd.calls[0]
    assert (method, url) == ("POST", "https://api.datadoghq.eu/api/v2/service_accounts/sa-123/application_keys")
    assert dd.headers[0]["DD-API-KEY"] == "api-xyz" and dd.headers[0]["DD-APPLICATION-KEY"] == "mgmt-abc"
    assert body["data"]["type"] == "application_keys"
    # The key is read with once before it is handed out, on a scope it carries.
    assert dd.calls[1][:2] == ("GET", "https://api.datadoghq.eu/api/v1/monitor?page=0&page_size=1")
    assert dd.headers[1]["DD-APPLICATION-KEY"] == "secret-kid-1" and len(dd.calls) == 2
    assert body["data"]["attributes"] == {"name": "bab-sherlock-202610301405", "scopes": dd_scopes(perms)}
    assert out.credential == {"dd_api_key": "api-xyz", "dd_app_key": "secret-kid-1", "dd_site": "datadoghq.eu"}
    assert out.handle == {"key_id": "kid-1"} and out.note == "application key scoped to the granted permissions"
    assert out.expires_at == m.now() + 3600  # capped at an hour whatever the tier asked
    # End deletes by id; a key already gone is fine.
    m.end(out.handle)
    assert dd.calls[-1][:2] == ("DELETE", "https://api.datadoghq.eu/api/v2/service_accounts/sa-123/application_keys/kid-1")
    assert dd.keys == {}
    m.end(out.handle)
    m.end({})
    assert len(dd.calls) == 4
    # Nothing scoped, nothing minted: an unscoped key would be the whole service account.
    with pytest.raises(MintError, match="names a Datadog scope"):
        m.mint("sherlock", "datadog", {}, [cat.action("aws_logs_read")], 3600)
    # Identity: the service account the owner created; probe: a key made and removed.
    assert m.identity() == {"subject": "sa-123", "site": "datadoghq.eu", "kind": "datadog_service_account"}
    out = m.probe()
    assert out["probe_key_id"] == "kid-2" and dd.keys == {}
    assert dd.calls[-2][2]["data"]["attributes"] == {"name": "bab-probe", "scopes": ["monitors_read"]}
    assert dd.calls[-1][0] == "DELETE"
    assert m.probe("sa-123")["subject"] == "sa-123"
    with pytest.raises(MintError, match="not sa-999"):
        m.probe("sa-999")


def test_a_datadog_key_is_held_until_datadog_answers_a_read_made_with_it():
    """Datadog refuses a new key for a moment (0.7 to 1.8 seconds, measured 2026-11-16), and a
    lease handed out inside it failed the agent's first call."""
    from bab.service.minters import DD_KEY_LATE_NOTE, DD_KEY_NOTE, DatadogMinter
    from tests.conftest import FakeDatadog

    cat = catalogue.load("catalogues/room.yaml")
    env = {"DD_SERVICE_ACCOUNT_ID": "sa-123", "DD_API_KEY": "api-xyz", "DD_MGMT_APP_KEY": "mgmt-abc"}

    def minter(dd):
        clock, slept = {"t": 0.0}, []

        def sleep(seconds):
            slept.append(seconds)
            clock["t"] += seconds

        return DatadogMinter.from_env(env, http=dd, sleep=sleep, clock=lambda: clock["t"]), slept

    def reads(dd):
        return [url.split("datadoghq.com")[1].split("?")[0] for method, url, _ in dd.calls if method == "GET"]

    # Refused three times, answered on the fourth read: handed out then, and not before.
    dd = FakeDatadog(slow=3)
    m, slept = minter(dd)
    out = m.mint("sherlock", "datadog", {}, [cat.action("datadog_monitors_read")], 3600)
    assert reads(dd) == ["/api/v1/monitor"] * 4 and slept == [0.2] * 3 and out.note == DD_KEY_NOTE
    assert all(h["DD-APPLICATION-KEY"] == "secret-kid-1" for h in dd.headers[1:])
    # The read is on a scope the key carries: events when it holds events and no monitors.
    dd = FakeDatadog()
    m, slept = minter(dd)
    m.mint("sherlock", "datadog", {}, [cat.action("datadog_events_read")], 3600)
    assert reads(dd) == ["/api/v1/events"] and slept == []
    # No scope there is a proven read for: held for the usual delay, and no read is made.
    dd = FakeDatadog()
    m, slept = minter(dd)
    out = m.mint("sherlock", "datadog", {}, [cat.action("datadog_dashboards_read")], 3600)
    assert reads(dd) == [] and slept == [2.5] and out.note == DD_KEY_NOTE
    # Never answered: the wait is bounded, and the key is handed out with a note, not lost.
    dd = FakeDatadog(slow=10_000)
    m, slept = minter(dd)
    out = m.mint("sherlock", "datadog", {}, [cat.action("datadog_monitors_read")], 3600)
    assert sum(slept) <= 6.0 and len(reads(dd)) == len(slept) + 1 > 20
    assert out.note == DD_KEY_LATE_NOTE and out.handle == {"key_id": "kid-1"} and "kid-1" in dd.keys


def test_datadog_minter_reports_datadogs_sentence_never_the_keys():
    from bab.service.minters import DatadogMinter, MintError
    from tests.conftest import FakeDatadog

    cat = catalogue.load("catalogues/room.yaml")
    m = DatadogMinter.from_env({"DD_SERVICE_ACCOUNT_ID": "sa-123", "DD_API_KEY": "api-xyz", "DD_MGMT_APP_KEY": "mgmt-abc"},
                               http=FakeDatadog(refuse="service_account_write is required"))
    with pytest.raises(MintError) as exc:
        m.mint("sherlock", "datadog", {}, [cat.action("datadog_monitors_read")], 3600)
    assert "HTTP 403 Forbidden service_account_write is required" in str(exc.value)
    assert "api-xyz" not in str(exc.value) and "mgmt-abc" not in str(exc.value)
    assert "api-xyz" not in repr(m.config()) and "mgmt-abc" not in repr(m.config())


def test_datadog_minter_reads_the_mounted_secret_on_every_call(monkeypatch, tmp_path):
    from bab.service.minters import DatadogMinter, MintError, NotConfigured, default_minters
    from tests.conftest import FakeDatadog

    for k in ("DD_SERVICE_ACCOUNT_ID", "DD_API_KEY", "DD_MGMT_APP_KEY", "DD_SITE"):
        monkeypatch.delenv(k, raising=False)
    # Always registered; nothing configured is the one sentence the room treats as "waiting".
    monkeypatch.setenv("BAB_DATADOG_DIR", str(tmp_path / "missing"))
    dd = default_minters()["datadog"]
    assert dd.name == "datadog" and dd.directory == str(tmp_path / "missing")
    with pytest.raises(NotConfigured, match="Datadog is not configured on the permission service yet: connect it under Admin > Integrations"):
        dd.identity()
    with pytest.raises(MintError, match="connect it under Admin > Integrations"):
        dd.probe()
    # No directory, environment set: a single-process run; a service account id alone is a refusal, not a boot failure.
    monkeypatch.setenv("DD_SERVICE_ACCOUNT_ID", "sa-env")
    with pytest.raises(MintError, match="DD_API_KEY and DD_MGMT_APP_KEY missing"):
        dd.identity()
    monkeypatch.setenv("DD_API_KEY", "api-env")
    monkeypatch.setenv("DD_MGMT_APP_KEY", "mgmt-env")
    assert dd.identity() == {"subject": "sa-env", "site": "datadoghq.com", "kind": "datadog_service_account"}
    # Files win over the environment, trailing newline and all (a Secret key mounted by Kubernetes).
    secret = tmp_path / "datadog"
    secret.mkdir()
    (secret / "DD_SERVICE_ACCOUNT_ID").write_text("sa-file\n")
    (secret / "DD_API_KEY").write_text("api-file\n")
    (secret / "DD_MGMT_APP_KEY").write_text("mgmt-file\n")
    (secret / "DD_SITE").write_text("datadoghq.eu\n")
    fake = FakeDatadog()
    m = DatadogMinter.from_dir(str(secret), env={"DD_SERVICE_ACCOUNT_ID": "sa-env", "DD_API_KEY": "api-env",
                                                 "DD_MGMT_APP_KEY": "mgmt-env"}, http=fake)
    assert m.identity() == {"subject": "sa-file", "site": "datadoghq.eu", "kind": "datadog_service_account"}
    m.probe()
    assert fake.calls[0][1] == "https://api.datadoghq.eu/api/v2/service_accounts/sa-file/application_keys"
    assert fake.last_headers["DD-API-KEY"] == "api-file" and fake.last_headers["DD-APPLICATION-KEY"] == "mgmt-file"
    # A rotated key is picked up on the next call, no restart; a removed Secret stops minting at once.
    (secret / "DD_MGMT_APP_KEY").write_text("mgmt-rotated\n")
    m.probe()
    assert fake.last_headers["DD-APPLICATION-KEY"] == "mgmt-rotated"
    for f in secret.iterdir():
        f.unlink()
    assert m.identity()["subject"] == "sa-env"  # the environment is the fallback behind an emptied directory
    with pytest.raises(NotConfigured):
        DatadogMinter.from_dir(str(secret), env={}, http=fake).identity()


DD_ENV = {"DD_SERVICE_ACCOUNT_ID": "sa-123", "DD_API_KEY": "api-xyz", "DD_MGMT_APP_KEY": "mgmt-abc"}
DD_KEYS_URL = "https://api.datadoghq.com/api/v2/service_accounts/sa-123/application_keys"


def test_with_a_key_store_an_agent_keeps_one_datadog_key_until_its_access_changes():
    """A key an hour per agent made Datadog write to its audit trail, and to the service
    account's owner, every hour. The lease is still the hour; the key is the agent's until
    what it may do changes, and a key whose access was taken is never handed out again."""
    from bab.service.minters import DD_STANDING_NOTE, DatadogMinter, MintError, dd_scopes
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys, clock = FakeDatadog(), FakeKeys(), {"now": datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp()}
    m = DatadogMinter.from_env(DD_ENV, http=dd, now=lambda: clock["now"], keys=keys)
    read = [cat.action("datadog_monitors_read")]
    first = m.mint_standing("sherlock", "datadog", {}, read, 7200)
    assert dd.keys == {"kid-1": {"name": "bab-sherlock", "scopes": ["mcp_read", "monitors_read"]}}
    assert first.note == DD_STANDING_NOTE and first.expires_at == clock["now"] + 3600
    record = keys.stored["datadog.sherlock"]
    assert (record["key_id"], record["key"], record["scopes"]) == ("kid-1", "secret-kid-1", ["mcp_read", "monitors_read"])
    assert (record["agent"], record["integration"], record["service_account_id"]) == ("sherlock", "datadog", "sa-123")
    # The lease ends and the key stands. The next hour's lease is the same key, and Datadog is not called.
    m.end(first.handle)
    clock["now"] += 3600
    calls = len(dd.calls)
    second = m.mint_standing("sherlock", "datadog", {}, read, 3600)
    assert (second.credential, second.handle) == (first.credential, first.handle) and len(dd.calls) == calls
    assert second.expires_at == first.expires_at + 3600
    # Another agent has its own; a lease made with `mint` is a key of its own and goes with the lease.
    assert m.mint_standing("watson", "datadog", {}, read, 3600).handle == {"key_id": "kid-2"}
    own = m.mint("sherlock", "datadog", {}, read, 3600)
    m.end(own.handle)
    assert set(dd.keys) == {"kid-1", "kid-2"}
    # More is granted: the key that carried the old set is deleted and the new one stored.
    both = read + [cat.action("datadog_metrics_read")]
    third = m.mint_standing("sherlock", "datadog", {}, both, 3600)
    assert set(dd.keys) == {"kid-2", "kid-4"} and dd.keys["kid-4"]["scopes"] == dd_scopes(both)
    assert keys.stored["datadog.sherlock"]["key_id"] == "kid-4"
    # Access is taken away: the key goes from Datadog and the store, with no lease asked for,
    # and the lease that carried it ends without another call.
    m.drop("sherlock", "datadog")
    assert set(dd.keys) == {"kid-2"} and set(keys.stored) == {"datadog.watson"}
    calls = len(dd.calls)
    m.end(third.handle)
    m.drop("sherlock", "datadog")
    m.drop("sherlock", "aws-prod")
    assert len(dd.calls) == calls
    # Datadog will not delete a key whose access was taken: it is never handed out again. The
    # next lease fails until the delete goes through, and then carries a new key.
    dd.keep = True
    m.drop("watson", "datadog")
    assert "kid-2" in dd.keys
    with pytest.raises(MintError, match="refused deleting application key kid-2"):
        m.mint_standing("watson", "datadog", {}, read, 3600)
    dd.keep = False
    assert m.mint_standing("watson", "datadog", {}, read, 3600).handle == {"key_id": "kid-5"}
    assert set(dd.keys) == {"kid-5"}
    # A store that will not take a key: the key is one lease's, as it was before there was a store.
    keys.broken = True
    lone = m.mint_standing("sherlock", "datadog", {}, read, 3600)
    assert "datadog.sherlock" not in keys.stored and lone.handle == {"key_id": "kid-6"}
    m.end(lone.handle)
    assert set(dd.keys) == {"kid-5"}
    # No store at all: `mint_standing` is `mint`.
    plain = DatadogMinter.from_env(DD_ENV, http=dd, now=lambda: clock["now"])
    assert dd.keys[plain.mint_standing("sherlock", "datadog", {}, read, 3600).handle["key_id"]]["name"].startswith("bab-sherlock-2026")


def test_a_restart_finds_the_kept_datadog_key_and_asks_datadog_before_trusting_it():
    """bab's ledger records leases, not secrets, so a restart would make every agent a new key.
    The store gives the key back, a minute or so behind what was last written to it."""
    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys = FakeDatadog(), FakeKeys()
    read = [cat.action("datadog_monitors_read")]
    first = DatadogMinter.from_env(DD_ENV, http=dd, keys=keys).mint_standing("sherlock", "datadog", {}, read, 3600)
    keys.deliver()
    m = DatadogMinter.from_env(DD_ENV, http=dd, keys=keys)
    # The lease from before the restart ends: its key is the kept one and stands. A key the
    # ledger holds and the store does not is deleted with its lease.
    dd.keys["kid-9"] = {"name": "bab-sherlock-202610301405", "scopes": ["mcp_read", "monitors_read"]}
    dd.accounts["kid-9"] = "sa-123"
    m.end(first.handle)
    m.end({"key_id": "kid-9"})
    assert set(dd.keys) == {"kid-1"}
    # The first lease after it asks Datadog, with the management key, whether the key is there. Once.
    calls = len(dd.calls)
    again = m.mint_standing("sherlock", "datadog", {}, read, 3600)
    assert (again.credential, again.handle) == (first.credential, first.handle)
    assert [x[:2] for x in dd.calls[calls:]] == [("GET", f"{DD_KEYS_URL}/kid-1")]
    assert dd.last_headers["DD-APPLICATION-KEY"] == "mgmt-abc"
    m.mint_standing("sherlock", "datadog", {}, read, 3600)
    assert len(dd.calls) == calls + 1
    # A stored key Datadog no longer has (deleted while the store lagged) is replaced, not handed out.
    del dd.keys["kid-1"]
    fresh = DatadogMinter.from_env(DD_ENV, http=dd, keys=keys).mint_standing("sherlock", "datadog", {}, read, 3600)
    assert fresh.handle == {"key_id": "kid-2"} and keys.stored["datadog.sherlock"]["key_id"] == "kid-2"
    # A key made on another service account is not this connection's to hand out. It is
    # deleted where it was made, so the service account that was left keeps nothing.
    keys.deliver()
    moved = DatadogMinter.from_env({**DD_ENV, "DD_SERVICE_ACCOUNT_ID": "sa-999"}, http=dd, keys=keys)
    assert moved.mint_standing("sherlock", "datadog", {}, read, 3600).handle == {"key_id": "kid-3"}
    assert keys.stored["datadog.sherlock"]["service_account_id"] == "sa-999"
    assert ("DELETE", "https://api.datadoghq.com/api/v2/service_accounts/sa-123/application_keys/kid-2", None) in dd.calls
    assert dd.accounts["kid-3"] == "sa-999" and set(dd.keys) == {"kid-3"}


def test_the_check_against_the_ledger_drops_the_key_it_judged_and_never_its_replacement():
    """A lease replacing a too-wide kept key and the ledger check judging that same key run at
    once. The check must drop the key it judged, not the correctly scoped one made meanwhile."""
    import threading

    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys = FakeDatadog(), FakeKeys()
    read = [cat.action("datadog_monitors_read")]
    both = read + [cat.action("datadog_metrics_read")]
    deleting, go = threading.Event(), threading.Event()

    def http(method, url, headers, body):
        if method == "DELETE" and not go.is_set():
            deleting.set()
            go.wait(10)
        return dd(method, url, headers, body)

    m = DatadogMinter.from_env(DD_ENV, http=http, keys=keys, sleep=lambda s: None,
                               now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp())
    old = m.mint_standing("sherlock", "datadog", {}, both, 3600).handle["key_id"]
    out = {}
    lease = threading.Thread(target=lambda: out.update(m=m.mint_standing("sherlock", "datadog", {}, read, 3600)))
    lease.start()
    assert deleting.wait(5)
    check = threading.Thread(target=lambda: m.settle("sherlock", "datadog", read))
    check.start()
    go.set()
    lease.join(10), check.join(10)
    new = out["m"].handle["key_id"]
    assert old not in dd.keys and new in dd.keys and keys.stored["datadog.sherlock"]["key_id"] == new
    assert m.holds(out["m"].handle) and not m.holds({"key_id": old})


def test_a_kept_key_the_mount_never_shows_is_asked_for_again_and_never_lost():
    """The store took a key and the delivery to the cluster never came. A process that cannot
    read a kept key never writes one, and only a write asked for the delivery: so reading the
    store's names asks again, and a revoke that cannot reach the key says so in the log. The
    key goes once the mount shows it."""
    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys = FakeDatadog(), FakeKeys()
    read = [cat.action("datadog_monitors_read")]

    def restart():
        return DatadogMinter.from_env(DD_ENV, http=dd, keys=keys, now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp())

    kept = restart().mint_standing("sherlock", "datadog", {}, read, 3600).handle["key_id"]
    m = restart()
    m.end(m.mint_standing("sherlock", "datadog", {}, read, 3600).handle)
    assert keys.redelivered == 1
    m.drop("sherlock", "datadog")
    assert keys.redelivered == 2 and kept in dd.keys
    keys.deliver()
    assert m.kept() == [("sherlock", "datadog")]
    m.settle("sherlock", "datadog", None)
    assert kept not in dd.keys and keys.stored == {}


def test_dropping_a_kept_key_never_raises_whatever_datadog_or_the_store_does():
    """`drop` runs inside revokes, approvals, disconnects and the ledger check. Whatever goes
    wrong reaching Datadog, the key stays marked, is never handed out, and goes on a later try."""
    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys = FakeDatadog(), FakeKeys()
    read = [cat.action("datadog_monitors_read")]
    broken = {"on": False}

    def http(method, url, headers, body):
        if broken["on"]:
            raise ValueError("a site that is not a host")
        return dd(method, url, headers, body)

    m = DatadogMinter.from_env(DD_ENV, http=http, keys=keys, now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp())
    lease = m.mint_standing("sherlock", "datadog", {}, read, 3600)
    broken["on"] = True
    m.drop("sherlock", "datadog")
    assert lease.handle["key_id"] in dd.keys and not m.holds(lease.handle)
    broken["on"] = False
    m.settle("sherlock", "datadog", read)
    assert dd.keys == {} and keys.stored == {}


def test_a_second_kept_datadog_key_is_never_made_while_the_first_may_still_stand():
    """Only its record knows a kept key's id, so a second key made for the same agent would leave
    the first in Datadog for good. Whenever the first may still stand where this process cannot
    see it, the lease gets a key of its own, which ends with the lease."""
    from bab.service.minters import DD_KEY_NOTE, DatadogMinter
    from tests.conftest import FakeDatadog, FakeKeys

    cat = catalogue.load("catalogues/room.yaml")
    dd, keys = FakeDatadog(), FakeKeys()
    read = [cat.action("datadog_monitors_read")]
    both = read + [cat.action("datadog_metrics_read")]

    def restart():
        return DatadogMinter.from_env(DD_ENV, http=dd, now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp(), keys=keys)

    def own_key(m, permissions=read, refused=0):
        """One lease that must not be, or replace, a kept key; it is ended, and its key with it.
        `refused`: how many times Datadog was asked for a key under the kept name."""
        before, record, asked = set(dd.keys), dict(keys.stored), len(dd.calls)
        lease = m.mint_standing("sherlock", "datadog", {}, permissions, 3600)
        made = set(dd.keys) - before
        assert made == {lease.handle["key_id"]} and lease.note == DD_KEY_NOTE
        assert [b["data"]["attributes"]["name"] for verb, _, b in dd.calls[asked:] if verb == "POST"].count("bab-sherlock") == refused
        assert dd.keys[lease.handle["key_id"]]["name"].startswith("bab-sherlock-2026") and keys.stored == record
        m.end(lease.handle)
        assert set(dd.keys) == before

    kept = restart().mint_standing("sherlock", "datadog", {}, read, 3600)
    # A restart before the store's copy is mounted: the store holds a key this process cannot read.
    m = restart()
    own_key(m)
    # The store does not answer, with its own error or any other.
    keys.broken = True
    own_key(m)
    keys.error = OSError("no token file")
    own_key(m)
    keys.broken = False
    # Mounted: the kept key again, and none was made in between.
    keys.deliver()
    assert m.mint_standing("sherlock", "datadog", {}, read, 3600).handle == kept.handle
    # After a restart Datadog will not say whether the key read back is still there: it is not handed out.
    m, dd.mute = restart(), True
    own_key(m)
    dd.mute = False
    assert m.mint_standing("sherlock", "datadog", {}, read, 3600).handle == kept.handle
    # More is granted, and bab restarts before the new key is mounted. The mount shows the old
    # one, which Datadog no longer has; Datadog refuses a second key under the name, and the
    # store's record is left alone.
    wide = m.mint_standing("sherlock", "datadog", {}, both, 3600)
    assert wide.handle != kept.handle and set(dd.keys) == {wide.handle["key_id"]}
    m = restart()
    own_key(m, both, refused=1)
    keys.deliver()
    assert m.mint_standing("sherlock", "datadog", {}, both, 3600).handle == wide.handle
    # A key the store would not take is one lease's, whatever the store raised.
    def refuse(name, record):
        raise OSError("no token file")

    put, keys.put = keys.put, refuse
    lone = m.mint_standing("watson", "datadog", {}, read, 3600)
    assert dd.keys[lone.handle["key_id"]]["name"] == "bab-watson" and "datadog.watson" not in keys.stored
    m.end(lone.handle)
    keys.put = put
    # An agent with a dot in its name has no kept key: `<integration>.<agent>` must split one way.
    dotted = m.mint_standing("eu.fred", "datadog", {}, read, 3600)
    assert set(keys.stored) == {"datadog.sherlock"}
    m.end(dotted.handle)
    # Two keys of their own for one agent in the same minute: Datadog keeps one key per name.
    a, b = m.mint("watson", "datadog", {}, read, 3600), m.mint("watson", "datadog", {}, read, 3600)
    assert a.handle != b.handle and dd.keys[b.handle["key_id"]]["name"].startswith(dd.keys[a.handle["key_id"]]["name"] + "-")
    m.end(a.handle), m.end(b.handle)
    assert set(dd.keys) == {wide.handle["key_id"]}


def test_the_key_store_is_the_secret_stores_machine_lane_and_a_mounted_secret(tmp_path):
    """bab and the secret store are released apart, and all that joins them is this: who is
    acting, a namespace, a path under apps/, one value per record, a delivery asked for once,
    and a last record that goes with its path because the store refuses to leave one empty."""
    from bab.service.keys import KeyStoreError, SeroKeys, sero_keys_from_env

    calls, held, answer = [], [], {"status": 200}

    def http(method, url, headers, body, params):
        assert headers["Authorization"] == "Bearer id-token-for-secrets-bab"
        calls.append((method, url.removeprefix("http://secrets:8000"), body or params))
        if method == "GET":
            return (200, {"keys": list(held), "version": 3}) if held else (404, {"detail": "there is no secret"})
        return answer["status"], {"blocked": []}

    keys = SeroKeys("http://secrets:8000/", "secrets-bab", "room", "bab@example.com", str(tmp_path),
                    token=lambda audience: f"id-token-for-{audience}", http=http)
    where = {"acting_email": "bab@example.com", "namespace": "room", "path": "apps/bab/datadog-keys"}
    assert keys.names() == set() and calls == [("GET", "/api/service/secrets", where)]
    del calls[:]
    keys.put("datadog.sherlock", {"key_id": "kid-1", "key": "s1"})
    assert calls == [
        ("POST", "/api/service/secrets", {**where, "values": {"datadog.sherlock": '{"key": "s1", "key_id": "kid-1"}'},
                                          "remove_keys": [], "apply": True}),
        ("POST", "/api/service/sync", {**where, "app": "bab", "name": "bab-datadog-keys", "target_name": "bab-datadog-keys",
                                       "refresh_interval": "1m", "apply": True})]
    keys.put("datadog.watson", {"key_id": "kid-2", "key": "s2"})
    assert len(calls) == 3  # delivery is asked for once
    # A mount that does not show the store asks again, at most once a minute.
    keys.redeliver()
    keys.redeliver()
    assert len(calls) == 4 and calls[-1][:2] == ("POST", "/api/service/sync")
    # One of two goes by name; the last goes with its path; one that is not there is nothing to do.
    del calls[:]
    held[:] = ["datadog.sherlock", "datadog.watson"]
    assert keys.names() == {"datadog.sherlock", "datadog.watson"}
    del calls[:]
    keys.remove("datadog.sherlock")
    assert calls == [("GET", "/api/service/secrets", where),
                     ("POST", "/api/service/secrets", {**where, "values": {}, "remove_keys": ["datadog.sherlock"], "apply": True})]
    del calls[:]
    held[:] = ["datadog.watson"]
    keys.remove("datadog.watson")
    keys.remove("datadog.nobody")
    held[:] = []
    keys.remove("datadog.watson")
    assert [c[:2] for c in calls] == [("GET", "/api/service/secrets"), ("DELETE", "/api/service/secrets"),
                                      ("GET", "/api/service/secrets"), ("GET", "/api/service/secrets")]
    assert calls[1][2] == {**where, "apply": True}
    # A refusal is an error that names the path and the status, never a value.
    answer["status"] = 403
    with pytest.raises(KeyStoreError, match="could not store datadog.sherlock at apps/bab/datadog-keys: the secret store answered HTTP 403"):
        keys.put("datadog.sherlock", {"key_id": "kid-1", "key": "s1"})
    with pytest.raises(KeyStoreError, match="cannot name a stored key"):
        keys.put("../etc", {})
    # A token source that fails in its own way (a token file that is not there) is the store not answering.
    def no_token(audience):
        raise FileNotFoundError("/var/run/token")

    with pytest.raises(KeyStoreError, match="no identity token for the secret store .FileNotFoundError."):
        SeroKeys("http://secrets:8000", "secrets-bab", "room", "bab@example.com", str(tmp_path), token=no_token, http=http).names()
    # bab names the namespace it runs in, so a delivery to anywhere it cannot mount is the store's refusal to log.
    answer["status"], there = 200, SeroKeys("http://secrets:8000", "secrets-bab", "room", "bab@example.com", str(tmp_path),
                                            token=lambda audience: f"id-token-for-{audience}", http=http, k8s_namespace="access")
    there.put("datadog.sherlock", {"key_id": "kid-1", "key": "s1"})
    assert calls[-1][:2] == ("POST", "/api/service/sync") and calls[-1][2]["k8s_namespace"] == "access"
    # What a restart reads: one file per record, as the cluster mounts a Secret.
    assert keys.all() == {} and keys.get("datadog.sherlock") is None
    (tmp_path / "datadog.sherlock").write_text('{"key_id": "kid-1", "key": "s1"}')
    (tmp_path / "datadog.torn").write_text('{"key_id": ')
    (tmp_path / "..data").mkdir()
    assert keys.all() == {"datadog.sherlock": {"key_id": "kid-1", "key": "s1"}} and keys.get("../etc") is None
    # A deployment names all of the store or none of it.
    env = {"BAB_SERO_URL": "http://secrets:8000", "BAB_SERO_AUDIENCE": "secrets-bab", "BAB_SERO_NAMESPACE": "room",
           "BAB_SERO_ACTING_EMAIL": "bab@example.com"}
    made = sero_keys_from_env(env, str(tmp_path), lambda audience: "t")
    assert (made.url, made.audience, made.namespace, made.acting_email, made.path) == (
        "http://secrets:8000", "secrets-bab", "room", "bab@example.com", "apps/bab/datadog-keys")
    assert sero_keys_from_env({**env, "BAB_SERO_AUDIENCE": " "}, str(tmp_path), lambda audience: "t") is None
    assert sero_keys_from_env({}, str(tmp_path), lambda audience: "t") is None


def test_every_datadog_permission_names_its_scopes():
    cat = catalogue.load("catalogues/room.yaml")
    scopes = {a.name: a.extra.get("scopes") for a in cat.for_vendor("datadog")}
    assert all(scopes.values()), scopes
    assert scopes["datadog_monitors_write"] == ["monitors_write"]
    assert scopes["datadog_metrics_read"] == ["metrics_read", "timeseries_query"]
    assert scopes["datadog_logs_read"] == ["logs_read_data"]
    assert scopes["datadog_incidents_read"] == ["incident_read"]
    assert scopes["datadog_rum_read"] == ["rum_apps_read"]
    assert not any("write" in s for a, ss in scopes.items() if a != "datadog_monitors_write" for s in ss)


def test_github_minter_narrows_an_installation_token_to_the_union(monkeypatch):
    from bab.service import minters as m_
    from bab.service.minters import GitHubMinter, MintError, gh_permissions
    from tests.conftest import FakeGitHub

    monkeypatch.setattr(GitHubMinter, "_jwt", lambda self, cfg: "app-jwt")
    cat = catalogue.load("catalogues/room.yaml")
    gh = FakeGitHub()
    now = datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp()
    m = GitHubMinter.from_env({"GITHUB_APP_ID": "4242", "GITHUB_APP_INSTALLATION_ID": "777",
                               "GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----"},
                              http=gh, now=lambda: now)
    assert "\\n" not in m.config().private_key and m.config().private_key.count("\n") == 2
    assert "abc" not in repr(m.config())
    # Union with write winning per permission; nothing named is nothing.
    perms = [cat.action("github_repos_read"), cat.action("github_pulls_write")]
    assert gh_permissions(perms) == {"actions": "read", "checks": "read", "contents": "write", "issues": "read",
                                     "metadata": "read", "pull_requests": "write"}
    assert gh_permissions([cat.action("github_pulls_review")])["pull_requests"] == "write"
    assert gh_permissions([cat.action("github_pulls_review")])["contents"] == "read"
    assert gh_permissions([]) == {}
    out = m.mint("sherlock", "github", {"repositories": ["infra", "web"]}, perms, 7200)
    method, url, body = gh.calls[0]
    assert (method, url) == ("POST", "https://api.github.com/app/installations/777/access_tokens")
    assert gh.headers[0]["Authorization"] == "Bearer app-jwt" and gh.headers[0]["X-GitHub-Api-Version"] == "2022-11-28"
    assert body == {"permissions": gh_permissions(perms), "repositories": ["infra", "web"]}
    assert out.credential == {"github_token": "ghs-1", "github_api_url": "https://api.github.com"}
    assert out.handle == {} and out.note == "installation token narrowed to the granted permissions and 2 repositories"
    assert out.expires_at == now + 3600  # the lease asked for two hours; an installation token is an hour
    # A console that stores the full name (owner/name) gets the same token: GitHub's
    # token API narrows by bare repository name, so the owner is dropped (a full name
    # sent through was a 422 "repository does not exist" for every lease, 2026-11-01).
    m.mint("sherlock", "github", {"repositories": ["acme/infra", "web"]}, perms, 7200)
    assert gh.calls[-1][2]["repositories"] == ["infra", "web"]
    # No repositories on the connection: the token sees what the installation sees, and says so.
    out = m.mint("sherlock", "github", {}, [cat.action("github_repos_read")], 600)
    assert "repositories" not in gh.calls[-1][2] and out.expires_at == now + 600
    assert out.note == "installation token narrowed to the granted permissions"
    m.end(out.handle)  # nothing to end, nothing called
    assert len(gh.calls) == 3  # the two narrowed mints and the whole-installation one
    with pytest.raises(MintError, match="names a GitHub App permission"):
        m.mint("sherlock", "github", {}, [cat.action("aws_logs_read")], 3600)
    # Identity is the app; the probe reads the installation, mints metadata-only, counts repositories.
    assert m.identity() == {"subject": "acme-room", "app_id": "4242", "installation_id": "777", "kind": "github_app"}
    out = m.probe()
    assert out == {"subject": "acme-room", "installation_id": "777", "account": "acme", "repositories": 3}
    assert gh.calls[-2][2] == {"permissions": {"metadata": "read"}}
    assert gh.headers[-1]["Authorization"] == "Bearer ghs-4"  # the fourth token the fake minted in this test
    assert m.probe("777")["account"] == "acme"
    with pytest.raises(MintError, match="not 778"):
        m.probe("778")
    assert m_.default_minters()["github"].name == "github"


def test_github_minter_reports_githubs_sentence_never_the_key_or_token(monkeypatch):
    from bab.service.minters import GitHubMinter, MintError, NotConfigured
    from tests.conftest import FakeGitHub

    monkeypatch.setattr(GitHubMinter, "_jwt", lambda self, cfg: "app-jwt")
    cat = catalogue.load("catalogues/room.yaml")
    m = GitHubMinter.from_env({"GITHUB_APP_ID": "4242", "GITHUB_APP_INSTALLATION_ID": "777", "GITHUB_APP_PRIVATE_KEY": "pem-secret"},
                              http=FakeGitHub(refuse="The permissions requested are not granted to this installation."))
    with pytest.raises(MintError) as exc:
        m.mint("sherlock", "github", {}, [cat.action("github_pulls_write")], 3600)
    assert "HTTP 422 The permissions requested are not granted to this installation." in str(exc.value)
    assert "pem-secret" not in str(exc.value) and "app-jwt" not in str(exc.value)
    with pytest.raises(NotConfigured, match="not configured"):
        GitHubMinter.from_env({}).config()
    with pytest.raises(MintError, match="half configured.*GITHUB_APP_PRIVATE_KEY missing"):
        GitHubMinter.from_env({"GITHUB_APP_ID": "4242", "GITHUB_APP_INSTALLATION_ID": "777"}).config()


def test_github_minter_reads_the_mounted_secret_on_every_call(tmp_path, monkeypatch):
    from bab.service.minters import GitHubMinter
    from tests.conftest import FakeGitHub

    monkeypatch.setattr(GitHubMinter, "_jwt", lambda self, cfg: "app-jwt")
    secret = tmp_path / "github"
    secret.mkdir()
    (secret / "GITHUB_APP_ID").write_text("4242\n")
    (secret / "GITHUB_APP_INSTALLATION_ID").write_text("777\n")
    (secret / "GITHUB_APP_PRIVATE_KEY").write_text("pem-file\n")
    (secret / "GITHUB_API_URL").write_text("https://github.acme.example/api/v3/\n")
    m = GitHubMinter.from_dir(str(secret), env={"GITHUB_APP_ID": "1", "GITHUB_APP_PRIVATE_KEY": "pem-env"}, http=FakeGitHub())
    cfg = m.config()
    assert (cfg.app_id, cfg.installation_id, cfg.private_key, cfg.api_url) == ("4242", "777", "pem-file", "https://github.acme.example/api/v3")
    (secret / "GITHUB_APP_INSTALLATION_ID").unlink()
    with pytest.raises(Exception, match="half configured"):
        m.config()


def test_github_minter_signs_a_real_app_jwt():
    """The one place the key is used for real: RS256 over iss/iat/exp, PyJWT[crypto]."""
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from bab.service.minters import GitHubMinter

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_key().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()).decode() if hasattr(key, "private_key") else \
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()).decode()
    m = GitHubMinter.from_env({"GITHUB_APP_ID": "4242", "GITHUB_APP_INSTALLATION_ID": "777", "GITHUB_APP_PRIVATE_KEY": pem},
                              now=lambda: 1_800_000_000.0)
    token = m._jwt(m.config())
    claims = jwt.decode(token, key.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims == {"iat": 1_800_000_000 - 60, "exp": 1_800_000_000 + 540, "iss": "4242"}


def test_github_is_three_nested_levels_with_labels():
    """Read < Review < Open: each level's app permissions are a superset of the one before, the
    two mutate rows are the only writes, and every row carries a label for the console."""
    cat = catalogue.load("catalogues/room.yaml")
    rows = {a.name: a for a in cat.for_vendor("github")}
    assert list(rows) == ["github_repos_read", "github_pulls_review", "github_pulls_write"]
    perms = {n: a.extra.get("permissions") for n, a in rows.items()}
    assert all(perms.values()), perms
    assert all("metadata" in p for p in perms.values()), "every token must be able to read repository metadata"
    writes = {n for n, p in perms.items() if any(v != "read" for v in p.values())}
    assert writes == {"github_pulls_review", "github_pulls_write"}
    assert perms["github_repos_read"] == {"metadata": "read", "contents": "read", "issues": "read", "pull_requests": "read",
                                          "checks": "read", "actions": "read"}
    assert perms["github_pulls_review"] == {**perms["github_repos_read"], "pull_requests": "write"}
    assert perms["github_pulls_write"] == {**perms["github_pulls_review"], "contents": "write"}
    assert [(a.tier, a.group, a.label) for a in rows.values()] == [
        ("read", "Repositories", "Read"), ("mutate", "Pull requests", "Review pull requests"),
        ("mutate", "Pull requests", "Open pull requests")]


def test_gcp_minter_impersonates_the_connections_service_account():
    from bab.service.minters import GcpMinter, MintError
    from tests.conftest import FakeGoogle

    cat = catalogue.load("catalogues/room.yaml")
    g = FakeGoogle()
    now = datetime(2026, 11, 1, 12, 0, tzinfo=UTC).timestamp()
    m = GcpMinter(http=g, now=lambda: now)
    sa = "reader@example-project.iam.gserviceaccount.com"
    out = m.mint("sherlock", "example-project", {"project": "example-project", "service_account": sa},
                 [cat.action("gcp_compute_read"), cat.action("gcp_vertex_ai_user")], 7200)
    # bab's own token first, from the metadata server; then generateAccessToken with it as bearer.
    assert g.calls[0] == ("GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", None)
    assert g.headers[0] == {"Metadata-Flavor": "Google"}
    method, url, body = g.calls[1]
    assert (method, url) == ("POST", f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken")
    assert body == {"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "3600s"}  # two hours asked, an hour is the cap
    assert g.headers[1]["Authorization"] == "Bearer own-1"
    assert out.credential == {"gcp_access_token": f"imp-2-{sa}", "gcp_project": "example-project"}
    assert out.expires_at == datetime(2026, 11, 1, 13, 0, tzinfo=UTC).timestamp()  # Google's expireTime, fraction and all
    assert out.handle == {}
    assert out.note == f"access token for {sa}; narrowing is bab's check only, the token carries the role pack"
    m.end(out.handle)
    assert len(g.calls) == 2  # nothing to end: Google cannot recall a token
    # Google's refusal is its sentence, never a token.
    refused = GcpMinter(http=FakeGoogle(refuse_impersonation="Permission 'iam.serviceAccounts.getAccessToken' denied"), now=lambda: now)
    with pytest.raises(MintError) as exc:
        refused.mint("sherlock", "example-project", {"project": "example-project", "service_account": sa}, [], 3600)
    assert f"Google refused a token for {sa}: HTTP 403 Permission 'iam.serviceAccounts.getAccessToken' denied" == str(exc.value)
    assert "own-" not in str(exc.value)
    with pytest.raises(MintError, match="is not a service account email"):
        m.mint("sherlock", "example-project", {"project": "example-project", "service_account": "not-an-email"}, [], 3600)


def test_gcp_minter_mints_babs_own_token_when_no_service_account_is_named():
    from bab.service.minters import GcpMinter, MintError
    from tests.conftest import FakeGoogle

    g = FakeGoogle()
    now = datetime(2026, 11, 1, 12, 0, tzinfo=UTC).timestamp()
    m = GcpMinter(http=g, now=lambda: now)
    out = m.mint("sherlock", "example-project", {"project": "example-project", "service_account": None}, [], 3600)
    assert len(g.calls) == 1 and g.calls[0][1].endswith("/service-accounts/default/token")
    assert out.credential == {"gcp_access_token": "own-1", "gcp_project": "example-project"}
    assert out.expires_at == now + 1800  # the metadata token ends in 30 minutes; the lease ends with it
    assert out.note == "access token for bab's own identity; narrowing is bab's check only, the token carries the role pack"
    assert m.mint("sherlock", "example-project", {"project": "example-project"}, [], 600).expires_at == now + 600
    with pytest.raises(MintError, match="names no Google Cloud project"):
        m.mint("sherlock", "example-project", {}, [], 3600)


def test_gcp_minter_identity_and_probe_name_the_identity_to_grant():
    from bab.service.minters import GcpMinter, MintError, Unreachable
    from tests.conftest import BAB_EMAIL, FakeGoogle

    g = FakeGoogle()
    m = GcpMinter(http=g, now=lambda: 1_800_000_000.0)
    assert m.identity() == {"subject": "1122334455", "email": BAB_EMAIL, "kind": "google_service_account"}
    assert g.calls[-1][1].endswith("/service-accounts/default/identity?audience=bab&format=full")
    # Probe with bab's own identity: one hop, the token it minted reads the project.
    out = m.probe(project="example-project")
    assert out == {"project": "example-project", "project_number": "123456789012", "subject": BAB_EMAIL, "hops": 1}
    assert g.calls[-1][1] == "https://cloudresourcemanager.googleapis.com/v1/projects/example-project"
    assert g.headers[-1]["Authorization"].startswith("Bearer own-")
    # Through a service account: two hops, and the impersonated token is what reads the project.
    sa = "reader@example-project.iam.gserviceaccount.com"
    out = m.probe(project="example-project", service_account=sa)
    assert out["hops"] == 2 and out["subject"] == sa
    assert g.headers[-1]["Authorization"].startswith("Bearer imp-")
    assert g.calls[-2][2]["lifetime"] == "600s"
    # 403 (Google's answer for "no such project" too) is one sentence naming the identity and the project, no token.
    with pytest.raises(MintError) as exc:
        m.probe(project="locked-project")
    assert str(exc.value) == (f"{BAB_EMAIL} has no access on project locked-project (or there is no such project): "
                              "grant it the role pack there, or on a folder or organization above it")
    assert "own-" not in str(exc.value)
    with pytest.raises(MintError, match="is not a Google Cloud project id"):
        m.probe(project="Not A Project")
    with pytest.raises(MintError, match="names a project, or a folder or organization"):
        m.probe()
    # A folder or organization probes as "can bab list its projects".
    assert m.probe(parent="folders/123") == {"parent": "folders/123", "projects": 3, "subject": BAB_EMAIL, "hops": 1}
    # A project that serves models: the same token then lists the project's own Vertex AI models in
    # the location (an empty page is fine; the publisher catalogue is not project-scoped and answers
    # 404 under a project), at a URL bab builds (regional host; the plain host for `global`), never
    # one a caller sends.
    out = m.probe(project="example-project", vertex_location="us-east5")
    assert out["vertex"] == {"location": "us-east5", "ok": True} and out["hops"] == 1
    assert g.calls[-1][1] == "https://us-east5-aiplatform.googleapis.com/v1/projects/example-project/locations/us-east5/models?pageSize=1"
    assert g.headers[-1]["Authorization"] == g.headers[-2]["Authorization"]  # the token that read the project
    m.probe(project="example-project", vertex_location="global")
    assert g.calls[-1][1].startswith("https://aiplatform.googleapis.com/v1/projects/example-project/locations/global/")
    with pytest.raises(Unreachable) as exc:
        m.probe(project="example-project", vertex_location="europe-west9")
    assert str(exc.value) == (f"{BAB_EMAIL} cannot reach Vertex AI in europe-west9 for project example-project: "
                              "HTTP 403 Permission 'aiplatform.models.list' denied")
    with pytest.raises(MintError, match="is not a Vertex AI location"):
        m.probe(project="example-project", vertex_location="https://evil.example/")


def test_gcp_minter_lists_the_active_projects_under_a_folder_or_organization():
    from bab.service.minters import GcpMinter, MintError, default_minters
    from tests.conftest import FakeGoogle

    g = FakeGoogle()
    m = GcpMinter(http=g)
    # The whole tree: the parent's own projects first (the deleted one dropped), then the
    # sub-folder's, each naming the folders between the parent and itself and its number.
    assert m.list_accounts("folders/123") == [
        {"id": "example-project", "name": "Example", "status": "ACTIVE", "project_number": "123456789012",
         "folder": "folders/123", "folder_path": []},
        {"id": "locked-project", "name": "Locked", "status": "ACTIVE", "project_number": "222",
         "folder": "folders/123", "folder_path": []},
        {"id": "nested-project", "name": "Nested", "status": "ACTIVE", "project_number": "777000111",
         "folder": "folders/777", "folder_path": ["Dev"]},
    ]
    # Two searches for the whole organization, not two calls per folder; a project under another
    # organization (Elsewhere) and the deleted project are left out.
    urls = [u.split("/v3/", 1)[1] for _, u, _ in g.calls if "/v3/" in u]
    assert urls == ["folders:search?pageSize=300",
                    "projects:search?pageSize=500",
                    "projects:search?pageSize=500&pageToken=page-2"]
    assert all(h["Authorization"] == "Bearer own-1" for h in g.headers[1:])
    with pytest.raises(MintError, match="is not a folder or organization"):
        m.list_accounts("example-project")
    assert default_minters()["gcp"].name == "gcp"


def test_gcp_minter_waits_out_a_rate_limit_and_gives_up_with_googles_sentence():
    """Gate (patience): Resource Manager answers 429 under load (a 100-folder tree on
    2026-11-09); bab pauses and asks again, three times, before it refuses."""
    from bab.service import minters as mod
    from bab.service.minters import GcpMinter, MintError

    class Flaky:
        def __init__(self, fail: int):
            self.fail, self.calls = fail, 0
        def __call__(self, method, url, headers, body):
            if "metadata.google.internal" in url:
                return 200, {"access_token": "own", "expires_in": 1800}
            self.calls += 1
            if self.calls <= self.fail:
                return 429, {"error": {"code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED"}}
            if "folders:search" in url:
                return 200, {"folders": []}
            return 200, {"projects": [{"name": "projects/1", "projectId": "one-project", "displayName": "One", "state": "ACTIVE", "parent": "folders/1"}]}

    m = GcpMinter(http=Flaky(fail=2)); naps = []; m.sleep = naps.append
    assert [p["id"] for p in m.list_accounts("folders/1")] == ["one-project"]
    assert naps == list(mod.GCP_RETRY_PAUSES_SEC[:2])
    m = GcpMinter(http=Flaky(fail=10)); m.sleep = lambda _s: None
    with pytest.raises(MintError, match="Google refused searching the folders: HTTP 429 Quota exceeded"):
        m.list_accounts("folders/1")


def test_gcp_minter_keeps_a_tree_for_two_minutes_and_reads_it_once_per_parent():
    """Gate (load): a console that asks twice, or retries, gets the kept answer; after the TTL
    Google is asked again. The kept list is copied out, so a caller cannot edit the cache."""
    from bab.service import minters as mod
    from bab.service.minters import GcpMinter
    from tests.conftest import FakeGoogle

    clock = [1000.0]
    g = FakeGoogle(); m = GcpMinter(http=g, now=lambda: clock[0])
    first = m.list_accounts("folders/123")
    n = len([u for _, u, _ in g.calls if "/v3/" in u])
    again = m.list_accounts("folders/123")
    assert again == first and len([u for _, u, _ in g.calls if "/v3/" in u]) == n
    again[0]["folder_path"].append("edited")
    assert m.list_accounts("folders/123")[0]["folder_path"] == []
    clock[0] += mod.GCP_TREE_TTL_SEC + 1
    m.list_accounts("folders/123")
    assert len([u for _, u, _ in g.calls if "/v3/" in u]) == 2 * n


def test_every_gcp_permission_names_its_roles_and_vertex_ai_is_the_one_user_role():
    cat = catalogue.load("catalogues/room.yaml")
    rows = {a.name: a for a in cat.for_vendor("gcp")}
    roles = {n: a.extra.get("roles") for n, a in rows.items()}
    assert all(roles.values()), roles
    assert len(rows) == 24
    vertex = rows["gcp_vertex_ai_user"]
    assert (vertex.tier, vertex.group, vertex.label) == ("read", "AI", "Use Vertex AI models")
    assert roles["gcp_vertex_ai_user"] == ["roles/aiplatform.user"]
    assert all(r.startswith("roles/") for rs in roles.values() for r in rs)
    not_viewer = {n for n, rs in roles.items() if any(not r.endswith(("viewer", "Viewer", "reader", "Reader", "browser")) for r in rs)}
    assert not_viewer == {"gcp_vertex_ai_user"}


def test_vertex_discovery_keeps_ga_chat_models_and_preview_only_where_a_family_has_nothing_ga():
    from bab.service.models import label_for, vertex_models
    from tests.conftest import VERTEX_ANTHROPIC, VERTEX_GOOGLE_PAGE1, VERTEX_GOOGLE_PAGE2

    listed = [("google", m) for m in VERTEX_GOOGLE_PAGE1 + VERTEX_GOOGLE_PAGE2] + [("anthropic", m) for m in VERTEX_ANTHROPIC]
    rows = vertex_models(listed)
    # GA chat text models only: embeddings, imagen, veo, tts, live audio, transcribe, nano-banana, bison, a
    # deploy-only gemma, the deprecated, the experimental and the preview rows of a family that has GA are
    # all gone; a repeat is one row.
    assert [r["id"] for r in rows] == ["claude-3-5-sonnet-v2", "claude-opus-4-1", "claude-sonnet-4-6",
                                       "gemini-2.0-flash-001", "gemini-2.5-flash", "gemini-2.5-pro"]
    assert {r["stage"] for r in rows} == {"GA"} and {r["via"] for r in rows} == {None}
    sonnet = next(r for r in rows if r["id"] == "claude-sonnet-4-6")
    assert sonnet == {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6", "publisher": "Anthropic",
                      "family": "claude", "stage": "GA", "via": None}
    assert next(r for r in rows if r["id"] == "gemini-2.5-pro")["label"] == "Gemini 2.5 Pro"
    assert next(r for r in rows if r["id"] == "claude-3-5-sonnet-v2")["label"] == "Claude 3.5 Sonnet v2"
    # A family with nothing GA keeps its public preview; private preview never shows.
    only_preview = [("google", {"name": "publishers/google/models/newfam-1.0-preview", "launchStage": "PUBLIC_PREVIEW",
                                "supportedActions": {"openGenerationAiStudio": {}}}),
                    ("google", {"name": "publishers/google/models/newfam-1.5", "launchStage": "PRIVATE_PREVIEW",
                                "supportedActions": {"openGenerationAiStudio": {}}})]
    assert [(r["id"], r["stage"]) for r in vertex_models(only_preview)] == [("newfam-1.0-preview", "PUBLIC_PREVIEW")]
    # No supportedActions at all (every current Gemini row): kept, the name decides; actions that
    # are deploy or notebook only: not something the room can call.
    assert [r["id"] for r in vertex_models([("google", {"name": "publishers/google/models/gemini-9-pro", "launchStage": "GA"})])] == ["gemini-9-pro"]
    assert vertex_models([("google", {"name": "publishers/google/models/gemini-9-pro", "launchStage": "GA",
                                      "supportedActions": {"deploy": {}, "openNotebook": {}}})]) == []
    assert label_for("llama-3-3-70b-instruct") == "Llama 3.3 70B Instruct"


def test_bedrock_discovery_maps_profile_only_models_to_the_regions_system_profile():
    from bab.service.models import bedrock_models, profile_for
    from tests.conftest import BEDROCK_MODELS, BEDROCK_PROFILES

    rows = {r["id"]: r for r in bedrock_models(BEDROCK_MODELS, BEDROCK_PROFILES, "us-east-1")}
    # Text output, ACTIVE, a chat name, served on demand or by a profile: image, speech, embedding,
    # rerank, provisioned-only, legacy and a profile-only model with no profile are gone.
    assert sorted(rows) == ["amazon.titan-text-express-v1", "anthropic.claude-3-haiku-20240307-v1:0",
                            "global.mistral.pixtral-large-2502-v1:0", "us.amazon.nova-pro-v1:0",
                            "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "us.deepseek.r1-v1:0"]
    # On demand when the model supports it, even if a profile exists too; the region's geo profile
    # is preferred over global and over another geo's; global when the geo has none.
    assert rows["anthropic.claude-3-haiku-20240307-v1:0"]["via"] == "on-demand"
    assert rows["us.anthropic.claude-sonnet-4-5-20250929-v1:0"] == {
        "id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "label": "Claude Sonnet 4.5", "publisher": "Anthropic",
        "family": "claude", "stage": "GA", "via": "inference-profile"}
    assert rows["global.mistral.pixtral-large-2502-v1:0"]["family"] == "pixtral"
    assert rows["us.deepseek.r1-v1:0"]["family"] == "deepseek" and rows["us.amazon.nova-pro-v1:0"]["family"] == "nova"
    assert profile_for("anthropic.claude-sonnet-4-5-20250929-v1:0", BEDROCK_PROFILES, "eu-west-1") == "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
    assert profile_for("amazon.nova-pro-v1:0", BEDROCK_PROFILES, "eu-west-1") == "us.amazon.nova-pro-v1:0"  # the one there is
    assert profile_for("meta.llama3-3-70b-instruct-v1:0", BEDROCK_PROFILES, "us-east-1") is None
    # Nothing listed in another region: an empty answer, not an error.
    assert bedrock_models([], [], "eu-west-1") == []


def test_aws_minter_lists_bedrock_through_the_hub_for_an_account_under_an_organization():
    from bab.service.minters import MintError
    from tests.conftest import BEDROCK_MODELS, BEDROCK_PROFILES

    hops, listed = [], []

    def assume(role_arn, token, name, seconds, policy):
        hops.append(("web-identity", role_arn, name, seconds, policy))
        return {"Credentials": {"AccessKeyId": "HUB", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2026, 10, 27, 13, 0, tzinfo=UTC)},
                "AssumedRoleUser": {"Arn": "arn:aws:sts::999999999999:assumed-role/BabHub/bab-models"}}

    def assume_role(creds, role_arn, name, seconds, policy, external_id):
        hops.append(("assume-role", creds["AccessKeyId"], role_arn, name, seconds, policy, external_id))
        return {"Credentials": {"AccessKeyId": "SPOKE", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2026, 10, 27, 13, 0, tzinfo=UTC)},
                "AssumedRoleUser": {"Arn": "arn:aws:sts::111111111111:assumed-role/BabSpoke/bab-models"}}

    def list_bedrock(creds, region):
        listed.append((creds["AccessKeyId"], region))
        return BEDROCK_MODELS, BEDROCK_PROFILES

    m = AwsMinter(token_source=lambda aud: "jwt", assume=assume, assume_role=assume_role, list_bedrock=list_bedrock)
    rows = m.list_models(region="us-west-2", hub_role_arn="arn:aws:iam::999999999999:role/BabHub",
                         spoke_role_arn="arn:aws:iam::111111111111:role/BabSpoke", external_id="x1")
    # The probe's shape: hub first with no policy, then the spoke with the external id; Bedrock is read as the spoke.
    assert hops[0][:3] == ("web-identity", "arn:aws:iam::999999999999:role/BabHub", "bab-models") and hops[0][4] is None
    assert hops[1] == ("assume-role", "HUB", "arn:aws:iam::111111111111:role/BabSpoke", "bab-models", 900, None, "x1")
    assert listed == [("SPOKE", "us-west-2")] and len(rows) == 6
    # A flat role is one hop; no role at all, or a bad region, never reaches AWS.
    m.list_models(role_arn="arn:aws:iam::123456789012:role/KoboAccess-Role")
    assert hops[-1][:2] == ("web-identity", "arn:aws:iam::123456789012:role/KoboAccess-Role") and listed[-1] == ("HUB", "us-east-1")
    with pytest.raises(MintError, match="names no IAM role"):
        m.list_models()
    with pytest.raises(MintError, match="is not an AWS region"):
        m.list_models(region="everywhere", role_arn="arn:aws:iam::123456789012:role/KoboAccess-Role")
