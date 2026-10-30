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
    m = DatadogMinter("sa-123", "api-xyz", "mgmt-abc", site="datadoghq.eu", http=dd,
                      now=lambda: datetime(2026, 10, 30, 14, 5, tzinfo=UTC).timestamp())
    perms = [cat.action("datadog_metrics_read"), cat.action("datadog_monitors_read"), cat.action("datadog_security_read")]
    assert dd_scopes(perms) == ["metrics_read", "monitors_read", "security_monitoring_rules_read",
                                "security_monitoring_signals_read", "timeseries_query"]
    out = m.mint("sherlock", "datadog", {}, perms, 7200)
    method, url, body = dd.calls[0]
    assert (method, url) == ("POST", "https://api.datadoghq.eu/api/v2/service_accounts/sa-123/application_keys")
    assert dd.last_headers["DD-API-KEY"] == "api-xyz" and dd.last_headers["DD-APPLICATION-KEY"] == "mgmt-abc"
    assert body["data"]["type"] == "application_keys"
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
    assert len(dd.calls) == 3
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


def test_datadog_minter_reports_datadogs_sentence_never_the_keys(monkeypatch):
    from bab.service.minters import DatadogMinter, MintError, default_minters
    from tests.conftest import FakeDatadog

    cat = catalogue.load("catalogues/room.yaml")
    m = DatadogMinter("sa-123", "api-xyz", "mgmt-abc", http=FakeDatadog(refuse="service_account_write is required"))
    with pytest.raises(MintError) as exc:
        m.mint("sherlock", "datadog", {}, [cat.action("datadog_monitors_read")], 3600)
    assert "HTTP 403 Forbidden service_account_write is required" in str(exc.value)
    assert "api-xyz" not in str(exc.value) and "mgmt-abc" not in str(exc.value)
    # Registered only when the pod names a service account; absent otherwise (datadog leases answer 501).
    for k in ("DD_SERVICE_ACCOUNT_ID", "DD_API_KEY", "DD_MGMT_APP_KEY", "DD_SITE"):
        monkeypatch.delenv(k, raising=False)
    assert set(default_minters()) == {"aws"}
    monkeypatch.setenv("DD_SERVICE_ACCOUNT_ID", "sa-123")
    with pytest.raises(SystemExit, match="DD_API_KEY and DD_MGMT_APP_KEY missing"):
        default_minters()
    monkeypatch.setenv("DD_API_KEY", "a")
    monkeypatch.setenv("DD_MGMT_APP_KEY", "b")
    dd = default_minters()["datadog"]
    assert dd.name == "datadog" and dd.site == "datadoghq.com" and dd.service_account_id == "sa-123"


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
