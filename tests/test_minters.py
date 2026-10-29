from datetime import UTC, datetime

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
