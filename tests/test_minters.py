from datetime import UTC, datetime

from bab import catalogue
from bab.service.identity import IdentityError, agent_from_username
from bab.service.minters import AwsMinter, session_policy


def test_session_policy_is_the_union_of_the_granted_permissions_iam_actions():
    cat = catalogue.load("catalogues/room.yaml")
    pol = session_policy([cat.action("aws_cloudtrail_read"), cat.action("aws_ecs_update_service")])
    assert pol["Statement"][0]["Action"] == ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:ListTrails",
                                             "cloudtrail:LookupEvents", "ecs:UpdateService"]
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
    assert calls[0][4]["Statement"][0]["Action"][0] == "cloudwatch:Describe*"
    assert out.credential["aws_access_key_id"] == "AKIA" and out.handle == {}


def test_agent_is_the_service_account_name():
    assert agent_from_username("system:serviceaccount:sherlock:sherlock") == ("sherlock", "sherlock")
    try:
        agent_from_username("kyle@example.com")
    except IdentityError:
        pass
    else:
        raise AssertionError("a person is not an agent")
