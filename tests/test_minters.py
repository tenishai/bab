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
    assert m.probe(parent="folders/123") == {"parent": "folders/123", "projects": 2, "subject": BAB_EMAIL, "hops": 1}
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
    assert m.list_accounts("organizations/456") == [{"id": "example-project", "name": "Example", "status": "ACTIVE"},
                                                     {"id": "locked-project", "name": "Locked", "status": "ACTIVE"}]
    urls = [u for _, u, _ in g.calls if "/v3/projects" in u]
    assert urls == ["https://cloudresourcemanager.googleapis.com/v3/projects?parent=organizations/456&pageSize=500",
                    "https://cloudresourcemanager.googleapis.com/v3/projects?parent=organizations/456&pageSize=500&pageToken=page-2"]
    assert all(h["Authorization"] == "Bearer own-1" for h in g.headers[1:])
    with pytest.raises(MintError, match="is not a folder or organization"):
        m.list_accounts("example-project")
    assert default_minters()["gcp"].name == "gcp"


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
