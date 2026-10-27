"""Every job in the repo's own CI keeps fork PRs off the self-hosted runner."""

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
FORK_SAFE = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.head.repo.full_name != github.repository && "
    "'ubuntu-latest' || vars.CI_RUNNER || 'ubuntu-latest' }}"
)


def test_every_job_sends_fork_prs_to_a_hosted_runner():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert jobs
    for name, job in jobs.items():
        assert job["runs-on"] == FORK_SAFE, f"job {name!r} can reach the self-hosted runner"


def test_port_from_env_tolerates_kubernetes_service_links(monkeypatch):
    from bab.cli import _port_from_env

    monkeypatch.delenv("BAB_PORT", raising=False)
    assert _port_from_env() == 8080
    monkeypatch.setenv("BAB_PORT", "9000")
    assert _port_from_env() == 9000
    monkeypatch.setenv("BAB_PORT", "tcp://10.140.5.222:8080")
    assert _port_from_env() == 8080
