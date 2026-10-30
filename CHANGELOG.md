# Changelog

All notable changes to bab are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Datadog leases: a scoped application key per lease, deleted when the lease ends.** A `DatadogMinter` is registered when the bab pod names a service account (`DD_SERVICE_ACCOUNT_ID`, with `DD_API_KEY`, `DD_MGMT_APP_KEY` and `DD_SITE`, default `datadoghq.com`). A lease creates an application key on that service account named `bab-<agent>-<yyyymmddhhmm>`, scoped to the union of the granted permissions' `extra.scopes`, for at most an hour; the credential is `{dd_api_key, dd_app_key, dd_site}`, the handle the key id. Every Datadog permission in the room catalogue now carries its scopes (`monitors_read`, `metrics_read` + `timeseries_query`, `logs_read_data`, ..., `monitors_write` for the one mutate). A lease whose permissions name no scope is refused: an unscoped key would be the whole service account. `GET /identity/datadog` is the service account; `POST /probe/datadog` creates and deletes a key named `bab-probe` (the body's `role_arn` may be omitted, or carry the service account id for bab to confirm). Without `DD_SERVICE_ACCOUNT_ID` nothing changes: a Datadog lease still answers 501.
- **The tool gateway may lease for the agent it is serving.** `POST /leases/for-agent` `{agent, integration, permissions?, task?}` takes the gateway's own pod identity (the same TokenReview path agents use; `BAB_GATEWAY_SERVICE_ACCOUNT` = `<namespace>/<service account>`), refuses every other identity with 403 (501 while no gateway is named), and then runs exactly the checks `POST /leases` runs for the named agent, sharing its live credential. The lease row and `GET /leases` carry `via: "gateway"`; an agent the topology does not know is 404; `on_behalf_of` is refused here too.

### Changed

- **A lease that has run out is ended at the vendor, not only at the sweep.** Every lease request first ends the leases past their expiry whose minter can (Datadog deletes the key; AWS left no handle), and a revoke ends the leases the agent still holds on that integration (`DELETE /grants/{id}` answers `leases_ended`), so the next call mints afresh, narrower, or gets nothing. `POST /sweep` ends whatever is left; a vendor's refusal is recorded as `lease.end_failed` and retried next time.

## [0.4.6] - 2026-10-30

### Fixed

- An `agents` integration is the room's own fact: `PUT` and `DELETE /integrations/{agent}` for that vendor take the console token from any actor, the way the topology push does, so the room registers its agents at boot as itself. Every other vendor still takes an admin or security reviewer.

## [0.4.5] - 2026-10-30

### Added

- **Talking to another team's agent is a permission; a consulted agent never borrows a credential.** The room catalogue gains an `agents` vendor ("Other agents"): one integration per agent (id = the agent's name) with one read permission, `a2a_ask`, which the asker's owner requests and a reviewer approves like any other. `GET /agents/{agent}/talks-to` lists the agents it holds an active, ungated `a2a_ask` on, for the switchboard to build its dispatch pairs from grants. Nothing is ever minted for this vendor: a lease on an `agents` integration is a 409 ("talking is granted, not leased"). As a second wall behind the runtime's, `POST /leases` takes `on_behalf_of` (the agents whose task the lease would serve) and refuses any lease that names one with a 403 ("a credential is never borrowed for another agent's task"), recorded in the ledger as `lease.refused`.

## [0.4.4] - 2026-10-29

### Added

- **One external id per organization, and discover.** An organization's row may carry `external_id`; a spoke connected without one of its own leases with the organization's, so one spoke template deploys the role to every member account. `POST /integrations/{org}/discover` lists the accounts through the hub and probes each active one for the spoke role (`role_name`, default `KoboAccess-Role`) with that id, eight at a time, and says which are reachable, which are connected, and why the rest are not. The listing carries an organization's external id.

## [0.4.3] - 2026-10-29

### Changed

- **A live credential is handed back, not minted again.** `POST /leases` returns the credential already minted for the same agent, integration and permissions while it has more than two minutes left (`reused: true`), after checking the grants as always. A runtime may therefore ask on every call, which is what makes a revoke stop the next call: the grant check fails, and a revoke also drops the held credential. One lease row per mint, as before.

## [0.4.2] - 2026-10-29

### Fixed

- **Connecting an account with a full ceiling returned 500.** Registering an integration writes a ceiling tuple per permission per team, more than the 100 operations OpenFGA allows in one write once the catalogue has forty read permissions. Writes and deletes go in batches of 100 now.

## [0.4.1] - 2026-10-29

### Changed

- `GET /integrations` carries an organization row's `hub_role_arn` (not a secret; a console renders the trust a member account's role must carry from it).

## [0.4.0] - 2026-10-29

### Added

- **Organizations and their accounts (hub and spoke).** An AWS integration may be an organization: its row holds a hub role in the management account that bab assumes with its own identity. Accounts connect under it (`parent`) with a spoke role and an external ID; a lease on an account is two hops, the second carrying the session policy and the agent's name, which the member account's CloudTrail records. One hub per organization; a second organization is a second row, never a cross-organization assume. `GET /integrations/{org}/accounts` lists the organization's accounts through the hub, each marked connected or not; `POST /probe/{vendor}` takes `hub_role_arn` and `external_id` to try a spoke; `GET /integrations` carries `kind` (org, account, connection), `parent`, `name` and `account_id`. A lease on an organization row is refused; an organization with accounts under it cannot be disconnected. Flat connections (one role bab assumes directly) keep working unchanged.

## [0.3.2] - 2026-10-29

### Added

- `GET /identity/{vendor}`: who bab is to that vendor (for AWS, the `sub` an account owner writes into a role's trust policy). `POST /probe/{vendor}` (reviewer): try a role once before saving a connection; AWS's refusal comes back as a 409 with its sentence. `DELETE /integrations/{id}` (reviewer): disconnect, revoking every active grant on it and removing every tuple that named it.

### Changed

- **Faster release builds.** The lockfile export runs once on the build host instead of once per target architecture, and unchanged layers come from a registry cache (`ghcr.io/tenishai/bab:buildcache`). The image's contents do not change.

## [0.3.1] - 2026-10-29

### Added

- **Vendors have a kind.** The catalogue's `vendors:` map says whether a vendor is a `cloud` (connected one account, project or subscription at a time, with the unit named: `account`, `project`, `subscription`) or a `service` (one connection whose read capabilities its own API or MCP server exposes). `GET /catalogue` lists vendors with kind, label and permission counts; `GET /catalogue/{vendor}` carries them too.
- **One read permission per cloud service.** The room catalogue offers AWS by service (EC2, S3, RDS, IAM, CloudTrail, ...; 40 entries), Google Cloud by service (viewer roles; 23) and Azure by area (built-in reader roles; 8), plus the read capabilities of Datadog (13) and Atlassian (9). The cloud-access bundles stay under "Bundles" for grants that already name them.

### Changed

- **The AWS session policy denies data-plane reads.** Every minted session carries a Deny for object bodies, secret and parameter values, table items, queue messages, stream records, query result rows and decryption, whatever a permission's IAM list says. A read permission is configuration and listings.
- `aws_cloudtrail_read` now covers trails, event history and Lake queries; `aws_cloudtrail_lake_query` (0.3.0) is folded into it.

## [0.3.0] - 2026-10-29

### Fixed

- **Connecting an integration a second time, or after a topology sync had already written its room link, returned 500.** OpenFGA refuses a write whose tuple already exists. `OpenFgaStore.write` now skips tuples already in the store and replaces one whose expiry changed, so a repeated connect or re-grant is harmless. Found on the first live lease in a dev room.

### Added

- Catalogue: `aws_cloudtrail_lake_query` (read tier), the CloudTrail Lake query actions an auditing agent needs; the existing `aws_cloudtrail_read` covers LookupEvents and trail metadata only.

- `PUT /topology` (console): the room pushes its agents and teams. Each agent may name the pod identity that is it (`namespace`, `service_account`); bab resolves a lease caller through that mapping, so a pod whose service account is `agent-ledger` leases as the agent `ledger`, and a pod the topology does not name is refused (#18). A team that appears after an integration was connected gets that integration's ceiling, the same tuples connect writes. `GET /agents` lists what was pushed; `GET /integrations` lists what is connected and each ceiling.

- A release workflow: a `vX.Y.Z` tag builds the multi-arch image (linux/amd64, linux/arm64), publishes it to ghcr under the tag and the short sha, and records the digest on the GitHub release. No image is built on a push to main.

### Changed

- The topology sync owns the `team` and `owner` relations only. It no longer writes or deletes the level under the root (`room` -> `integration`): that link is written when a person connects an integration, and a sync that also owned it deleted connected integrations on its next run (#19).
- The image is pinned end to end: base image by digest, Python packages from `uv.lock` (new) with hashes verified by pip, the fga CLI by version.

## [0.2.0] - 2026-10-27

bab becomes the permission authority for agents: permissions are requested, approved,
recorded, leased and audited here. Design: `docs/design-leases.md`.

### Added

- **Grants expire.** The generated model defines the one condition `grant_window`
  and every grant relation accepts `agent with grant_window`; every check passes
  `current_time`, so a grant written with an expiry stops answering yes at that instant.
  `bab/grants.py` is the one writer of grant tuples (ceiling-checked) and `sweep` tidies
  expired ones. Catalogue actions take `group`, `vendor` and `extra`; a `tiers` block sets
  lease length and grant validity per tier (read 1 h and standing, mutate 1 h and 30 days,
  destroy 30 min and 7 days).
- **`bab serve`**, the HTTP service (`[service]` extra): `PUT /integrations/{id}` (connect
  and set the ceiling), `POST`/`GET /requests`, `POST /requests/decide` (bulk; admin or
  security team, destroy tier needs security), `GET /agents/{agent}/grants`,
  `DELETE /grants/{id}`, `POST /leases` (agent token only; mints for the granted subset,
  turns gated permissions into a one-hour request), `GET /leases`, `POST /check`,
  `POST /sweep`, `GET /catalogue/{vendor}`. Agents are verified by TokenReview or JWKS;
  the console by a shared token plus the signed-in person.
- **Ledger** (integrations, requests, grants, leases, events) in a `bab` PostgreSQL
  database; SQLite only for tests and laptops.
- **AWS minter**: `AssumeRoleWithWebIdentity` with bab's own Google identity token, the
  agent in the session name, a session policy built from the granted permissions.
- At boot the service finds or creates its OpenFGA store by name and writes the model
  from the catalogue (the image carries the `fga` CLI). `bab sweep` on the CLI.
- `catalogues/room.yaml`: a room-shaped catalogue (room → integration).

## [0.1.0] - 2026-10-27

Increment one as built in September 2026: the catalogue, the generated model with
ceilings, `Door.decide` (allow / approve / deny, fail-closed), the write-time ceiling
check, identity and topology syncs, the CLI and the demo.
