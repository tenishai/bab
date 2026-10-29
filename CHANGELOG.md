# Changelog

All notable changes to bab are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
