# Changelog

All notable changes to bab are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Connecting an integration a second time, or after a topology sync had already written its room link, returned 500.** OpenFGA refuses a write whose tuple already exists. `OpenFgaStore.write` now skips tuples already in the store and replaces one whose expiry changed, so a repeated connect or re-grant is harmless. Found on the first live lease in a dev room.

### Added

- A release workflow: a `vX.Y.Z` tag builds the multi-arch image (linux/amd64, linux/arm64), publishes it to ghcr under the tag and the short sha, and records the digest on the GitHub release. No image is built on a push to main.

### Changed

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
