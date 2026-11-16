# Changelog

All notable changes to bab are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **An agent keeps one Datadog application key, where bab has somewhere to keep it.** A lease
  was a new application key, so Datadog recorded a key made and a key deleted every hour for
  every agent, and told the service account's owner each time. Datadog's keys do not expire,
  and the hour was always bab's: the lease. So with a key store configured (below), an agent
  has one key per Datadog connection, named `bab-<agent>`, and each lease on everything it
  holds there hands out that same key. Nothing else about a lease changes: it is an hour, it
  is a row in the ledger, and when it runs out the next call asks for another. The key is
  deleted, and the next one made with the new scopes, when what the agent may do there
  changes: a permission approved, a grant revoked or lapsed, the agent removed, Datadog
  disconnected. A revoke still deletes the key in the agent's hand at once. A key Datadog
  refuses to delete at that moment is never handed out again, and the delete is tried again
  with the next lease. A lease that names its permissions (`permissions` on `POST /leases`)
  still gets a key of its own, deleted with the lease. The wait for Datadog to accept a new
  key (below) is now paid once per key, not once an hour.

  Without a key store nothing changes: a key per lease, as before. bab does not keep a
  secret in its ledger, and a key held only in memory would be remade for every agent at
  each restart, with the old ones left behind.

### Added
- **A key store: bab keeps a vendor key in the room's secret store (sero).** Four settings
  turn it on, all or none: `BAB_SERO_URL`, `BAB_SERO_AUDIENCE` (the audience sero's machine
  lane pins to bab's own identity; it needs one of its own, not another caller's),
  `BAB_SERO_NAMESPACE` (the namespace that caller is pinned to) and `BAB_SERO_ACTING_EMAIL`
  (the address sero records beside each write; no person is behind these writes, so name the
  service's own). bab writes each agent's key as one value at `apps/bab/datadog-keys`
  (`BAB_SERO_APP` renames the application) and asks sero once to deliver that path to its own
  namespace as the Secret `bab-datadog-keys`, re-read every minute. sero never returns a
  value, so bab reads its keys back from that Secret, mounted at `BAB_DATADOG_KEYS_DIR`
  (default `/etc/bab/datadog-keys`; mount it `optional: true`, it does not exist before the
  first key). bab only needs the mount after a restart. A key read from it is checked with
  Datadog once before it is handed out, because the mount lags a delete by about a minute.
  A key the store would not take is used for its one lease and deleted with it. A restart
  inside the minute after a key was made makes that agent a second key, and the first is
  deleted when its lease ends. One limit: a grant that lapses by its own date, on an agent
  that then never asks for a lease again, leaves its key in Datadog until the agent is
  removed, the grant is revoked, or Datadog is disconnected. This assumes one bab process,
  as the lease cache already does.

### Fixed
- **A Datadog lease is not handed out before Datadog accepts its key.** Datadog refuses a new
  application key for a moment after it creates it: measured from the service's own pod, five
  keys of five answered 403 for 0.7 to 1.8 seconds after the create returned, then 200, and
  never 403 again. A lease handed out inside that moment failed the agent's first call, and
  read as a missing permission. The minter now reads with the new key until Datadog answers
  200, then hands it out. The read is one the key's own scopes allow (`monitors_read`,
  `events_read` or `timeseries_query`); a key that carries none of those is held for 2.5
  seconds instead. The wait is bounded at 6 seconds. A key Datadog still has not accepted by
  then is handed out anyway, with a note on the lease and a warning in the log, so a slow
  Datadog never costs an agent its lease. A Datadog lease request now takes 1 to 3 seconds
  longer the first time in each hour; a caller that waits less than that on a lease should
  wait longer.

## [0.4.24] - 2026-11-16

### Added
- **Okta in the room catalogue.** A new service vendor, `okta`, with two levels:
  `okta_directory_read` (read tier, label "Look up people and groups") and
  `okta_access_write` (mutate tier, label "Change group membership and assignments").
  Nothing is minted for it: a room holds one API token for the org and its gateway opens
  the matching tools only to an agent granted the level. The token's own admin role in
  Okta is the outer wall.

## [0.4.23] - 2026-11-13

### Added
- **The room allows its own default.** A room that gives a newborn agent Read on its own
  repository asks for it as itself, with nobody there to click yes, and `POST /requests/decide`
  took an admin or security reviewer from every caller, so the default never landed. One
  caller on no team may now approve: the room, whose actor is `room@<BAB_ROOM>`
  (`Settings.room_actor`; no new setting), and only its own default. Every request in the batch
  must be pending, a level request (not a pick of repositories), raised by that same actor,
  made only of permissions the catalogue marks `room_default`, and on an agent's repository
  set: a child of a service connection that names its repositories, never the connection
  itself. Anything else in the batch, a denial included, refuses the whole batch with the 403
  every non-reviewer gets. The grant's `granted_by`, the request's `decided_by` and the
  `request.decided` event name the room, and the event carries `room_default: true`.
- **`room_default` in the catalogue.** An action may carry `room_default: true` (read tier
  only; anything else is a catalogue error). The room's catalogue sets it on
  `github_repos_read` and nothing else. `GET /catalogue/{vendor}` carries it on every
  permission.
- **`DELETE /agents/{agent}`: the room says an agent is gone.** Nothing removed what a
  departed agent held: its repository set, its grants on other integrations and its pending
  requests stayed behind, and a later agent of the same name would have inherited them. Like
  the topology, this is the room's own fact: the console token is the authority and the actor
  is recorded. It answers 409 while the topology still lists the agent. Otherwise it revokes
  every active grant the agent holds on any integration and deletes the tuples, ends the
  credentials it has in hand where the vendor allows, withdraws its pending requests, removes
  its repository set (`<connection>-<agent>`) and its `agents` integration with the grants on
  it, and writes one `agent.removed` event. A set another agent still holds a level on, or is
  waiting for one on, is kept and named under `kept`. The answer is
  `{agent, grants_revoked, requests_withdrawn, integrations_removed, tuples_deleted,
  leases_ended, removed, kept}`; calling it again answers zeros.

### Fixed
- **A missing integration is 404 whoever asks.** `DELETE /integrations/{id}` ran the reviewer
  gate before looking for the row, so a caller on no team got 403 for a row that was not
  there and could not tell "already gone" from "not yours". A row that exists still takes a
  reviewer (or is an `agents` row).

## [0.4.22] - 2026-11-12

### Fixed
- **An agent's owner can pick its repositories.** `PUT /integrations/{id}` took an admin or
  security reviewer for every vendor but `agents`, so a console that lets an agent's owner pick
  the repositories the agent may reach (a set under the GitHub connection) was refused for
  anyone not on those teams. A caller on no team may now write that one shape: a child of a
  service connection whose spec names its `repositories`, for a vendor whose credential is
  narrowed by them (GitHub). Picking grants nothing; the level is still asked for and decided
  by a reviewer, who sees the set. An empty set stays a reviewer's (it would be the whole
  connection), and of such a write the repositories alone are taken: an existing set keeps its
  ceiling and the rest of its spec, a new one starts with the repositories only.
- **Naming the `agents` vendor no longer opens another vendor's row.** Any actor may write an
  `agents` integration, and the check read the vendor from the request, so a caller on no team
  could re-describe any integration as an `agents` one and then delete it. The lane is now for
  rows that are, or are about to be, `agents` rows.
- **Disconnecting an integration takes back what waited on it.** Requests still pending on a
  deleted integration are marked `withdrawn`, so none can be approved onto a row that later
  takes the same name.

### Added
- **A repository added to a set that carries grants waits for a reviewer.** Once an agent
  holds a level on its set, or has asked for one a reviewer has yet to decide, an owner's pick
  is split: what it removes leaves the set at once, and what it adds becomes one request of
  kind `repositories` (`proposal: {added, removed}`; `permissions` the levels held or asked
  for on the set, read again each time the request is listed and frozen when it is decided, so
  the reviewer sees what the new repositories would be reached with). The `PUT` answers 202 with the set as it stands and the request under
  `pending`; picking again replaces what waits, and saving the set without the addition (or a
  reviewer writing the set) marks it `withdrawn`. `POST /requests/decide` applies an approved
  one to the set; a denial leaves it. `GET /requests` rows carry `proposal` (null on a
  permission request). The `requests` table gains a `proposal` column at boot.
- **A changed set reaches the agent on its next call.** Writing a set that carries grants, or
  approving an addition to it, drops the credential cached for it, so the next lease is minted
  for the new set instead of the old one being handed out until its hour ran out.

## [0.4.21] - 2026-11-12

### Fixed
- **A new grant replaces the credential in hand.** Approving a request now ends what the agent
  holds on that integration, the way a revoke always has (Datadog deletes the key; the cached
  credential is dropped), and the decide answer carries `leases_ended`. Before, a credential
  minted with two permissions stayed in use beside a grant of two more: an agent granted
  metrics a few minutes after its first Datadog call kept answering 403 until the hour ran out.
  A tool gateway that holds a lease for its whole hour still has to ask again to see the new
  one: `POST /leases/for-agent` answers the lease in hand while the grants stand, so asking
  every few seconds is cheap.

## [0.4.20] - 2026-11-09

### Changed
- **Google Cloud discover** no longer probes each project after the tree search: `projects:search`
  lists only what bab's identity may read, so every project it returns is reachable by
  construction. Probing 737 projects one by one took minutes and tripped Resource Manager's
  rate limit, which marked readable projects "not granted" in the console. AWS discover still
  probes each account through the hub (that is the only way to know the spoke role exists).

## [0.4.19] - 2026-11-09

The Google Cloud tree is read in two searches, not two calls per folder: the 0.4.18 walk of
a hundred-folder tree hit Resource Manager's rate limit and held bab's workers until its
liveness probe killed the pod.

### Changed
- **`GcpMinter.list_accounts`** reads `projects:search` and `folders:search` once each (paged)
  and assembles the tree under the parent itself; a project whose folders bab cannot see is
  left out. A 429 or 5xx is retried after 1, 2 and 4 seconds, then refused with Google's
  sentence. The answer is kept two minutes per parent and one read runs per parent at a
  time, so a console that asks twice does not ask Google twice. `GCP_TREE_DEPTH` and
  `GCP_TREE_FOLDERS` are gone with the walk.

## [0.4.18] - 2026-11-09

A Google Cloud folder's projects, the whole tree down, so a console can offer them for
picking instead of connecting every project the identity can read (tenishai/kobo, the
project picker).

### Changed
- **`GcpMinter.list_accounts`** walks the tree under a folder or organization: Resource
  Manager v3 `folders.list` and `projects.list` per folder (both in roles/browser), at most
  `GCP_TREE_DEPTH` (10) folders down and `GCP_TREE_FOLDERS` (500) folders in all, deleted
  folders never entered, active projects only. Each project now carries `project_number`,
  `folder` (the resource it sits in) and `folder_path` (the display names of the folders
  between the connected parent and the project, the parent excluded), and the list is sorted
  by that path, then by name. `GET /integrations/{org}/accounts`, `POST
  /integrations/{org}/discover` and a parent probe (`projects` count) answer for the tree.
  Nothing changes for AWS.

### Added
- A deploy contract: `gojira.yaml`, `k8s/base` (bab's service account and OpenFGA, pinned by digest, migrating its Postgres schema before every start) and `k8s/cluster/tokenreview.yaml`, so Gojira, or the stack installer's published-image path, deploys bab and its store together. The Datadog and GitHub minters load as optional env Secrets; an install without one runs without that vendor.
- The room catalogue's first Atlassian writing level, `atlassian_jira_issues_write` (mutate tier, label "Write issues"): create and edit issues, add comments and move issues between statuses. A room's gateway opens the matching tools only to an agent granted it.

## [0.4.17] - 2026-11-02

The room's Models pane: which chat models each connected cloud offers, so an admin ticks the
ones New agent shows (tenishai/kobo#405, section C).

### Added

- **`GET /integrations/{integration}/models`** (console auth, admin or security team, the
  discover route's gate): the chat models a connected cloud offers, listed with the identity
  the probes use. The answer is `{"integration", "provider", "models", "fetched_at"}` with
  `provider` `vertex_ai` or `bedrock` and a row `{"id", "label", "publisher", "family",
  "stage", "via"}`. A Google Cloud row lists Vertex AI's publisher models (google and
  anthropic) from the global endpoint, the one that lists them, billed to the row's Vertex
  project (`spec.models.project`, then `spec.identity.project`, then `spec.project`) through
  `x-goog-user-project`; `location` (default global, or the row's `spec.models.location`)
  is checked and kept for the console, since the listing has no location. Kept: launch stage
  GA, or PUBLIC_PREVIEW only when a family has nothing GA; no `supportedActions` (every
  current Gemini row) or a generate-type one among them (deploy- or notebook-only rows go); a
  chat text name (embedding, imagen, veo, tts, gecko, bison, codey and the image, video,
  speech, transcribe and translate names go). `id` is the bare name (`claude-sonnet-4-6`), `via`
  null. An AWS row lists Bedrock's models in `region` (default us-east-1) through its role,
  assumed briefly with no policy the way a probe does (through the hub for an account under
  an organization): `ListFoundationModels` cut to output TEXT, lifecycle ACTIVE, a chat name
  and ON_DEMAND (`id` = the model id, `via` on-demand) or INFERENCE_PROFILE (`id` = the
  region's system profile from `ListInferenceProfiles`, `us.<modelId>` in us-east-1, `via`
  inference-profile; no profile, dropped). `family` is a best-effort grouping from the name
  (claude, gemini, llama, nova, ...), `label` a readable name. A vendor that is not a cloud
  with models is 501; an organization row with no role, or a Google Cloud row naming no
  Vertex project, is 409; the vendor refusing is 502 with its own sentence. The pure filters
  live in `bab/service/models.py`; `GcpMinter.list_models` and `AwsMinter.list_models` make
  the vendor calls.

## [0.4.16] - 2026-11-02

### Fixed
- The Vertex AI probe at connect lists the project's own models (`projects/{p}/locations/{l}/models`) instead of the publisher catalogue under a project, which Google answers with 404; every Google Cloud connect with the models tick failed on it.

## [0.4.15] - 2026-11-01

Google Cloud, the way the room's cloud-access design describes it: bab's own identity is
granted, a lease is a token for it (kobo `docs/superpowers/specs/2026-10-25-cloud-access-design.md`,
"GCP, the way Wiz does it").

### Added

- **Google Cloud minter.** A `gcp` integration is a project (`spec.project`, kind `account`),
  flat or under an organization row that names a folder or organization (`spec.parent_resource`
  = `folders/<n>` or `organizations/<n>`, kind `org`). An admin grants bab's own service account
  the role pack on the project, folder or organization; a lease is then a fresh access token for
  that identity from the metadata server (workload identity, the same source as the AWS web
  identity token), capped at the token's own expiry and the hour. When the project's spec names
  a `service_account`, bab impersonates it instead (`generateAccessToken`, `cloud-platform`
  scope, lifetime at most an hour) and the lease carries that narrower identity's roles. The
  credential is `{gcp_access_token, gcp_project}`; the note says `access token for <who>;
  narrowing is bab's check only, the token carries the role pack`, because Google has no
  session policy and the console must say so. `end` is a no-op: Google cannot recall a token.
  `GET /identity/gcp` is bab's service account (`email`, `subject` = its unique id);
  `POST /probe/gcp {project, service_account?}` mints once and reads the project with Resource
  Manager (a 403 is one sentence naming the identity and the project; `{parent}` instead asks
  whether bab can list a folder's or organization's projects; `vertex_location` then lists Vertex
  AI's publisher models there with the same token, `vertex: {location, ok}` in the answer or a
  502 saying the identity cannot reach Vertex AI in that location; the Vertex URL is built by bab
  from the location and the project, and a `vertex_url` in the body is accepted but never
  fetched, since the probe presents a token for bab's identity); `GET /integrations/{org}/accounts`
  and `POST /integrations/{org}/discover` list the active projects directly under the folder or
  organization and mark the ones bab's identity can already read. Nothing is mounted or stored.
- **`gcp_vertex_ai_user`** in the room catalogue (tier read, group AI, label "Use Vertex AI
  models", `roles/aiplatform.user`): the role pack for a project that also serves models
  includes it. The other 23 Google Cloud rows are unchanged.

### Changed

- **`POST /probe/{vendor}`, `GET /integrations/{org}/accounts` and `POST /integrations/{org}/discover`
  take every vendor's shape.** The probe body carries every vendor's fields (`role_arn`,
  `audience`, `hub_role_arn`, `external_id` for AWS; `project`, `service_account`, `parent` for
  Google Cloud) and each minter is handed the ones its `probe` accepts; a field it requires and
  did not get is a 422 naming it (an AWS probe without `role_arn` was a 409 before). An
  organization's accounts are listed with the vendor's own parent (`hub_role_arn` for AWS,
  `parent_resource` for Google Cloud) and discover probes each account the vendor's way: the
  AWS lane still builds `arn:aws:iam::<account>:role/<role_name>` and needs the organization's
  external id; the Google Cloud lane probes `project=<id>` and needs neither. A vendor whose
  minter lacks the method still answers 501. `GET /integrations` rows carry `project` and, on an
  organization, `parent_resource`.

## [0.4.14] - 2026-11-01

### Fixed

- **A GitHub lease narrowed to a repository set works when the console stores full names.**
  GitHub's installation-token API narrows by bare repository name; a set stored as
  `owner/name` (the room's picker) was sent through as is and GitHub answered 422
  "repository does not exist" on every lease. The minter now drops the owner.

## [0.4.13] - 2026-11-01

The room's audit reads what agents did with their connections (tenishai/kobo#371, section 3).

### Added

- **`GET /events`** (console auth): the ledger's events, newest first, with `since`, `until`
  (exclusive), `kind` (repeatable or a comma list), `agent` (reads `detail.agent`) and `limit`
  (default 200, at most 1000). A row is `{"id", "at", "kind", "actor", "detail"}`. A mint
  still writes no event; a console reads mints from `GET /leases`.

### Changed

- **Every `lease.refused` and `lease.failed` row names the agent and the integration in
  `detail`**, with the `permissions` asked for and a `reason` (`not granted`, the borrowing
  sentence, or the minter's). A lease the agent holds nothing for, and one asked for
  permissions it does not hold, are now recorded as `lease.refused` too (they were a bare 403);
  a 202 with permissions waiting for approval is not a refusal and writes nothing.

## [0.4.12] — 2026-11-01

GitHub as three levels, a repository set per agent under the one connection, and a lease
that finds it (tenishai/kobo#365, section "bab").

### Changed

- **The GitHub catalogue is three nested levels.** `github_repos_read` ("Read": code, issues,
  pull requests, checks and workflow runs), `github_pulls_review` ("Review pull requests":
  Read plus `pull_requests: write`) and `github_pulls_write` ("Open pull requests": Review plus
  `contents: write`). Each level's app permissions are a superset of the one before.
  `github_actions_read` is folded into Read; `github_repos_delete` is gone. A catalogue row
  may now carry a `label`, and `GET /catalogue/{vendor}` returns it on every permission
  (`null` where a row has none) so a console can show a name instead of the identifier.
- **A child may hang under a service connection.** `PUT /integrations/{id}` accepts a
  `parent` that is an organization (as before) or a service connection with no parent of its
  own, one level deep; a parent that itself has a parent is a 422, and the vendor must still
  match. Children keep kind `account`, so `GET /integrations` lists a repository set
  (`github-<agent>`, spec `repositories`) under the `github` connection the way a spoke lists
  under its hub; the listing now carries `repositories` too. Disconnecting a parent with
  children stays a 409.

### Added

- **A lease asked for by the parent's name lands on the agent's own child.** `POST
  /leases/for-agent` (and the agent's own `POST /leases`) with an integration the agent holds
  no active grant on, which is the parent of exactly one child the agent does hold a grant on,
  leases that child: the minter narrows the token to the child's `repositories`, the row and
  the live cache are the child's, and the response says `resolved_from`. Two or more such
  children are a 409 that names them; no grant anywhere is the existing 403. The gateway asks
  for `github`; the agent's repository set is `github-<agent>`.

## [0.4.11] - 2026-10-31

The release of the GitHub minter. 0.4.10 was tagged on a commit that still declared
0.4.9, so the tag guard refused it and no image was published; 0.4.11 is the same code
with the version declared.


## [0.4.10] - 2026-10-31

### Added

- **GitHub minter** (#49, kobo#338 vendor 1). A lease on a `github` integration is a GitHub App
  installation token narrowed to the union of the granted permissions' `extra.permissions`
  (write wins over read per permission) and, when the connection's spec names
  `repositories`, to those repositories; it lives at most an hour on GitHub's clock, so bab
  keeps no handle and `end` is a no-op. bab reads the app id, one installation id, the
  private key and an optional API URL on every call from the mounted Secret
  (`BAB_GITHUB_DIR`, default `/etc/bab/github`) or the environment, as the Datadog minter
  does. `GET /identity/github` names the app; `POST /probe/github` reads the installation,
  mints a metadata-only token and counts the repositories it can see. The catalogue's GitHub
  rows now carry the app permissions each needs, plus a new `github_actions_read`.


## [0.4.9] - 2026-10-30

### Changed

- **Every Datadog lease can be used through Datadog's MCP server.** The scoped application key a lease mints now carries `mcp_read` next to the granted permissions' scopes, and `mcp_write` as well when a granted permission is a mutate; Datadog's hosted MCP server admits a key only with those, on top of the resource permission each tool needs. The resource scopes still decide what the key may touch, so a read-only lease stays read-only there too. A lease whose permissions name no scope is still refused. The service account's own role must hold `mcp_read` (and `mcp_write`) for a key to carry them, and the organization must have MCP Access enabled; both are the console's connect instructions.

## [0.4.8] - 2026-10-30

### Fixed

- **The Datadog minter reads its configuration on every call, from a mounted Secret.** It read `DD_SITE`, `DD_API_KEY`, `DD_MGMT_APP_KEY` and `DD_SERVICE_ACCOUNT_ID` from the environment at boot, so before a restart Datadog was absent (`501`) and after one it held stale keys for good; a console that writes the Secret on connect and probes at once was refused and undid its own connect. Now the minter is always registered and resolves those four values per call from the files of the same names under `BAB_DATADOG_DIR` (default `/etc/bab/datadog`, one file per Secret key, trailing newline stripped), each falling back to the environment variable of the same name. Nothing configured answers `409` with `Datadog is not configured on the permission service yet: connect it under Admin > Integrations` on `POST /probe/datadog` and `GET /identity/datadog` (a lease keeps its lane: `502 no lease: <that sentence>`, recorded as `lease.failed`); a service account id without both keys is refused the same way at call time, no longer a boot failure. A connect, a key rotation or a disconnect takes effect on the next call, no restart.

## [0.4.7] - 2026-10-30

### Added

- **Datadog leases: a scoped application key per lease, deleted when the lease ends.** A `DatadogMinter` is registered when the bab pod names a service account (`DD_SERVICE_ACCOUNT_ID`, with `DD_API_KEY`, `DD_MGMT_APP_KEY` and `DD_SITE`, default `datadoghq.com`). A lease creates an application key on that service account named `bab-<agent>-<yyyymmddhhmm>`, scoped to the union of the granted permissions' `extra.scopes`, for at most an hour; the credential is `{dd_api_key, dd_app_key, dd_site}`, the handle the key id. Every Datadog permission in the room catalogue now carries its scopes (`monitors_read`, `metrics_read` + `timeseries_query`, `logs_read_data`, ..., `monitors_write` for the one mutate). A lease whose permissions name no scope is refused: an unscoped key would be the whole service account. `GET /identity/datadog` is the service account; `POST /probe/datadog` creates and deletes a key named `bab-probe` (the body's `role_arn` may be omitted, or carry the service account id for bab to confirm). Without `DD_SERVICE_ACCOUNT_ID` nothing changes: a Datadog lease still answers 501.
- **The tool gateway may lease for the agent it is serving.** `POST /leases/for-agent` `{agent, integration, permissions?, task?}` takes the gateway's own pod identity (the same TokenReview path agents use; `BAB_GATEWAY_SERVICE_ACCOUNT` = `<namespace>/<service account>`, e.g. `liminal/liminal`), refuses every other identity with 403 (501 while no gateway is named), and then runs exactly the checks `POST /leases` runs for the named agent, sharing its live credential. The lease row and `GET /leases` carry `via: "gateway"`. On this lane a 403 is always one plain sentence naming the agent and the integration (nothing held, a permission not held, or an agent the topology does not know) and a 404 is only an integration that is not connected; `on_behalf_of` is refused here too.

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
