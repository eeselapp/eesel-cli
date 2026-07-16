# eesel CLI — capability-parity catalog

Platform-dashboard capabilities that the `eesel` CLI does **not** yet expose,
catalogued and ranked so an agent (or a person) can pull in the one a task
actually needs — one command at a time, not a big-bang parity push.

Each entry names the backend REST route the command would call and whether the
CLI can build it today. Routes were confirmed against the backend
(`eeselapp/slack`, commit `90df71d`, 2026-07-16). **Re-confirm the route before
you build** — the backend moves; treat the `file:line` citations as a starting
point, not a guarantee.

## Scope: the platform, not v2

The CLI targets the **platform** product — a *workspace* of *agents* with files,
skills, integrations, and tasks. eesel also has an older **v2** helpdesk surface
scoped by *namespace*, with its own dashboard (`v2/[id]/...`). This catalog lists
**platform** gaps only; v2/legacy features are not parity targets and are listed
under "Excluded" below so the reasoning is visible.

The rule for classifying a backend route: **scoped by `namespace_id`
(`/v2/namespaces/...`, `/simulation/<ns>/...`, `/learning/<ns>/...`,
`/<ns>/articles`) → v2/legacy.** Scoped by `workspace_id`, `agent_id`, or an
opaque `connection_id`/`integration_id` → platform. (An API-version prefix like
`/v2/sync-runs` is *not* the product-v2 — that route is workspace-scoped and the
CLI already uses it.)

## How to read a verdict

- **Buildable** — a REST route exists that the CLI can call with the bearer it
  already holds. The CLI ships an Auth0 access token from `eesel login` and uses
  it for every read/write today (that's how `files`, `billing`, `workspace`, and
  `tasks` work), so an `@requires_auth` route is not a blocker.
- **Buildable — human-gated** — buildable, but the blast radius is large and the
  CLI is presumed to be driven by an agent. Build it behind an explicit human
  confirmation, never a silent agent write.
- **Needs backend** — no bearer-callable REST route (signed link only,
  Stripe-hosted, or a sandbox-VM-only token). Server work comes first.

## Before you build any of these

Follow the existing conventions — do not invent new ones:

- Register the command in `build_parser` and add its endpoint to
  `_COMMAND_ENDPOINTS` so `eesel schema` documents it.
- Read with `http_request`, write with `write_request` (the single write choke
  point — it honours `--dry-run` for free). Emit through `emit(...)`, never a raw
  `print(json.dumps(...))`, so `--json`, `--fields`, NDJSON-when-piped, and
  secret redaction keep working.
- Tag every write subparser with `set_defaults(write=True)`; gate anything
  destructive behind `confirm(...)` / `--force`.
- Name a command after what the thing *is* to the user, not the REST verb behind
  it; on/off is a **property** shown by `list`, not its own command. See
  [CONTEXT.md](CONTEXT.md) for the full output contract.

---

## Buildable platform gaps (ranked by how central to operating a workspace)

| Rank | Capability | Current CLI state | Backend route | Suggested command |
|---|---|---|---|---|
| 1 | **Source path-settings** — configure what a connected source syncs (which categories / sub-paths / crawl scope). See the explainer below. | The CLI can `connect`/`sync`/`sync-status` an integration but can't set its sync scope. | Set config entry `POST /connections/<connection_id>/config-entry` (`connection_config.py:11`); read `GET /connections/<connection_id>/configuration` (`:23`). Changing it re-fires a sync. | `eesel integrations config` / `sources set` |
| 2 | **Sync stop / dismiss** | `integrations sync`/`sync-status`/`remove` only. | Stop `POST /v2/sync-runs/<run_id>/stop` (`integration_sync.py:228`); dismiss `POST /v2/sync-runs/<run_id>/dismiss` (`:286`). Both workspace-scoped (same route family the CLI's `sync-status` already reads). | `eesel integrations sync stop` / `sync dismiss` |
| 3 | **Document share / search** | `files list`/`read`/`export`/`add`/`remove` + `files acl`; no `share` or `search` verb. | Search `POST /documents/search` (`documents_v2.py:132`); share `POST /documents/by-id/<id>/share` (`:390`, mints a public read-only link). | `eesel files search` / `files share` |
| 4 | **Egress policy** — the agent's network-access allow-list (a platform *Settings → Network access* control). | Absent. | Read `GET /agents/<id>/egress-policies` (`sandbox_egress_policies.py:41`); add `POST .../egress-policies` (`:93`); remove `DELETE .../egress-policies` (`:112`). | `eesel agents egress list/add/remove` |
| 5 | **Skill authoring** — create/edit/delete a custom skill definition (distinct from attaching an existing skill, which the CLI already does). | `skills add`/`remove`/`set` attach existing skills to an agent. | Create `POST /custom-skills` (`skills/__init__.py:724`); list `GET /custom-skills` (`:774`); update `PUT /custom-skills/<id>` (`:793`); delete `DELETE /custom-skills/<id>` (`:837`). | `eesel skills author create/edit/remove` |

## Buildable — but human-gated (high blast radius; the CLI is agent-driven)

These are ordinary `@requires_auth` writes, so technically buildable — but each
changes who can access the workspace, what it's billed, or whether it exists.
Because the CLI is presumed to run unattended under an agent, build these only
behind an explicit human confirmation (interactive `confirm` that `--force`
alone can't satisfy in an agent context), not a silent write.

| Capability | Current CLI state | Backend route |
|---|---|---|
| **Team / member writes** — invite, change role, remove, transfer ownership | `workspace members` reads only. | Invite `POST /workspaces/<ws>/invite` (`workspace_access.py:16`); role `PUT /workspaces/<ws>/members/<uid>/role` (`:33`); remove `POST /workspaces/<ws>/remove-user` (`:115`); transfer ownership `POST .../transfer-ownership` (`:146`). |
| **Billing writes** — billing mode, billing email, checkout link | `billing show`/`list` (read-only); `workspace extend-trial` and `workspace set billing-limit` already exist. | Billing mode `PUT /subscription/billing-mode` (`subscription.py:257`); billing email `PUT /subscription/billing-email` (`:200`); checkout link `POST /subscription/checkout-session` (`:219`). |
| **Workspace delete** | `workspace show`/`set`/`members`/`extend-trial`; rename already exists (`workspace set name`). | Delete `DELETE /workspaces/<id>` (`workspace.py:57`). (Creation is auto-provision only — no explicit create route.) |

## Blocked on backend work

Skip these until the server side exists:

- **Approvals approve/reject** — a platform agent can pause a tool call for human
  approval, but the only routes (`GET /agents/tool-approvals/approve` /
  `reject`, `pending_invocations.py:52`/`:81`) are authorised by a signed JWT
  carried in an email/chat link, not a bearer token, and there is **no
  list-pending-approvals route**. A CLI can't enumerate or act on an approval by
  id. Needs a bearer-authenticated, id-addressable approve/reject **and** a list
  route.
- **Skill replay** — every route is `@vm_auth_required`
  (`skills/replay.py:154`), a sandbox-VM token with no mint path for an external
  caller.
- **Billing plan / seat / payment change** — happens on Stripe-hosted checkout /
  portal; only the inbound webhook exists server-side.

## Excluded — v2/legacy, not the platform product

Real dashboard features, but on the **v2** namespace surface — out of scope for a
platform CLI. Listed so the exclusion is a decision, not an oversight.

| Capability | Why excluded |
|---|---|
| **Conversation-sessions / History** (`GET /v2/namespaces/<ns>/sessions`, `messages.py:42`) | The v2 helpdesk conversation inbox — namespace-scoped transcripts of chats the legacy bot handled (dashboard "History", `v2/[id]/history-v2`). Not the same as a platform **task** (an agent's unit of work). The platform dashboard doesn't render it. |
| **Simulation** (`/simulation/<ns>/trigger`, `simulation.py:35`) | Namespace-scoped, Zendesk-only, living entirely in the v2 Zendesk knowledge flow (`v2/[id]/knowledge/priority/zendesk/simulation`). No platform simulation surface. |
| **Learning — tickets → knowledge** (`/learning/<ns>/...`, `learning.py:223`) | The v2 "learn from tickets" flow (`v2/[id]/knowledge/priority/zendesk/tickets/learning`). On the platform this isn't a dedicated feature — the agent learns through chat, not a batch job. |
| **Knowledge base / Articles page** (`GET /<ns>/articles`, `articles.py:29`) | The v2 namespace knowledge base. The platform expresses knowledge as files/documents in the agent's file tree (see the explainer), not an "Articles" page. |
| **Adhoc-sources** (`/namespaces/<ns>/adhoc-sources`, `adhoc_sources_api.py`) | The v2 knowledge-source manager. The platform equivalent is path-settings on a connection (row 1 above). |

## Not a gap — don't build

- **Agent enable/disable** — a route exists (`PUT /agents/<id>` with `is_active`),
  but on/off is a **property**, not a dashboard feature or a command. `agents
  list` already shows the on/off column. Per the CLI's own design rule, don't
  mint an `enable`/`disable` verb for a property; if it's ever wanted, it's a
  flag on `agents set`, not a new command.
- **Reports / analytics** — already the `tasks analytics` payload
  (`eesel tasks analytics`); the dashboard reports read the same data.
- **Developers / API-keys page** — a hardcoded UI stub with no backing endpoint;
  nothing to expose.
- **Prompt / instruction versioning** — doesn't exist in the dashboard either.

---

## Explainer: Knowledge vs Files

On the platform, an agent's knowledge is a single **file tree** (the sidebar
renders integrations, files, and outputs together). Content reaches it two ways:

- **Uploaded files** — things you add directly (a PDF, a markdown doc), via the
  workspace upload flow (`PlatformSidebar.tsx:52`, presigned upload →
  `asyncProcessWorkspaceUploadedFile`).
- **Synced documents** — content pulled from a connected integration (Google
  Drive, Notion, Confluence, a web crawl), refreshed by sync.

The CLI's `files` command is the **upload path** — the files you add directly.
Both kinds feed the same per-agent knowledge the agent reads, gated by a
per-agent knowledge ACL (what `files acl` manages). There is no separate
"knowledge base" object on the platform — "Knowledge base / Articles" is the
**v2** namespace concept (excluded above). So the platform gap here is narrow:
**search** and **share** verbs over the existing tree, not a new knowledge store.

## Explainer: Sources / Path settings

A connected integration is a knowledge **source**. Connecting it isn't the whole
story — you also choose *what subset of it to sync*. **Path settings** is that
control: for a given source you include/exclude categories or sub-paths and set
crawl scope (e.g. sync Help Center + Macros, skip Tickets; crawl only these URL
paths). The form is driven by the integration's own settings schema, and saving
it re-fires a sync because it changes which documents get pulled.

The CLI today can connect a source and trigger a sync, but can't set this scope —
so a sync pulls the source's default set. Closing the gap means a command over
`POST /connections/<connection_id>/config-entry` (row 1) that reads the source's
settings schema and writes the chosen include/exclude entries.
