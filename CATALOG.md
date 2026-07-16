# eesel CLI — capability-parity catalog

Dashboard capabilities that the `eesel` CLI does **not** yet expose, catalogued
and ranked so an agent (or a person) can pull in the one a task actually needs —
one command at a time, not a big-bang parity push.

Each entry names the backend REST route the command would call, whether the CLI
can build it today, and a suggested command shape. Routes were confirmed against
the backend (`eeselapp/slack`, commit `90df71d`, 2026-07-16). **Re-confirm the
route before you build** — the backend moves; treat the `file:line` citations as
a starting point, not a guarantee.

## How to read a verdict

- **Buildable** — a REST route exists that the CLI can call with the bearer it
  already holds. The CLI ships an Auth0 access token from `eesel login` and uses
  it for every read/write today (that is how `files`, `billing`, `workspace`,
  and `tasks` already work), so an `@requires_auth` route is not a blocker.
- **Needs backend** — the capability has no bearer-callable REST route: it is
  reachable only through a signed email/chat link, a Stripe-hosted page, or a
  sandbox-VM-only token. A CLI command can't be built without server work first.

## Before you build any of these

Follow the existing conventions — do not invent new ones:

- Register the command in `build_parser` and add its endpoint to
  `_COMMAND_ENDPOINTS` so `eesel schema` documents it.
- Read with `http_request`, write with `write_request` (the single write choke
  point — it honours `--dry-run` for free). Emit through `emit(...)`, never a
  raw `print(json.dumps(...))`, so `--json`, `--fields`, NDJSON-when-piped, and
  secret redaction all keep working.
- Tag every write subparser with `set_defaults(write=True)` and gate anything
  destructive behind `confirm(...)` / `--force`.
- The cleanest on/off precedent to copy is the `mcp enable`/`mcp disable` block
  in `cmd_mcp`. See [CONTEXT.md](CONTEXT.md) for the full output contract.

---

## Tier 1 — the automation-blocking four (build first if a loop needs one)

These block an agent from operating a workspace end-to-end unattended. Three are
buildable now; approvals needs backend work first.

| Capability | Current CLI state | Backend route | Auth | Verdict | Suggested command |
|---|---|---|---|---|---|
| **Agent enable/disable** | `agents list`/`show` display the on/off flag; no verb to change it. Creation hardcodes on. | `PUT /agents/<id>` with body `{"is_active": bool}` — `server/app/api/agents/agents.py:323`; field on `EeselAgentUpdate` (`agent_schema.py:29`). The repo's `exclude_unset` means sending only `is_active` updates just that field. | `@requires_auth` | **Buildable** — the exact route `agents set` already calls. | `eesel agents enable` / `eesel agents disable` |
| **Simulation run + results** | Absent. | Trigger `POST /simulation/<namespace_id>/trigger?product=<p>` (`simulation.py:35`); list `GET /namespace/<ns>/simulations` (`:52`); status `GET /simulation/<id>` (`:63`); results `GET /simulation/<id>/results` (`:92`). | `@requires_auth` + namespace permission | **Buildable.** Caveat: the trigger currently supports **Zendesk only** and needs the HELPDESK entitlement — other products raise `Unsupported product`. | `eesel simulation run` / `eesel simulation results <id>` |
| **Conversation-sessions read** | Absent as backend data. The CLI's `sessions` command reads only **local** on-disk chat sessions; `tasks` returns agent *task* records, not end-user transcripts. | List `GET /v2/namespaces/<ns>/sessions` (`messages.py:42`); transcript `GET /v2/namespaces/<ns>/sessions/<id>` (`:95`). | `@requires_auth` + namespace permission | **Buildable.** Note the name clash: `sessions` is taken by local CLI sessions, so use a distinct noun (e.g. `conversations`). | `eesel conversations list` / `eesel conversations show <id>` |
| **Approvals approve/reject** | Absent. | Approve `GET /agents/tool-approvals/approve`, reject `GET /agents/tool-approvals/reject` (`pending_invocations.py:52`/`:81`). | **None** — authorised only by a signed JWT carried in the email/chat link, not a bearer token. No list-pending-approvals route exists. | **Needs backend** — a CLI can't enumerate pending approvals or act on one by id. Requires a bearer-authenticated, id-addressable approve/reject route **and** a list route first. | — (blocked) |

---

## Tier 2 — the rest, ranked by how central to operating a workspace

All routes below are `@requires_auth` and callable with the CLI's existing token
unless noted.

| Rank | Capability | Current CLI state | Backend route | Verdict | Suggested command |
|---|---|---|---|---|---|
| 1 | **Team / member writes** | `workspace members` reads only. | Invite `POST /workspaces/<ws>/invite` (`workspace_access.py:16`); change role `PUT /workspaces/<ws>/members/<uid>/role` (`:33`); remove `POST /workspaces/<ws>/remove-user` (`:115`); revoke invite `POST .../revoke-invite` (`:101`); transfer ownership `POST .../transfer-ownership` (`:146`). | **Buildable** | `eesel workspace invite` / `members remove` / `members role` |
| 2 | **Learning (tickets → knowledge)** | Absent. | Initialise `POST /learning/<ns>/initialise` (`learning.py:223`); enqueue `POST /learning/<ns>/enqueue` (`:40`) or workspace-wide `POST /learning/enqueue` (`:81`); status `GET /learning/<ns>/status` (`:135`). | **Buildable** | `eesel learning run` / `learning status` |
| 3 | **Knowledge articles** | Absent (distinct from `files` uploads). | Create `POST /<ns>/articles/create` (`articles.py:14`); list `GET /<ns>/articles` (`:29`); update `PATCH /<ns>/articles/<id>` (`:156`); delete `DELETE /<ns>/articles/<id>` (`:182`). | **Buildable** | `eesel articles list/create/remove` |
| 4 | **Sources / path-settings** | Absent. | Adhoc source config `PUT /namespaces/<ns>/adhoc-sources/<id>` (`adhoc_sources_api.py:239`, create `:177`, list `:107`); connection include/exclude `POST /connections/<id>/config-entry` (`connection_config.py:11`); crawl URLs `POST /namespaces/<ns>/urls` (`dashboard_api.py:133`). | **Buildable** | `eesel sources list/set` |
| 5 | **Sync stop / dismiss** | `integrations sync`/`sync-status`/`remove` only. | Stop `POST /v2/sync-runs/<id>/stop` (`integration_sync.py:228`); dismiss `POST /v2/sync-runs/<id>/dismiss` (`:286`); list `GET /v2/sync-runs` (`:148`). | **Buildable** | `eesel integrations sync stop`/`dismiss` |
| 6 | **Egress policy** | Absent. | Add `POST /agents/<id>/egress-policies` (`sandbox_egress_policies.py:93`); remove `DELETE .../egress-policies` (`:112`); read `GET .../egress-policies` (`:41`). | **Buildable** | `eesel agents egress list/add/remove` |
| 7 | **Billing writes** | `billing show`/`list` (read-only). Two config writes already exist: `workspace extend-trial` and `workspace set billing-limit`. | Still-missing config writes are buildable: billing mode `PUT /subscription/billing-mode` (`subscription.py:257`); billing email `PUT /subscription/billing-email` (`:200`); checkout link `POST /subscription/checkout-session` (`:219`, returns a Stripe URL). | **Partial** — those config writes are buildable; the actual **plan / seat / payment-method change happens on Stripe's hosted checkout/portal**, which has no bearer-callable mutation (**needs backend**). | `eesel billing set-mode` / `billing checkout` |
| 8 | **Workspace lifecycle** | `workspace show`/`set`/`members`/`extend-trial`. Rename already exists (`workspace set name` → `PUT /workspaces/<id>`). | Delete `DELETE /workspaces/<id>` (`workspace.py:57`). Creation is auto-provision only (`GET /workspaces` → `get_or_create_default_workspace`, `:20`); there is no explicit create route. | **Buildable** (delete only; rename already shipped, no explicit create) | `eesel workspace delete` |
| 9 | **Document share / search** | `files list`/`read`/`export`/`add`/`remove` + `files acl`; no `share` or `search` verb. | Share `POST /documents/by-id/<id>/share` (`documents_v2.py:390`, mints a public `share_id`); search `POST /documents/search` (`:132`). | **Buildable** | `eesel files share` / `files search` |
| 10 | **Skill authoring** | `skills add`/`remove`/`set` attach existing skills to an agent. | Custom-skill CRUD: create `POST /custom-skills` (`skills/__init__.py:724`); list `GET /custom-skills` (`:774`); update `PUT /custom-skills/<id>` (`:793`); delete `DELETE /custom-skills/<id>` (`:837`). | **Buildable** | `eesel skills author create/edit/remove` |
| 11 | **Skill replay** | Absent. | `POST /skills/replay/run` (`skills/replay.py:154`), status `GET /skills/replay/run/<task_id>` (`:243`). | **Needs backend** — every replay route is `@vm_auth_required` (a sandbox-VM token minted only server-side); not callable with the CLI's bearer. | — (blocked) |

---

## Blocked on backend work (summary)

A build loop should skip these until the server side exists:

- **Approvals approve/reject** — no list route; approve/reject are link-signed
  (JWT-in-query), not bearer-callable by approval id.
- **Skill replay** — all routes require a sandbox-VM token with no mint path for
  an external caller.
- **Billing plan / seat / payment change** — happens on Stripe-hosted pages;
  only the inbound webhook exists server-side.

## Confirmed non-gaps — do not build

- **Reports / analytics** — already the `tasks analytics` payload
  (`eesel tasks analytics`); the dashboard reports read the same data.
- **Developers / API-keys page** — a hardcoded UI stub with no backing endpoint;
  there is nothing to expose.
- **Prompt / instruction versioning** — does not exist in the dashboard either,
  so it is not a parity gap.
