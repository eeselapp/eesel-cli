# eesel-cli

A simple CLI for the [eesel.ai](https://eesel.ai) platform. Auth, then
chat — almost like the dashboard, from your terminal.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/eeselapp/eesel-cli/main/install | sh
```

This drops a single `eesel` script into `~/.local/bin`. Requires
`python3` (>= 3.8) — no other deps, stdlib only.

By default the installer pulls the latest release from
`https://github.com/eeselapp/eesel-cli/releases/latest/download/eesel`.

Pin a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/eeselapp/eesel-cli/main/install | sh -s -- --version v0.1.0
# or via env
EESEL_VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/eeselapp/eesel-cli/main/install | sh
```

Install somewhere else:

```bash
EESEL_INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/eeselapp/eesel-cli/main/install | sh
```

## Quick start

```bash
eesel login                         # opens dashboard.eesel.ai, signs in as you (Auth0)
eesel whoami
eesel agents list                   # --json or --plain for machine-readable output
eesel agents show <id-or-name>      # full detail (type, status, instructions)
eesel agents instructions <id-or-name>   # just the system prompt (also `eesel instructions`)
eesel agents create --name "QA Bot" --instructions "..."
eesel agents set <id-or-name> --name "..."   # change name and/or instructions
eesel agents remove <id-or-name>    # delete an agent (asks to confirm; --force to skip)

# Scope a command to an agent explicitly — no hidden saved state:
EESEL_AGENT=<id-or-name> eesel ...  # per-invocation, applies to any command
eesel <cmd> --agent <id-or-name>    # per-command flag (wins over EESEL_AGENT)

eesel instructions                  # print the scoped agent's instructions (system prompt)
eesel instructions <id-or-name>     # ...for a specific agent
eesel instructions > prompt.md      # stdout is just the prompt, so redirect/pipe freely

eesel new                           # start a chat session
eesel chat "hey, talk to me"        # one-shot send to active session
eesel chat                          # interactive REPL

eesel chat --task <task-id> "..."   # continue an existing conversation by
                                    # its backend task id — e.g. post an
                                    # async job result back into the chat
                                    # that requested it
```

Sessions:

```bash
eesel sessions list
eesel sessions use <id>
eesel sessions show
eesel sessions remove <id>
```

In the REPL: `/new`, `/sessions`, `/agents`, `/show`, `/tasks`, `/task <id>`,
`/cost`, `/cost-on`, `/cost-off`, `/quit`.

## Documents

List, read, and export documents from your workspace — e.g. to view or
download a blog draft the agent generated, or any other artifact in the
doc store.

```bash
eesel document list                                            # all documents
eesel document list --prefix outputs/skills                    # filter by key prefix
eesel document list --search "blog title"                      # filter by name/key

eesel document read                                            # arrow-key menu, then print
eesel document read <id-or-key>                                # print one doc to stdout
eesel document read --prefix files/                            # menu, filtered to files/…
eesel document read <id> --format html                         # read as HTML (default: md)
eesel document read <id> > draft.md                            # body→stdout, so redirect works

eesel document export --document-key <key> --format md -o post.md
eesel document export --document-id <id-or-prefix> --format html -o post.html
```

`--format` accepts `md` or `html`. For `export`, `-o` is optional; without
it the file lands in the current directory using the document's filename.
`read` prints the body to stdout (the header goes to stderr, so redirects
capture just the content) and, with no id, opens an arrow-key picker.

Documents are scoped to one agent — its `files/…` and `outputs/skills/…`
keys — so scope the command with `EESEL_AGENT` or `--agent` first.
`--prefix` filters within that scope (e.g. `files/`, `outputs/`).

## Tasks (workspace activity)

`tasks` shows everything the workspace's agents have actually done —
dashboard chats, the website widget, helpdesk ticket replies,
scheduled-trigger runs, and sub-agent spawns. It's the same data as the
dashboard's **Activity** view, and distinct from `sessions` (which are
just the local chat handles you created with the CLI). `tasks list` marks
rows that are also one of your local sessions with a `*`.

```bash
eesel tasks list                    # recent activity, newest first
eesel tasks list --limit 100 --page 2
eesel tasks list --agent "Support Bot"   # filter by agent (id, id-prefix, or name)
eesel tasks count                   # total task count (optionally --agent)
eesel tasks show <id>               # full transcript of one task (id-prefix ok)
eesel tasks show <id> --json        # raw history payload
eesel tasks show <id> --full        # don't truncate tool args/outputs
eesel tasks show <id> --cost        # append a cost breakdown (dev only)
eesel tasks cost <id>               # cost breakdown for any task (dev only)
eesel tasks analytics               # resolution rate, counts, CSAT (optionally --agent / --start-date / --end-date / --json)
eesel tasks export                  # start a CSV export; download link is emailed (optionally --agent / --start-date / --end-date)
```

Backed by the same workspace token the chat stream already uses
(`POST /workspace/tasks`, `GET /workspace/tasks/{id}/history`), so no extra
login is needed. Staff preview/impersonation tasks are filtered out
server-side and never appear here.

## Integrations, tools, triggers & schedules

Inspect and wire up how an agent runs: which integrations the workspace has
connected, what tools/actions an agent can take, what event/webhook triggers
fire it, and what scheduled jobs run it on a cron.

Triggers and scheduled jobs are two separate command groups. An **event/webhook
trigger** (`zendesk_ticket_created`, etc.) fires the agent when something happens
in an integration. A **scheduled job** runs the agent on a cron and can also be
fired manually.

> **Moved:** `eesel triggers` / `eesel triggers list` used to list scheduled
> (cron) jobs as well. They now list **only event/webhook triggers** — scheduled
> jobs are under `eesel schedules`. If you scripted `eesel triggers` to read cron
> jobs, switch that call to `eesel schedules`. (The old `eesel triggers --all`
> flag is gone; use the two groups.)

```bash
eesel integrations                  # id, type, connection status, subdomain
eesel integrations --json           # raw payload
eesel integrations --secrets        # also show access tokens etc. (sysadmin only)

# The integrations group is agent-scoped: connection status is computed against
# an agent, and `connect` connects the integration for one. It defaults to the
# active agent / $EESEL_AGENT; --agent overrides that for a single command.
eesel integrations --agent <agent>                       # list, scoped to one agent
eesel integrations available [--agent <agent>]           # the connectable catalog: key, category, connect options
eesel integrations show <id> [--agent <agent>]           # one integration's detail + latest sync run

# `connect <key>` drives off the connector's connection options (see `available`).
# `--option <type>` picks one (required when a connector has several):
#   - a "submit" option connects directly — pass its fields with --field key=value
#   - a "redirect" option opens the dashboard OAuth URL in your browser and hands
#     off (like `eesel login`); the CLI does not wait for the flow to finish.
eesel integrations connect <key> --option quick_start --field subdomain=acme [--agent <agent>]   # direct connect
eesel integrations connect <key> --option oauth [--agent <agent>]                                # browser OAuth hand-off
eesel integrations sync <id> [--type help-center] [--agent <agent>]                  # trigger a data sync (Zendesk only)
eesel integrations sync-status [<id>] [--agent <agent>]                              # sync-run status + progress (all, or one integration's)
# `remove` has two scopes (mirrors the dashboard's two options):
#   --agent <agent>  → remove from just that agent; other agents keep their access
#   (no --agent)     → uninstall for the WHOLE workspace; every agent loses it
eesel integrations remove <id> --agent <agent>           # remove from one agent (others keep access)
eesel integrations remove <id>                           # uninstall for the whole workspace (-f to skip the prompt)

# Actions (formerly `tools`) are scoped under their integration; --agent picks
# whose action set to read/write (default: the active agent)
eesel integrations <integration> actions list [--agent <agent>]            # the agent's actions for one integration
eesel integrations <integration> actions show <action> [--agent <agent>]
eesel integrations <integration> actions enable <action> [--agent <agent>]
eesel integrations <integration> actions disable <action> [--agent <agent>]   # -f to skip the prompt
eesel integrations <integration> actions set <action> --config '{...}' [--agent <agent>]

# Event/webhook triggers
eesel triggers                      # every event trigger, grouped by integration
eesel triggers --json               # raw payload
eesel triggers registry             # available trigger types (keys for `add`)
eesel triggers add <agent> --key zendesk_ticket_created
eesel triggers remove <id>

# Scheduled jobs (cron)
eesel schedules                     # every scheduled job (id, title, cron, tz)
eesel schedules add <agent> --cron "0 9 * * *" --prompt "Summarise overnight tickets" --title "Morning digest"
eesel schedules fire <id-or-title>  # run one manually, now
eesel schedules remove <id>
```

`eesel integrations <integration> actions list [--agent <agent>]` lists each
action's name, read/write kind, permission mode, and integration. `eesel triggers` shows
each event trigger's type, config, last-run time, and integration. `eesel
schedules` shows each job's title, cron, and timezone. Secret-looking values in
trigger config (access tokens, signing secrets) are masked in the human view;
use `--json` for the raw payload. `eesel integrations --secrets` reveals
integration credentials and is gated to sysadmin/impersonator accounts.

### `set` (and the old `edit` alias)

`set` is the canonical write verb across the CLI. How it treats the keys you
*don't* pass differs by command — `set` does **not** mean "replace everything"
everywhere. When in doubt, check that verb's `--help`:

- **Merges** the keys you pass into the existing config, leaving the rest intact
  (PATCH) — `eesel skills set <agent> <skill> --config '{…}'`.
- **Replaces** the config wholesale, dropping any key you omit — `eesel
  integrations <x> actions set <action> --config '{…}'`. The tools endpoint has
  no partial-merge, so a one-field write drops the action's other settings
  (only the permission keys are preserved).
- **Writes only the named fields you pass**, leaving the rest of the record
  untouched — `eesel agents set <agent> --instructions …`, `eesel mcp set
  <server> --name … --url …`, `eesel workspace set <field> <value>`.
- **Replaces a whole set** — `eesel documents acl set <agent> --prefix …`
  replaces the agent's ACL key prefixes (it does not append).

`edit` is kept only as a **hidden back-compat alias** for `set` on the commands
that used to spell it that way (agents, mcp, skills, `integrations actions`); new
scripts should use `set`.

Some renamed commands keep **hidden back-compat aliases** so existing scripts
don't break: `eesel tools [agent]` still works (now `eesel integrations <x>
actions`), `eesel agents add` aliases `eesel agents create`, and on the
integrations group `add` aliases `connect` and `disconnect` aliases `remove`.
They're hidden from `--help`; prefer the canonical spellings. Manually firing a
scheduled job is `eesel schedules fire <id>` (the old `eesel triggers fire` has
been removed).

## Cost

`eesel cost` and `eesel chat --cost` show how much a session has cost end
to end, including everything the agent's sub-agents spawn under the hood.

```bash
eesel chat --cost "hello"           # one-line cost summary after each reply
eesel cost                          # full breakdown for the active session
eesel cost <session-id-prefix>      # cost for a specific session
```

Cost data is currently **dev-only** — in production, cost lives in the
dashboard's Activity view.

## How auth works

`eesel login` opens `dashboard.eesel.ai/cli` in your browser. The page hands
your Auth0 access token (and a refresh token) back to a local HTTP server the
CLI runs briefly. The CLI then calls the API as you, with your real
permissions — same identity as the dashboard, no separate credentials. The
access token is short-lived; the CLI refreshes it silently using the refresh
token, so you stay logged in without re-running `eesel login`.

`eesel login --dev` is unchanged: it mints a local workspace JWT against the
dev secret for the docker stack (no browser).

Tokens live at `~/.config/eesel/credentials.json` (chmod 600). If a refresh
ever fails (e.g. the token was revoked), re-run `eesel login`.

**MCP clients** (Claude Code, Cursor) authenticate to `/mcp` with a workspace
token, not the Auth0 token. Mint one with `eesel mcp token` and pass it as the
`Authorization: Bearer` header — see the MCP setup guide.

## Local state

```
~/.config/eesel/
├── credentials.json        env, api_url, workspace_id, agent_id, token,
│                           refresh_token, expires_at
├── current.json            { session_id }
└── sessions/
    └── <id>.json           { id, name, agent_id, task_id, messages: [...] }
```

CLI sessions are independent of dashboard task history. Each session
maps to one stable `taskId` so you can keep talking to the same chat
across many invocations.

## Uninstall

```bash
rm ~/.local/bin/eesel
rm -rf ~/.config/eesel
```
