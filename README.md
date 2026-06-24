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
eesel login                         # opens dashboard.eesel.ai, captures workspace token
eesel whoami
eesel agents list
eesel agents use <id-or-name>       # set the active agent
eesel agents use                    # ...or pick from an arrow-key menu (↑/↓, Enter)
eesel agents unset                  # clear the active agent (next command prompts again)

eesel instructions                  # print the active agent's instructions (system prompt)
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
eesel sessions delete <id>
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
capture just the content) and, with no id, opens an arrow-key picker like
`eesel agents use`.

Documents are scoped to the currently-active agent (`eesel agents use`) —
its `files/…` and `outputs/skills/…` keys — so set the right agent first.
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

```bash
eesel integrations                  # id, type, connection status, subdomain
eesel integrations --json           # raw payload
eesel integrations --secrets        # also show access tokens etc. (sysadmin only)

eesel tools                         # the active agent's tools/actions
eesel tools <id-or-name>            # ...for a specific agent
eesel tools --json                  # raw payload

# Event/webhook triggers
eesel triggers                      # every event trigger, grouped by integration
eesel triggers --json               # raw payload
eesel triggers registry             # available trigger types (keys for `add`)
eesel triggers add <agent> --key zendesk_ticket_created
eesel triggers remove <id>

# Scheduled jobs (cron)
eesel schedules                     # every scheduled job (id, title, cron, tz)
eesel schedules add <agent> --cron "0 9 * * *" --title "Morning digest"
eesel schedules fire <id-or-title>  # run one manually, now
eesel schedules remove <id>
```

`eesel tools` lists each tool's name, read/write action, permission mode, and
integration. `eesel triggers` shows each event trigger's type, config, last-run
time, and integration. `eesel schedules` shows each job's title, cron, and
timezone. Secret-looking values in trigger config (access tokens, signing
secrets) are masked in the human view; use `--json` for the raw payload.
`eesel integrations --secrets` reveals integration credentials and is gated to
sysadmin/impersonator accounts.

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

`eesel login` opens `dashboard.eesel.ai/cli` in your browser. The page
captures a workspace token from your active dashboard session and
hands it back to a local HTTP server the CLI runs briefly. Same auth
as the dashboard — no separate credentials.

The token lives at `~/.config/eesel/credentials.json` (chmod 600) and
expires in 30 days. Re-run `eesel login` when it expires.

## Local state

```
~/.config/eesel/
├── credentials.json        env, api_url, workspace_id, agent_id, token, expires_at
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
