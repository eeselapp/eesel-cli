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
eesel agents list
eesel agents show <id-or-name>      # full detail (type, status, instructions)
eesel agents create --name "QA Bot" --instructions "..."
eesel agents edit <id-or-name> --name "..."  # change name and/or instructions
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
```

Backed by the same workspace token the chat stream already uses
(`POST /workspace/tasks`, `GET /workspace/tasks/{id}/history`), so no extra
login is needed. Staff preview/impersonation tasks are filtered out
server-side and never appear here.

## Integrations, tools & triggers

Read-only inspectors for how an agent is wired up: which integrations the
workspace has connected, what tools/actions an agent can take, and what
triggers fire it.

```bash
eesel integrations                  # id, type, connection status, subdomain
eesel integrations --json           # raw payload
eesel integrations --secrets        # also show access tokens etc. (sysadmin only)

eesel tools                         # the scoped agent's tools/actions
eesel tools <id-or-name>            # ...for a specific agent
eesel tools --json                  # raw payload

eesel triggers                      # scheduled triggers (the default view)
eesel triggers --all                # every trigger, grouped by integration,
                                    # with scheduled triggers on top
eesel triggers --all --json         # raw payload
```

`eesel tools` lists each tool's name, read/write action, permission mode,
and integration. `eesel triggers --all` shows each trigger's type, config,
last-run time, and integration. Secret-looking values in trigger config
(access tokens, signing secrets) are masked in the human view; use `--json`
for the raw payload. `eesel integrations --secrets` reveals integration
credentials and is gated to sysadmin/impersonator accounts.

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
