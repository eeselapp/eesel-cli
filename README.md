# eesel-cli

A simple CLI for the [eesel.ai](https://eesel.ai) platform. Auth, then
chat — almost like the dashboard, from your terminal.

## Install

```bash
curl -fsSL https://eesel.ai/install.sh | sh
```

This drops a single `eesel` script into `~/.local/bin`. Requires
`python3` (>= 3.8) — no other deps, stdlib only.

Pin a specific version:

```bash
curl -fsSL https://eesel.ai/install.sh | sh -s -- --version v0.1.0
```

Install somewhere else:

```bash
EESEL_INSTALL_DIR=/usr/local/bin curl -fsSL https://eesel.ai/install.sh | sh
```

## Quick start

```bash
eesel login                         # opens dashboard.eesel.ai, captures workspace token
eesel whoami
eesel agents list
eesel agents use <id-or-name>

eesel new                           # start a chat session
eesel chat "hey, talk to me"        # one-shot send to active session
eesel chat                          # interactive REPL
```

Sessions:

```bash
eesel sessions list
eesel sessions use <id>
eesel sessions show
eesel sessions delete <id>
```

In the REPL: `/new`, `/sessions`, `/agents`, `/show`, `/quit`.

## How auth works

`eesel login` opens `dashboard.eesel.ai/cli` in your browser. The page
captures a workspace token from your active dashboard session and
hands it back to a local HTTP server the CLI runs briefly. Same auth
as the dashboard — no separate credentials.

The token lives at `~/.config/eesel/credentials.json` (chmod 600) and
expires in 24h. Re-run `eesel login` when it expires.

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
