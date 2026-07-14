# eesel CLI — context for an AI agent

You are driving the `eesel` CLI: a single-file command-line client for the
eesel.ai platform. This file states the things you cannot infer from `--help`
alone. Read it once, then discover the rest with `eesel schema`.

## Scope an agent first

Almost every command acts on **one agent**. Set it once, then omit it:

- `--agent <id-or-name>` on the command, or
- `EESEL_AGENT=<id-or-name>` in the environment.

A single-agent workspace needs neither — the only agent is used automatically.
`eesel agents list` shows the ids and names you can pass.

## Ask for machine output

Human output (tables, colour) is the default. For anything you parse, ask for
JSON:

- `--json`, or `EESEL_OUTPUT=json` in the environment. Both are equivalent and
  work on every command that returns data.
- When JSON is on **and stdout is piped**, a list is emitted as **NDJSON** —
  one object per line. Parse it line by line, not as one array. On a terminal
  the same list prints as one pretty block.
- Trim a large payload to the keys you need with `--fields a,b,c` (top-level
  keys only). An unknown key is silently dropped, so requesting a superset is
  safe.

Example: `eesel agents list --json --fields agent_id,name`

## Discover the surface — don't guess

`eesel schema` prints the **entire** command tree as JSON: every command, its
flags (names, whether each takes a value, whether it's required, and any closed
enum `choices`), the handler that runs, and the API endpoint the command hits.
It is walked live from the parser, so it can't drift from what the CLI actually
accepts. **Trust it over `--help`.** Combine with `--fields` to trim it.

## Preview before you write

Add `--dry-run` to any side effect to see what it would do — with **no call
made** and nothing changed. This covers config mutations (printed as
`{"method", "url", "body"}`), a billed `chat` turn (the sandbox/start request is
previewed, not sent), and `login` (prints the flow and endpoint, mints no token,
writes no credentials). Read-only commands still run normally under `--dry-run`
(a mutation often has to resolve an id or read existing config first, and that
read executes so the previewed body is faithful). `--dry-run` works in any
position, before or after the subcommand.

Example: `eesel agents create --name Probe --dry-run`

## Secrets are masked

JSON output shows `***` for anything that looks like a secret (tokens,
passwords, credentials). This is on by default and applies everywhere. Raw
values require **both** `--secrets` **and** a sysadmin/impersonator login;
a normal agent never sees them, and asking without the right login just leaves
them masked. Boolean flags like `has_auth_token` are never masked — they tell
you a secret exists without exposing it.

## Auth

- `eesel login` — browser-based login for a human (opens the dashboard).
- `eesel link <url>` — point one git worktree at a branch (preprod) env; the
  token is minted fresh per run and never written to disk.

Check who you are with `eesel whoami`.

## Exit codes

`0` = success · `2` = usage error (bad flags/arguments, from the parser) ·
any other non-zero = the command failed. Branch on `0` vs non-zero; treat `2`
as "I called it wrong" rather than "the operation failed".
