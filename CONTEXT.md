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

## Platform (new vs legacy v2)

The CLI serves two backends and auto-detects which one the workspace is on
(cached; `eesel whoami` shows it). Same commands either way. On the **legacy
v2** platform the CLI is **read-only**: only `agents list`/`show`,
`instructions`, `integrations list`/`show`, `tasks list`/`show`, `workspace
show`/`members`, and the universal commands (`login`/`logout`/`whoami`/`link`/
`schema`) work — everything else is refused with exit code `5`, and `--help` is
trimmed to those. Force the platform for one command with `--legacy` or
`--platform` (mutually exclusive). `eesel schema` marks each command with a
`legacy_supported` flag, so check there before calling on a legacy workspace.

## Reading a customer's workspace (support only)

`eesel support read --task <task_id> <read command…>` runs one ordinary read
command against the workspace of a support conversation's sender, using a
15-minute read-only token the server mints. You never name the customer: the
server reads the sender off the helpdesk's record of that conversation. Writes
are refused, by the server as well as by the CLI, and `eesel support status` /
`end` show and drop the cached tokens. The command is hidden from `--help` for
non-staff logins but always present in `eesel schema`.

Four answers are expected outcomes rather than bugs, each named on a `reason:`
line with exit code 3: `no_verified_sender`, `sender_not_verified_owner`,
`caller_not_allowlisted`, `task_not_in_support_workspace`. See the README for
what to do about each.

⚠️ `tasks list` / `count` / `analytics` do not work inside a support session:
the API serves those reads over POST and the server's read-only rule is decided
by HTTP method. `tasks show <id>` (a GET) does work, and `eesel tasks list` as
yourself is unaffected.

## Exit codes

`0` = success · `2` = usage error (bad flags/arguments, from the parser) ·
any other non-zero = the command failed. Branch on `0` vs non-zero; treat `2`
as "I called it wrong" rather than "the operation failed".
