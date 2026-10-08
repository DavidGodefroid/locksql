# locksql

> *Your AI writes the query. You hold the key.*

locksql lets an AI coding agent (Claude Code, Codex, Cursor, Gemini CLI, ...)
query MariaDB, MySQL, PostgreSQL and SQLite databases while you stay in
control. The agent never sees a credential, and every statement it runs has
been validated, weighed and approved by you in a separate terminal.

Status: pre-release. No tagged release has been published yet; build from
source (see [Build](#build)) until `v0.1.0` is out.

## Quick start

```sh
# 1. Install (once releases are published; until then use go install)
brew install davidgodefroid/tap/locksql        # macOS, Linux
scoop bucket add locksql https://github.com/DavidGodefroid/scoop-bucket
scoop install locksql                           # Windows
go install github.com/DavidGodefroid/locksql/cmd/locksql@latest

# 2. In your project: wire your agent and get an example config
locksql init claude                             # or codex, cursor, gemini

# 3. Uncomment and adapt the profile in .locksql/config.toml, then in a
#    second terminal that you keep in view:
locksql console --profile dev

# 4. Ask your agent: "how many orders were placed yesterday on dev?"
#    Approve or deny each query in the console.
```

## How it works

Two processes in two terminals. Only the console holds the key.

```
 Your terminal                                    Agent side
 ┌───────────────────────────────────┐            ┌──────────────────────────────┐
 │ locksql console --profile dev     │  local     │ locksql mcp   (stdio MCP)    │◄── AI agent
 │  credentials (ask | OS keychain)  │  socket    │ locksql plan|run|status|pii  │◄── AI via shell
 │  policy · classifier · EXPLAIN    │◄──────────►│ no secrets, no DB connection │
 │  approval prompt · masking · audit│  JSON-RPC  └──────────────────────────────┘
 └─────────────────┬─────────────────┘
                   │ native protocol
                   ▼
        MariaDB · MySQL · PostgreSQL · SQLite
```

1. The agent submits SQL with `locksql plan` (or the `locksql_plan` MCP tool).
   The console classifies it, runs `EXPLAIN`, weighs the plan and returns a
   one-shot plan id with a verdict (`OK`, `WARN` or `REFUSE`).
2. The agent calls `locksql run PLAN_ID`. The console shows you the approval
   screen and waits:

   ```
   ━━ DEV ━━ 127.0.0.1 / app ━━ user alice ━━ tier read
   SELECT id, status FROM orders WHERE customer_id = 88123 LIMIT 20
   class READ · EXPLAIN: orders lookup ~3 · est. 3 rows examined · verdict OK
   PII: masked (4 column rules; detectors: email, phone, iban, card)
   Approve? [y/N]
   ```

3. On approval the console runs the statement, masks PII, caps the output and
   hands the rows back to the agent, framed as untrusted data.

Full walkthrough: [docs/usage.md](docs/usage.md).

## Engines

| Engine | Versions | Read-only session (tier `read`) | Server-side timeout | Plan source |
|---|---|---|---|---|
| `mariadb` | 10.1+ (tested 10.11, 11.4) | `SET SESSION TRANSACTION READ ONLY` + `START TRANSACTION READ ONLY` | `max_statement_time` + `KILL QUERY` | `EXPLAIN FORMAT=JSON` |
| `mysql` | 8.0+ (tested 8.0, 8.4) | same as MariaDB | `max_execution_time` + `KILL QUERY` | `EXPLAIN FORMAT=JSON` |
| `postgres` | 13+ (tested 13, 17) | `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` + `BEGIN READ ONLY` | `statement_timeout` + cancel request | `EXPLAIN (FORMAT JSON, VERBOSE)` |
| `sqlite` | 3 (pure Go, in-process) | `mode=ro` + `query_only` | interrupt on deadline | `EXPLAIN QUERY PLAN` + `sqlite_stat1` |

All engines are pure Go: the binary is built with `CGO_ENABLED=0` for Linux,
macOS and Windows on amd64 and arm64.

## Safety model

The console is the enforcement point. Skills, rules and MCP tool descriptions
only guide the agent; the console's checks are the guarantee.

- **One key holder.** Credentials are typed at console start (no echo) or read
  from the OS keychain. They never appear in argv, environment, files, logs,
  the socket protocol or error messages. The console disables core dumps.
- **Human approval.** Every statement is shown and approved in the console.
  On a production profile you type the profile name, not `y`. Pending
  keystrokes are flushed before each prompt, so type-ahead never approves. No
  answer within 5 minutes means denied.
- **Fail closed.** A dialect-aware classifier refuses anything it cannot
  classify with certainty: several statements, comments, variables, bind
  parameters, file and OS access, sleeps and locks, session tampering.
- **Tiers.** `read < write < ddl < admin`; the default is `read`. Tier `read`
  is also enforced server side (read-only session and transaction).
- **Weight check.** A READ statement must carry `LIMIT n` with `n <= max_rows`.
  The console runs `EXPLAIN` and refuses statements that would examine too
  many rows; REFUSE cannot be overridden from the console.
- **PII masking.** On first start the console proposes column rules from the
  schema (multilingual names and types). Matching cells are masked by their
  origin column, and value detectors (email, phone, IBAN, card, opt-in
  national ids) mask the rest. Only base-table origins count: columns read
  through a view, or (on MariaDB and MySQL) a derived table or CTE, are
  matched by name, and aliasing a masked column is refused. A view that
  renames a masked column (`firstname AS contact`) needs its own rule for the
  new name. Without an origin, a non-ASCII column name is masked whenever any
  rule exists, since the server may resolve it to a masked column.
- **The AI tightens, the human loosens.** Agents may add mask rules and
  request changes. A config edit that loosens the policy (higher tier, larger
  limits, new host, removed PII rule, ...) only takes effect after you
  confirm it in the console.
- **Audit.** Every login, policy change, refusal, decision, catalog read and
  logout is appended to a JSONL audit log (mode 0600). Never secrets, never
  row data.

Details and threat model: [docs/security-model.md](docs/security-model.md).

## Configuration

Profiles live in `.locksql/config.toml` at the project root (found by walking
up from the current directory) and in `<user config dir>/locksql/config.toml`.
A project profile wins over a user profile of the same name. No file ever
holds a secret: keys named like `password`, `passwd`, `pwd`, `secret` or
`token`, and DSNs with an embedded password, are refused.

```toml
[profiles.uat]
engine      = "mariadb"             # mariadb | mysql | postgres | sqlite
host        = "db.uat.example.com"  # or path = "app.db" for sqlite
port        = 3306                  # default 3306, or 5432 for postgres
user        = ""                    # empty: asked at console start
database    = ""                    # empty: chosen per query (--db)
credentials = "ask"                 # ask | keychain
tier        = "read"                # read | write | ddl | admin
production  = false
detectors   = ["email", "phone", "iban", "card", "be_niss"]

[profiles.uat.limits]
statement_timeout   = "30s"
explain_rows_warn   = 100000
explain_rows_refuse = 1000000
max_rows            = 200
max_cell_chars      = 200
max_output_bytes    = 65536
```

| Key | Default | Notes |
|---|---|---|
| `engine` | required | `mariadb`, `mysql`, `postgres`, `sqlite` |
| `host`, `port` | required host; port 3306 / 5432 | a host starting with `/` is a Unix socket (MariaDB/MySQL) |
| `path` | required for sqlite | relative to the project root; the file is never created |
| `user` | asked at start | |
| `database` | none | the default database for queries |
| `credentials` | `ask` | `keychain` offers to save the secret after the first successful login; `locksql forget --profile P` removes it |
| `tier` | `read` | highest statement class allowed |
| `production` | `false` | stricter limits, typed approval, `--skip-permissions` ignored |
| `detectors` | `email`, `phone`, `iban`, `card` | also `be_niss`, `fr_nir`, `nl_bsn`, `us_ssn`; `[]` disables them |
| `limits.statement_timeout` | 30s (production 10s) | |
| `limits.explain_rows_warn` | 100 000 (production 20 000) | |
| `limits.explain_rows_refuse` | 1 000 000 (production 200 000) | |
| `limits.max_rows` | 200 | upper bound for `LIMIT n` and for returned rows |
| `limits.max_cell_chars` | 200 | longer cells are cut with `…` |
| `limits.max_output_bytes` | 65 536 | output is cut with a marker |

PII column rules live in `.locksql/pii.toml`:

```toml
[[mask]]
column = "app.users.email"            # db.table.column, * per segment
[[mask]]
column = "*.*.recipient_reference"
[[allow]]                             # explicit exception: never mask
column = "app.templates.name"
```

On PostgreSQL the first segment is the schema (`public.users.email`).

## `--skip-permissions`

`locksql console --profile dev --skip-permissions` auto-approves statements
that the tier and the weight check allow. It exists for fast local
iteration, and it is deliberately narrow:

- it is a console flag only; no client or config file can turn it on;
- it is **ignored on production profiles** (the console says so and prompts
  as usual);
- it never auto-approves an unmasked query and never overrides a REFUSE
  verdict;
- every console line is prefixed with `AUTO-APPROVE` while it is in effect,
  and each auto-approval is audited with `decision: "auto"`.

## Limitations

- **Same-user malware is out of scope.** A process running as you can already
  read your keychain session and drive your terminal.
- **Windows peer check.** On Linux and macOS the console checks the uid of
  every socket peer. On Windows it relies on the ACL of the socket directory
  under `%LOCALAPPDATA%` only.
- **TLS is not configurable yet.** PostgreSQL, MariaDB and MySQL connect like
  PostgreSQL's `sslmode=prefer`: encrypted when the server offers TLS, plain
  otherwise, and the certificate is not verified, so an active attacker on the
  path can intercept or downgrade the connection. A plain TCP connection is
  reported as a warning. This mode gives no protection against such an
  attacker, the password included: over the unverified TLS connection the
  attacker can ask for it in clear (MySQL and MariaDB `mysql_clear_password`
  or a `caching_sha2_password` full authentication), and PostgreSQL sends
  it in clear to a server that asks for cleartext authentication, with or
  without TLS. On a plain MySQL/MariaDB TCP connection locksql refuses the
  authentications that would hand the password over (clear text, or RSA
  encryption with a key the server sends: `sha256_password` and a
  `caching_sha2_password` full authentication), so a MySQL 8 account on a
  server without TLS can log in only while the server's authentication cache
  holds it. Use an SSH tunnel (`ssh -L`) or a Unix socket for remote
  servers.
- One console per profile and project, one request at a time. No remote or
  shared consoles, no data export.

## Why a separate console?

Agent tools already ask before running a command, but that approval lives
inside the agent's own process and UI: the agent holds the credentials, the
prompt can be configured away, and a long session trains you to press "yes".
locksql moves the decision out of the agent. The agent process has no
credential and no database connection, so there is nothing to bypass from
its side; the console in your terminal holds both, shows you the exact SQL
with its cost and PII status, and applies limits that only you can loosen.
In-agent approval is a convenience; a separate approval process is a
boundary.

## Documentation

- [docs/usage.md](docs/usage.md): console, client commands, MCP server, agent
  integration.
- [docs/security-model.md](docs/security-model.md): threat model and
  mitigations.
- [SECURITY.md](SECURITY.md): reporting a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md): building and testing.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
