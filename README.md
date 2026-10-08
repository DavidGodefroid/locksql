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
go install github.com/DavidGodefroid/locksql/cmd/locksql@latest

# 2. In your project: wire your agent and get an example config
locksql init claude                             # or codex, cursor, gemini

# 3. Uncomment and adapt the profile in .locksql/config.toml, then in a
#    second terminal that you keep in view:
locksql console --profile dev

# 4. Optional, recommended: run the console under its own OS account
#    (Linux, macOS), then check the machine
locksql install
locksql doctor

# 5. Ask your agent: "how many orders were placed yesterday on dev?"
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
   The console classifies it, parses and analyses a read down to the source
   column of every output, runs `EXPLAIN`, weighs the plan and returns a
   one-shot plan id with a verdict (`OK`, `WARN` or `REFUSE`).
2. The agent calls `locksql run PLAN_ID`. The console shows you the approval
   screen and waits:

   ```
   ━━ DEV ━━ 127.0.0.1 / app ━━ user alice ━━ tier read
   requested by uid 1000 (alice) · pid 48211 (claude)
   SELECT id, email FROM customers WHERE country = 'BE' LIMIT 20
   class READ · EXPLAIN: customers range ~410 · est. 410 rows examined · verdict OK
   reads: app.customers
   returns at most 20 rows
   PII columns touched: customers.email (select)
   masked outputs: email → partial
   PII: masked (4 column rules; detectors: email, phone, iban, card)
   Approve? [y/N]
   ```

3. On approval the console runs its k-anonymity counts when the statement
   filters, groups or aggregates PII, then the statement itself, masks PII,
   caps the output and hands the rows back to the agent, framed as untrusted
   data.

Full walkthrough: [docs/usage.md](docs/usage.md).

## Engines

| Engine | Versions | Read-only session (tier `read`) | Server-side timeout | Plan source |
|---|---|---|---|---|
| `mariadb` | 10.1+ (tested 10.11, 11.4) | `SET SESSION TRANSACTION READ ONLY` + `START TRANSACTION READ ONLY` | `max_statement_time` + `KILL QUERY` | `EXPLAIN FORMAT=JSON` |
| `mysql` | 8.0+ (tested 8.0, 8.4) | same as MariaDB | `max_execution_time` + `KILL QUERY` | `EXPLAIN FORMAT=JSON` |
| `postgres` | 13+ (tested 13, 17) | `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` + `BEGIN READ ONLY` | `statement_timeout` + cancel request | `EXPLAIN (FORMAT JSON, VERBOSE)` |
| `sqlite` | 3 (pure Go, in-process) | `mode=ro` + `query_only` | interrupt on deadline | `EXPLAIN QUERY PLAN` + `sqlite_stat1` |

All engines are pure Go: the binary is built with `CGO_ENABLED=0`. locksql
supports Linux and macOS only, on amd64 and arm64.

## Safety model

The console is the enforcement point. Skills, rules and MCP tool descriptions
only guide the agent; the console's checks are the guarantee.

- **One key holder.** Credentials are typed at console start (no echo) or read
  from the OS keychain. They never appear in argv, environment, files, logs,
  the socket protocol or error messages. The console disables core dumps.
  `credentials_ttl` makes it ask again after a set time (vault leases).
- **OS separation.** `locksql install` creates a `locksql` console account
  and a `locksql-clients` group: the console runs as that account in its own
  login session, the agent's account only reaches its socket, and the kernel
  checks every peer. Without it (same-user mode) the console warns that the
  agent's account could read or type into its terminal.
- **Human approval.** Every statement is shown and approved in the console
  terminal; no socket method can approve. On a production profile you type the
  profile name, not `y`. Pending keystrokes are flushed before each prompt, so
  type-ahead never approves. No answer within 5 minutes means denied.
- **Fail closed.** A dialect-aware classifier refuses anything it cannot
  classify with certainty: several statements, comments, variables, bind
  parameters, file and OS access, sleeps and locks, session tampering. Reads
  are limited to `SELECT`, `WITH ... SELECT` and `EXPLAIN SELECT`, parsed in
  full: unknown syntax, functions outside an allowlist and system schemas
  are refused.
- **Tiers.** `read < write < ddl < admin`; the default is `read`. Tier `read`
  is also enforced server side (read-only session and transaction).
- **Weight check.** A READ statement must carry `LIMIT n` with `n <= max_rows`.
  The console runs `EXPLAIN` and refuses statements that would examine too
  many rows (or cost more than `explain_cost_refuse`); REFUSE cannot be
  overridden from the console.
- **PII masking.** At every start the console scans the schema and proposes
  rules for columns that look like personal data (multilingual names and
  types) and that no rule names yet. Every output column is resolved to its
  source columns through aliases, functions, subqueries, CTEs, unions, joins
  and `*`, and masked on that source, not on its label; the engine's origin
  metadata is a second check, and a result whose columns do not match the
  analysis is dropped. Value detectors (email, phone, IBAN, card, opt-in
  national ids) mask the other cells. Mask modes: `partial`, `redact`,
  `email`, `hash` (per-session tokens that keep joins and equality filters).
- **PII usage.** PII columns may be selected, counted, joined with `=` and
  filtered with `=`, `IN (literals)` or `IS NULL`. Expressions over them,
  `LIKE`, ranges and `ORDER BY` are refused. A filter, grouping or aggregate on
  PII must cover at least `k_anonymity` rows (default 5, production 10).
- **Quiet failures.** Clients get a generic message, never the server's error
  text, and no timings; `query.run` answers on a 250 ms quantum.
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
credentials_ttl = "20m"             # optional: ask for the secret again
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
k_anonymity         = 5
explain_cost_refuse = 0             # engine cost units; 0 = off
```

| Key | Default | Notes |
|---|---|---|
| `engine` | required | `mariadb`, `mysql`, `postgres`, `sqlite` |
| `host`, `port` | required host; port 3306 / 5432 | a host starting with `/` is a Unix socket (MariaDB/MySQL) |
| `path` | required for sqlite | relative to the project root; the file is never created |
| `user` | asked at start | |
| `database` | none | the default database for queries |
| `credentials` | `ask` | `keychain` offers to save the secret after the first successful login; `locksql forget --profile P` removes it |
| `credentials_ttl` | none | a duration of at least `1m` (`"20m"`, `"1h"`): the connection is closed and the secret asked again once it is that old |
| `tier` | `read` | highest statement class allowed |
| `production` | `false` | stricter limits, typed approval, `--skip-permissions` ignored |
| `detectors` | `email`, `phone`, `iban`, `card` | also `be_niss`, `fr_nir`, `nl_bsn`, `us_ssn`; `[]` disables them |
| `limits.statement_timeout` | 30s (production 10s) | |
| `limits.explain_rows_warn` | 100 000 (production 20 000) | |
| `limits.explain_rows_refuse` | 1 000 000 (production 200 000) | |
| `limits.max_rows` | 200 | upper bound for `LIMIT n` and for returned rows |
| `limits.max_cell_chars` | 200 | longer cells are cut with `…` |
| `limits.max_output_bytes` | 65 536 | output is cut with a marker |
| `limits.k_anonymity` | 5 (production 10) | smallest row count a PII filter, a group or an aggregate of a PII column may cover; lowering it is a loosening |
| `limits.explain_cost_refuse` | 0 (off) | refuse plans above this total cost, in the engine's own units; SQLite reports no cost and is not checked |

PII column rules live in `.locksql/pii.toml`:

```toml
[[mask]]
column = "app.users.email"            # db.table.column, * per segment
mode   = "email"                      # j***@example.com
[[mask]]
column = "app.users.customer_ref"
mode   = "hash"                       # tok_... per console session
[[mask]]
column = "*.*.recipient_reference"    # mode "partial" by default: j***(12)
[[allow]]                             # explicit exception: never mask
column = "app.templates.name"
```

| Mode | Output | Notes |
|---|---|---|
| `partial` (default) | `j***(12)` | first character and length |
| `redact` | `<redacted>` | |
| `email` | `j***@example.com` | first character and domain; other values as `partial` |
| `hash` | `tok_` + 20 characters | keyed HMAC with a random key per console session: equal values give equal tokens, so the agent can join, group and count, and filter with `WHERE col = 'tok_...'` (the console substitutes the value in the statement that runs) |

Only columns explicitly configured with `mode = "hash"` get tokens, and a
token is accepted only against such a column. A column covered by several
rules with different modes is redacted. Changing a mode is a loosening unless
the new mode is `redact`.

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

- **Same-user mode is weaker.** Without `locksql install`, the agent runs as
  the console's account and could read its terminal, type into it or read
  its keychain session. Run `locksql doctor` to see what your machine allows.
  Malware running as the console account is out of scope in both modes.
- **k-anonymity is a query-set-size control.** It refuses a single query
  whose PII filter covers fewer than `k` rows; it does not stop differencing
  attacks that combine several approved queries.
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
  mitigations, and an upstream recommendation (PII encrypted at rest with a
  blind index).
- [SECURITY.md](SECURITY.md): reporting a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md): building and testing.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
