# Security model

locksql lets an AI agent query a database while a human stays in control.
This document states what it protects, against whom, and how. Report
weaknesses as described in [SECURITY.md](../SECURITY.md).

## Assets and actors

- **Assets:** database credentials; the data (in particular personal data);
  the availability of the database server; the integrity of the data and of
  the policy that governs access.
- **The human** runs `locksql console` in a terminal and is trusted.
- **The agent** (and anything that can steer it, such as text stored in the
  database or in files it reads) is *not* trusted. It runs the client
  commands and the MCP server.
- **Other local users** are not trusted.

locksql supports Linux and macOS only. Where the agent runs depends on the
mode:

| Mode | Console runs as | Agent runs as | Boundary |
|---|---|---|---|
| Separated (`sudo locksql install`, `/etc/locksql/system.toml`) | the `locksql` account, in its own login session | its own account, member of `locksql-clients` | the kernel: separate uids, peer credentials on the socket, a root-owned binary and system file |

Separation is mandatory. Without `system.toml` the console refuses to start
and names `locksql doctor` and `sudo locksql install`; `doctor` reports
same-user mode as a failure. Same-user threats (an agent reading the
console's terminal, typing into it through TIOCSTI, attaching with ptrace or
reading the keychain session) are therefore excluded, not mitigated by a
warning.

The agent's account is assumed to have no password-less `sudo`
(`locksql doctor` fails otherwise) and no other way to become `locksql` or
root.

## Principles

1. **Two processes, one key holder.** The credentials and the only database
   connection live in the console process. The clients have neither.
2. **The console is the enforcement point.** Skills, rules and tool
   descriptions are guidance. Every check that matters runs in the console.
3. **The AI tightens, the human loosens.** Agents may add mask rules or
   request changes; every loosening needs the human's confirmation in the
   console.
4. **Fail closed.** What cannot be classified with certainty is refused.
5. **Defence in depth.** Server-side read-only and timeouts, a client-side
   classifier, a full parse and column analysis of reads, a privilege audit,
   an EXPLAIN gate, k-anonymity counts, result caps, then human approval.
6. **Results are data, not instructions.**

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| The agent runs a query the human did not approve | The console is the only connection holder. `query.run` needs a one-shot plan id (valid 10 minutes) and an explicit approval, or `--skip-permissions` outside production. |
| The agent loosens its own policy | The socket protocol has no method that loosens policy. Config and PII file edits are detected by a policy fingerprint diff; a loosening is held until the human confirms it. The approved policy is stored outside the repository. |
| Credential leak | Secrets exist only in console memory or the OS keychain (the console account's, in separated mode). They never go through argv, environment, files, logs, the socket or error messages (errors are sanitised). Config keys named like secrets and DSNs with passwords are refused. Core dumps are disabled (`RLIMIT_CORE=0`, and `PR_SET_DUMPABLE=0` on Linux). `credentials_ttl` bounds how long one secret stays in use. `doctor` flags a secret left in the agent's keychain. |
| Statement smuggling | The classifier refuses several statements, comments, variables, bind parameters and unbalanced quotes, and classifies by keywords outside literals per dialect. Reads are limited to `SELECT`, `WITH ... SELECT` and `EXPLAIN SELECT` and parsed in full by a fail-closed parser: unknown syntax is refused. Multi-statements are off in every driver; PostgreSQL uses the extended protocol only. Tier `read` is also enforced by a read-only session and transaction on the server. |
| Dangerous functions and statements | Reads may call only allowlisted functions (`internal/sqlast/funcs.go`); schema-qualified (possibly user-defined) functions and system schemas and relations are refused. At every tier: file and OS access, engine escape hatches (`ATTACH`, `load_extension`, `dblink`), SQLite raw storage tables (`sqlite_dbpage`, `dbstat`), sleeps, benchmarks, advisory locks, `FOR UPDATE`, session tampering (`SET ROLE`, `set_config`, guarded `SET` targets) and statements carrying credentials are refused. |
| Server overload | READ statements need `LIMIT n <= max_rows`; `EXPLAIN` estimates the rows examined and refuses heavy plans, and `explain_cost_refuse` caps the engine's total cost (not on SQLite); k-anonymity counts are weighed too; a server-side timeout plus a client-side cancel; one request at a time. |
| PII exposure | Column rules proposed from the schema at every start; per-rule mask modes (`redact` by default); quasi-identifiers proposed apart and masked only on acceptance; value detectors with checksums; unmasking is per query, shown in red and never auto-approved. |
| Alias or expression bypass | Every output column of a read is resolved to its base source columns through aliases, functions, subqueries, CTEs (recursive ones by fixpoint), set operations, joins and `*`, and masked on that source, not on its label. Expressions and functions over PII columns are refused; aggregates other than `COUNT`, `MIN` and `MAX` are redacted. The result's column count and labels must match the analysis or the result is dropped; the engine's origin metadata is a second check. |
| Predicate oracles | A PII column may only be compared for equality with a literal (`=`, `IN (literals)`, `IS NULL`) in `WHERE`/`HAVING`, or joined with `=` (also `IN (subquery)`, `USING`, `NATURAL`) to another PII column: a join with an unmasked column would copy its values where no mask applies. These atoms must be positive and reached through `AND` only: a PII atom under `NOT`, `OR` or `XOR`, and `<>`, `!=`, `NOT IN`, `IS NOT NULL`, `IS DISTINCT FROM` on a PII column, would select the complement of what the k-anonymity check counts and are refused. A scalar subquery returning a PII value cannot be a filter operand. `LIKE`, ranges, functions over it, `ORDER BY`, window `PARTITION BY`/`ORDER BY`, `FILTER`, `DISTINCT ON` and constant comparisons in `JOIN ... ON` are refused, so a query cannot compare it character by character with generated values. |
| Inference through aggregates and filters | A filter, grouping or aggregate on a PII column runs console-built `COUNT` queries (from the statement's own `FROM`, `WHERE`, `GROUP BY` and `HAVING`, shown on the approval screen) after approval and before the statement; fewer than `k_anonymity` rows (default 5, production 10) refuses it. Row estimates are hidden from the agent and `EXPLAIN` is refused for such statements, since the planner's figures would answer the same question. |
| Inference by equality probing | A placeholder `'${name}'` or a cell reference `'${rN.R.C}'` can only be compared with a PII column, in `WHERE` or `HAVING` (not in a `JOIN` condition), on a masked read statement (a write holding one is refused); the agent never sees the value, and a reference filter reaches the engine with the clear value of the cell. Since the agent did not choose that value, a filter made only of placeholders skips the k-anonymity check, and the console warns instead (approval screen and audit `warnings`, never a refusal): a clear value written by the agent, a reference combined with a filter on a one-column unique key (`=`, `IN` literals or `BETWEEN` constants), a reference filter with an output holding no plain column (counts, aggregates or expressions only), and distinct uses of one result's cells beyond `limits.reference_probe` (default 5, an `IN` list counts once; raising it is a loosening). Every redacted cell gets its own reference, so nothing in a result reveals which cells are equal. A column that may hold a literal of the statement (`UNION ALL SELECT 'x'`, `INTERSECT`) gets no reference on any row, nor does one masked only by its engine-reported origin: a reference to a value the agent chose would be a one-row lookup without the k-anonymity check. |
| Typed and referenced values | Typed with echo off, kept only in console memory (no core dump), never in the audit log, client answers, plan answers or client errors; the audit error of a statement with substituted values is generic. Clear values of results are bounded (50 results, 16 MiB) and forgotten oldest first. Their one trace outside the console is the server's own statement history, where the substituted value is a literal: the views that hold it are already refused while mask rules exist (see Statement text), but the server's logs, if enabled, are not locksql's to protect. |
| Timing and error channels | Clients get a generic failure message, never the server's text (shown on the console, redacted in the audit log). No timings are returned, and `query.run` answers on a 250 ms quantum, success or failure. |
| Statement text | Some server views hold the text of past statements, literals included: `pg_stat_statements` and `pg_stat_activity` on PostgreSQL; `information_schema.PROCESSLIST`, every `performance_schema` and `sys` relation (`threads`, `events_statements_*`, `session`, `statement_analysis`, ...), `mysql.general_log` and `mysql.slow_log` on MySQL and MariaDB. The read path refuses every system schema, these included; the write path (`INSERT ... SELECT`, ...) refuses these names while mask rules exist. |
| Prompt injection through data | Rows are framed as untrusted data in every output; the generated agent instructions say so; control and bidirectional characters are escaped in client output and on the console screen, so data cannot spoof the approval prompt. |
| Type-ahead approval | Pending input is flushed before each prompt (`tcflush`). |
| The agent mimics the human | In separated mode the console refuses to start as any account but `service_user`, when that account may also connect as a client, when started through `sudo`/`su` from another login session (`loginuid`), or when its terminal belongs to another uid. An X11 session, where any client can read and inject input, is refused on production profiles and with `x11 = "refuse"`, and warned about otherwise. The binary and `system.toml` are root-owned; `doctor` fails on password-less `sudo` for the agent's account. |
| Approval spoofing through the socket | Approval comes only from the console terminal; no socket method approves, and no socket method loosens policy. The approval screen names the requesting uid, pid and process as the kernel reports them. |
| A client stuck or killed during an approval | The approval is abandoned or times out after 5 minutes; the socket keeps serving. |
| A fake console | In separated mode clients check through peer credentials that the socket is served by `service_user`, and the socket directory is owned by it. |
| Another local user | The socket directory is `service_user:client_group` mode 0710, the socket 0660, and each peer is checked with `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS): the console's own uid, a member of `client_group` or an `allowed_uids` entry. |

## Approval

- The approval screen shows the profile, host, database, user, tier, the
  requesting uid, pid and process, the exact SQL with the PII columns it
  touches highlighted, its class, the EXPLAIN summary and verdict, the
  relations read, the PII columns touched and in which clause, the masked
  outputs and their modes, the k-anonymity counts, the row cap and the PII state.
- Approval comes only from the console terminal.
- locksql never rewrites SQL: what the human approves is what runs.
- Production profiles need the profile name typed, not `y`.
- REFUSE verdicts cannot be overridden from the console; the human has to
  raise the limits, which is itself a confirmed loosening.

## `--skip-permissions`

Auto-approval is a console-only flag. It is ignored on production profiles,
never covers unmasked queries, never overrides REFUSE, marks every console
line with `AUTO-APPROVE` and audits each decision as `auto`.

## Audit

The console appends one JSONL record per event (login, policy change,
refusal, approval, denial, timeout, auto-approval, abandoned approval,
catalog read, logout) to `<user state dir>/locksql/audit.log`, mode 0600.
Records contain the SQL and metadata, never secrets and never row data.

## Out of scope and limitations

- **Same-user mode is excluded.** The console refuses to start without a
  separated setup, so an agent running as the console's account (reading its
  keychain session, attaching with ptrace, typing into its terminal) is not a
  supported configuration.
- **The console account.** Malware running as `locksql` or as root, and an
  agent account that can become either, are out of scope. So is an X11
  session on a non-production profile with `x11 = "warn"`.
- **Transport security.** TLS to the database is not configurable yet.
  PostgreSQL, MariaDB and MySQL connect like PostgreSQL's `sslmode=prefer`:
  encrypted when the server offers TLS, plain otherwise, and the certificate
  is not verified. A plain TCP connection is reported on the console and in
  the audit log (`"decision":"notice"`). MariaDB and MySQL refuse a server
  that asks for the password in clear text (`mysql_clear_password`) on an
  unencrypted connection. An active attacker on the path can still strip TLS
  or intercept the unverified handshake. Use an SSH tunnel to reach remote
  servers.
- **Write tiers.** Above tier `read`, the human's approval is the gate. The
  classifier assigns the class shown on the screen, but the server does not
  restrict what an approved write statement does within the account's
  privileges. The column analysis covers reads; a write's `RETURNING` list
  or a data-modifying CTE may not alias or transform a masked column.
- **Masking is best effort.** Column rules depend on the rules being right,
  and value detectors catch common formats only. Use a database account that
  cannot read what the agent must never see.
- **Probing under the threshold.** The probing warnings do not refuse. An
  agent that spreads equality probes through references under
  `limits.reference_probe`, across results or sessions, can still learn which
  cells are equal; the human reading the warnings is the control. The unmasked
  columns of a row the agent targets can identify it, and free text without a
  detector is not masked.
- **k-anonymity is a query-set-size control.** It refuses a single query
  whose PII filter, group or aggregate covers fewer than `k` rows. Each
  constant PII filter is counted twice: the subjects of the column in its own
  base table (a join cannot multiply them; a column of a view, which has no
  base table to count in, cannot be filtered on), and the rows the
  statement's own `FROM`/`WHERE` selects. A join still multiplies the second
  count: `WHERE u.id = 3 AND u.salary IN (...)` joined with a large table
  passes when at least `k` users earn one of those salaries, and tells the
  agent that user 3 is among them. It does
  not stop differencing attacks: two approved queries whose sets differ by
  one row (all customers of a city, then the same minus one email) still
  reveal that row's other columns. The approval screen shows each PII filter
  so the human can spot such sequences; `--unmask` queries skip the check.
- **Equality still leaks equality.** A filter `WHERE email = 'x@example.com'`
  tells the agent whether that value exists among at least `k` rows. That is
  the purpose of this feature.
- **Relations that project another relation.** A view, a materialized view
  or a foreign table is masked by column name only: a view that renames a
  rule column (`firstname AS contact`) needs its own rule for the new name.
  The same holds for a classic-inheritance table (`INHERITS`) read through a
  parent or a child the rule does not name. A PostgreSQL partition is
  resolved to the root of its partition tree, so a rule on the partitioned
  table covers its partitions.
- **Copies at higher tiers.** A write (`INSERT ... SELECT`, `UPDATE ...
  SET`, `MERGE`) that copies a rule column into another column is refused,
  with or without `RETURNING`. DDL such as `CREATE TABLE ... AS SELECT` is
  not checked that way: at tier `ddl` and above the human's approval is the
  gate.
- **Catalog metadata** (database, table, column and index names) is returned
  without approval.

## Upstream recommendation

locksql masks what leaves the database; the database still holds plaintext,
and any other client of it (a backup, a replica, a reporting tool) sees it.
Where you control the schema, store personal data encrypted at rest with a
blind index: the application encrypts the value with a key the database
never holds, and stores next to it a keyed HMAC of the normalised value for
equality lookups and joins. The database then holds no plaintext to leak.
locksql's masks are the downstream half of the same idea: they hide values in
query results, whatever the database stores.
