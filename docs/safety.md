# Safety model and limitations, in detail

The [README](../README.md#safety-model) has the summary. The threat model and every mitigation are in [security-model.md](security-model.md), which is the reference.

## Safety model

The console is the enforcement point. Skills, rules and MCP tool descriptions
only guide the agent; the console's checks are the guarantee.

- **One key holder.** Credentials are typed at console start (no echo), or
  fetched from HashiCorp Vault with the `vault` CLI
  at every connection (`credentials = "vault"`, suited to the database
  secrets engine's per-user, short-lived logins). They never appear in argv,
  environment, files, logs, the socket protocol or error messages. The
  console disables core dumps. `credentials_ttl` makes it ask again after a
  set time; a Vault lease is renewed with a fresh login before it ends.
- **OS separation.** The image holds a `locksql` console account and a
  `locksql-clients` group: the console runs as that account in its own
  container, the agent's MCP server runs as `agent`, a member of the group, in
  another, and the two share only the socket volume. The kernel checks every
  peer. The console refuses to start without this setup, since an agent in
  the console's own account could read or type into its terminal. Whoever can
  run `docker` commands can still reach the console's container: see
  [what Docker does and does not separate](docker.md#what-docker-does-and-does-not-separate).
- **Human approval.** Every statement goes to lockhub as a ticket and runs
  only once lockhub's signed decision approves it, or is a read inside a
  grant such a decision approved (below); no socket method can approve. You can deny with a reason the agent reads. The console's own
  decisions (a loosened policy, `:unmask`) stay at its terminal.
- **Grants, against approval fatigue.** An agent that needs several reads
  of the same few tables asks once for a grant (`locksql_grant`, `locksql
  grant`): a database, tables, a duration and a budget of statements, rows
  and bytes returned, clamped to the profile's `grant_max_*` limits. You
  approve that scope once in lockhub (its ticket is never auto-approved);
  then the agent's masked reads of those tables run without a ticket each,
  capped at what is left of the budget. Writes, `unmask`, any filter,
  grouping or aggregate on a PII column, and any predicate or expression
  on a text column no allow rule names still get a ticket. A grant needs
  the agent's lea token. `:revoke` ends
  grants; they end with the session and never survive a restart. See
  [Grants](usage.md#grants).
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
  many rows (or cost more than `explain_cost_refuse`); a recursive CTE is at
  least WARN on PostgreSQL and SQLite, whose planners only guess how often it
  iterates; REFUSE cannot be overridden from the console.
- **PII masking.** At every start the console scans the schema and proposes
  rules for columns that look like personal data (multilingual names and
  types) and that no rule names yet. Every output column is resolved to its
  source columns through aliases, functions, subqueries, CTEs, unions, joins
  and `*`, and masked on that source, not on its label; the engine's origin
  metadata is a second check, and a result whose columns do not match the
  analysis is dropped. Value detectors (email, phone, IBAN, card, opt-in
  national ids) mask the other cells. Mask modes: `redact` (the default),
  `partial`, `email`. Quasi-identifiers (birth date, postal code, gender) are
  never masked unless you accept them one by one, since masking blocks range
  filters, `LIKE` and `ORDER BY` on the column.
- **Statement text.** While mask rules exist, the views that hold the text of
  past statements are refused, in reads and in writes: `pg_stat_statements`
  and `pg_stat_activity`; on MySQL and MariaDB,
  `information_schema.PROCESSLIST`, every `performance_schema` and `sys`
  relation, `mysql.general_log` and `mysql.slow_log`.
- **PII usage.** PII columns may be selected, counted, joined with `=` and
  filtered with `=`, `IN (literals)` or `IS NULL`. Expressions over them,
  `LIKE`, ranges and `ORDER BY` are refused. A filter, grouping or aggregate on
  PII that covers fewer than `k_anonymity` rows (default 5, production 10)
  warns you on the ticket, since it could single out one person; you decide.
  The warning is kept in the audit log. The agent is told nothing of the
  count.
- **No typed values.** Placeholders (`col = '${email}'`) and cell
  references (`col = '${r1.2.3}'`) are not supported: a statement holding
  one is refused at plan time (`E_PLACEHOLDER`), since no value is typed in
  lockhub, and masked cells come back as plain `<redacted>`. The approval screen warns, in red and in the
  audit log, when the agent put a clear value in its statement. Warnings
  never refuse and never carry a value.
- **Quiet failures.** Clients get a generic message, never the server's error
  text, and no timings; once the statement is approved, `query.run` answers
  on a 250 ms quantum (a refusal before approval is not quantized).
- **The AI tightens, the human loosens.** Agents may add mask rules and
  request changes. A config edit that loosens the policy (higher tier, larger
  limits, new host, removed PII rule, ...) only takes effect after you
  confirm it in the console.
- **Audit.** Every login, policy change, refusal, decision, run, catalog
  read and logout is appended to a JSONL audit log (mode 0600): the approval
  before the statement runs, its outcome after. The records of a client
  request name the requester: its uid, pid and account. Never secrets, never
  row data.

Details and threat model: [docs/security-model.md](security-model.md).

## Limitations

- **The console runs only in a separate account.** The image sets it up;
  `locksql console` refuses to start without it and names `locksql doctor`.
  Docker does not separate the console from your own account: whoever can
  run `docker` commands, an agent in your shell included, can attach to the
  console's container. Run the agent in a container of its own, without the
  Docker socket, for that boundary
  ([docs/docker.md](docker.md#agent-in-its-own-container)).
  Malware running as the console account, or as root, is out of scope.
- **k-anonymity is a decision aid, not a guarantee.** A count under `k` warns
  you before you approve; it refuses nothing. Even heeded, it is a query-set-size control: it does not stop
  differencing attacks that combine several approved queries.
- **Masking has limits.** The unmasked columns of a targeted row still
  identify it, and free text without a detector is not masked.
- **Clear results stay on the console's screen.** With the clear results on
  (Ctrl-O, `--show-results`) and for an unmasked run, the clear rows stay in the scrollback of the console's
  terminal, visible to anyone who sees that screen (screen sharing, recording,
  a terminal that logs its output). locksql does not clear it.
- **Transport security is the driver's and the infrastructure's.** locksql
  passes the `tls*` settings to the driver (default `prefer`, libpq's
  semantics) and enforces nothing about them: no refusal at load time, none
  of an authentication method. Its only TLS behaviour is one warning, at
  session start, when the established connection is plaintext. Below
  `verify-ca` an active attacker on the path can intercept or downgrade the
  connection, and obtain the password if the server's authentication
  method sends it (MySQL `mysql_clear_password`, PostgreSQL `password` or
  `md5`); `tls = "verify-full"` (with `tls_ca` for a private CA), an SSH
  tunnel, a mesh or a sidecar prevent it. Through an `ssh` bastion the SSH
  leg is encrypted and verified, but the bastion-to-database leg is
  protected only by `tls`, unless the database runs on the bastion. See
  [Transport security](security-model.md#out-of-scope-and-limitations).
- One console per profile and project, one request at a time. No remote or
  shared consoles, no data export.
