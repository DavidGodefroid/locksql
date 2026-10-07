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
  commands and the MCP server as the same OS user as the console.
- **Other local users** are not trusted.
- **Same-user malware** is out of scope (see [Out of scope](#out-of-scope)).

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
   classifier, a privilege audit, an EXPLAIN gate, result caps, then human
   approval.
6. **Results are data, not instructions.**

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| The agent runs a query the human did not approve | The console is the only connection holder. `query.run` needs a one-shot plan id (valid 10 minutes) and an explicit approval, or `--skip-permissions` outside production. |
| The agent loosens its own policy | The socket protocol has no method that loosens policy. Config and PII file edits are detected by a policy fingerprint diff; a loosening is held until the human confirms it. The approved policy is stored outside the repository. |
| Credential leak | Secrets exist only in console memory or the OS keychain. They never go through argv, environment, files, logs, the socket or error messages (errors are sanitised). Config keys named like secrets and DSNs with passwords are refused. Core dumps are disabled (`RLIMIT_CORE=0`, and `PR_SET_DUMPABLE=0` on Linux). |
| Statement smuggling | The classifier refuses several statements, comments, variables, bind parameters and unbalanced quotes, and classifies by keywords outside literals per dialect. Multi-statements are off in every driver; PostgreSQL uses the extended protocol only. Tier `read` is also enforced by a read-only session and transaction on the server. |
| Dangerous functions and statements | File and OS access, engine escape hatches (`ATTACH`, `load_extension`, `dblink`), sleeps, benchmarks, advisory locks, `FOR UPDATE`, session tampering (`SET ROLE`, `set_config`, guarded `SET` targets) and statements carrying credentials are refused at every tier. |
| Server overload | READ statements need `LIMIT n <= max_rows`; `EXPLAIN` estimates the rows examined and refuses heavy plans; a server-side timeout plus a client-side cancel; one request at a time. |
| PII exposure | Column rules proposed from the schema; masking by origin column, with a name-based fallback; aliases and expressions over masked columns are refused; value detectors with checksums; unmasking is per query, shown in red and never auto-approved. |
| Prompt injection through data | Rows are framed as untrusted data in every output; the generated agent instructions say so; control and bidirectional characters are escaped in client output and on the console screen, so data cannot spoof the approval prompt. |
| Type-ahead approval | Pending input is flushed before each prompt (`tcflush` on Unix, `FlushConsoleInputBuffer` on Windows). |
| A client stuck or killed during an approval | The approval is abandoned or times out after 5 minutes; the socket keeps serving. |
| Another local user | The socket lives in a private directory (mode 0700, owner checked; user ACL under `%LOCALAPPDATA%` on Windows). On Linux and macOS each peer's uid must match the console's. |

## Approval

- The approval screen shows the profile, host, database, user, tier, the
  exact SQL, its class, the EXPLAIN summary and verdict, and the PII state.
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

- **Same-user malware.** A process running as the same OS user can read the
  user's keychain session, attach to the console process where the OS
  allows it, or type into the terminal. locksql does not defend against it.
- **Windows peer check.** Windows has no peer credential check for Unix
  sockets; locksql relies on the socket directory's ACL.
- **Transport security.** TLS to the database is not configurable yet.
  PostgreSQL uses `sslmode=prefer` without certificate verification;
  MariaDB and MySQL connect without TLS. Use an SSH tunnel to reach remote
  servers.
- **Write tiers.** Above tier `read`, the human's approval is the gate. The
  classifier assigns the class shown on the screen, but the server does not
  restrict what an approved write statement does within the account's
  privileges.
- **Masking is best effort.** Column rules depend on the rules being right,
  and value detectors catch common formats only. Use a database account that
  cannot read what the agent must never see.
- **Catalog metadata** (database, table, column and index names) is returned
  without approval.
