# Changelog

Release notes also list every commit on the
[GitHub releases](https://github.com/DavidGodefroid/locksql/releases) page.
This file records the changes a user or an agent has to know about.

## Unreleased

### Fixed

- **Config errors never quote a value.** A secret pasted in the wrong key
  (`credentials = "<token>"`) no longer ends up in the terminal, the logs or
  the agent's output: the errors of the config file (`tier`, `engine`, `tls`,
  `credentials`, `write_functions`, `detectors`, the `limits` durations), of
  `config import` (`needs_local`, the PII rule set names), of the PII rules
  files (a rule's `column` and `mode`), of `locksql profile add` (profile
  name, engine, credentials, vault path, tls), of `config import --local`
  without `=` and of `console --instance` and `LOCKSQL_PII_DIR` name the key
  and the allowed values, never the value given. A PII rules file error
  names the entry (`[[mask]] entry 2: pii rule: unknown mode (want redact,
  partial or email)`).
- lockkit v0.7.2 (was v0.7.1): the same for `ssh.credentials` and the
  `--hub` URL, which the console's errors and start line now show by scheme
  and host only; a `--hub` URL with a user or password is refused.

## v0.11.3 (2026-10-31)

Supported lockhub: as v0.11.2.

### Changed

- The SQLite engine embeds SQLite 3.54.1 (`modernc.org/sqlite` v1.61.0,
  `modernc.org/libc` v1.79.0; was 3.53.4, #107). A statement cancelled, or
  past its timeout, while it waits for a lock under `busy_timeout` now stops
  then instead of waiting out the 2 s, and one whose context is done before
  it starts stops within 1000 VM steps instead of running to completion; a
  write's COMMIT blocked by a reader (rollback journal) still waits the 2 s.
- Release signing is unchanged: CI and the release workflow use
  `sigstore/cosign-installer` v4.1.2, still pinned to cosign v2.6.1 (#108).

## v0.11.2 (2026-10-31)

Supported lockhub: as v0.11.1; `allowed_uids` on a locksql lock under
`lock up` needs lockhub v0.2.5 or later (#139).

### Added

- `locksql console --allowed-uids UID,...`: these uids may connect besides
  the members of `locksql-clients`, as `allowed_uids` of the image's
  `system.toml` (the `ALLOWED_UIDS` build argument) does, for that console
  only, with the release image unchanged: an agent in a container of its own
  whose uid has no account in the console's image (lea's agents run as the
  host user's uid, #139). Set only by whoever starts the console (the human:
  the launcher and the handoff to the console account pass it on; `lock up`
  of lockhub v0.2.5 a lock's reviewed `allowed_uids`); root, leading zeros,
  65534 (nobody) and the console's own uid are refused; every isolation
  check sees the uids (a session or terminal of one is the agent's), and the
  console prints them at start.

### Changed

- The `ALLOWED_UIDS` build argument refuses root (0), leading zeros, the
  console account (10001) and 65534 (nobody); it took any digits before.

## v0.11.1 (2026-10-30)

Supported lockhub: v0.2.1 or later; v0.2.2 or later under `lock up`
([docs/usage.md](docs/usage.md#approving-in-lockhub-hub-mode), #135).

### Upgrading

- Records written by consoles before v0.11.1 stay unsigned under
  `lock audit verify --lock`; their hub denials and the approvals that
  expired before their run show there as decisions not in the log, not as
  problems.

### Fixed

- **Hub decisions are audited with the hub's signature** (#118, #133).
  The `approved` record of a ticket decided in lockhub now carries
  `hub_sig` (the `run` record after it does not), so that lockhub's
  `lock audit verify --lock INSTANCE=PATH` checks it against the decision
  the hub signed instead of reporting it unsigned. The hub's denials are
  now audited too (`denied`, with the reason, approver, facade and
  `hub_sig`), and so is the agent-side renewal (the run of an expired
  ticket, not audited before; renewals asked in lockhub already were): a
  `renew` record for every answer, the new ticket (also when planned again
  as stale) or refused with why (#136, #137). That record carries the
  approver, facade and `hub_sig` when an approval came with the expiry (an
  approval the console could not use; only the first run of the ticket).
- **`locksql doctor` in a `lock up` workspace** (#130, #134). In a project
  whose `lockfamily.yaml` lock up reads (`.lockfamily/`, or the root when
  there is no `.lockfamily`), a `.locksql/` or `.locksql/pii/` the console
  account does not own (but can read) now warns instead of failing with a
  `chown` repair: lock up's console keeps its PII rule sets in its own
  volume (`LOCKSQL_PII_DIR`). Unreadable by the console account, writable
  by group or others (now with a `chmod go-w` repair), or a symbolic link
  still fails; outside a lock up workspace nothing changes.

## v0.11.0 (2026-10-30)

### Added

- **`LOCKSQL_PII_DIR`** (lockhub#41). With it, the console keeps its PII
  rule sets in that directory instead of the profile's: `lock up` sets it
  to the console's own volume, its copy of the profile being read-only, so
  a first start no longer needs a rule set written beforehand by locksql's
  own launcher. The profile's sets are copied in once; from then on the
  console's copy is in force. At each start the profile's new mask rules
  are added to it; nothing else of the profile's set is (allow rules,
  removed masks, mode changes), and a profile set that still differs is
  told at start. It must be an absolute path (a relative one is a config
  error).

### Changed

- **Hub mode: re-approval, reveal and rollback** (lockkit v0.5.0 and v0.6.0).
  - An expired ticket (pending past its TTL, or approved but the approval
    aged before the run) is asked again: `query.run` with it answers
    `pending` with a new ticket that names the expired one and the inputs
    of the plan hash that moved since (`state`: the definitions the
    statement resolves to, `policy_fp`, `sql`, …; names only, never
    values). The statement is planned again first, read-only, as the run's
    recheck does. A renewal asked for in lockhub is checked too: the policy
    and the profile now; the statement and its definitions are named
    `unchecked` on it (no session there), and checked at the run (stale,
    with a new ticket, if they moved). A changed policy is no
    renewal: plan again. Before, an expired ticket answered `denied`.
  - The clear approval screen stays in the plan, for a pinned local facade
    to reveal (Ctrl-O, `--facade-keys-file`) or a pinned device; the hub
    still gets the masked one. Reveals and renewals are audited (`reveal`,
    `renew` records).
  - The separated-setup handoff forwards every hub flag lockkit registers
    (`--facade-keys-file`, `--devices-file`, `--require-device`,
    `--seal-clear`, `--hub-plain-http`); a relative facade keys or devices
    file is made absolute like the hub key file.
  - `--facade-keys-file` and `--devices-file` are trust anchors checked
    like `--hub-key-file`: a link, a file or directory writable by its
    group or others, or one owned by neither root nor the console's
    account is refused before any prompt, and the console reads its own
    0600 copy in its state directory.
  - Hub mode off (rollback): a console started without `--hub` after
    running with it withdraws the plans hub mode left pending (the hub
    hears of it at the next start with `--hub`) and answers a run of their
    tickets with the error `withdrawn` (`CodeWithdrawn`), instead of
    `invalid_params`. Nothing of them runs.

- **The console runs on lockkit's console** (#96). The request loop, the
  live switches (Shift+Tab, Ctrl-O, `:unmask`), `:status`, `:review` and
  the policy polling, the session limits and the reconnection are
  lockkit's `console.Server`; locksql is its backend (the SQL methods, the
  approval screen, the masking). The approval screens, the `status`
  answer, `:status` and `:review` are unchanged and pinned by the golden
  screens. Other differences:
  - a tightening read from the files that cannot be saved as the approved
    policy now applies anyway (audited `policy`/`unsaved`); before, the
    looser policy stayed in force. `pii.add` then answers ok;
  - a tightening locksql cannot compile (an unknown detector) ends the
    session instead of leaving the looser policy in force;
  - a change request beyond the 20 queued is refused ("too many pending
    change requests") instead of dropping the oldest; an empty or too long
    one says "change must be 1 to 500 bytes";
  - any request naming a hub `ticket` on a console without its hub is
    answered `CodeWithdrawn`, whatever the method;
  - a request handler that panics is told on the console (escaped) and
    audited as a failed `run`;
  - at level 2 the fingerprint prompt names what it decides ("to apply
    the policy changes");
  - credentials that expire without a way to reconnect end the session as
    "connection lost" (was "credentials expired");
  - a change request is no longer checked for valid UTF-8 (it is escaped
    for the console either way);
  - `pii.add`: a rule the on-disk rule file refuses answers
    `CodeInternal` (was `CodeInvalidParams`), and error texts go through
    the sanitiser;
  - in hub mode, three failed writes in a row of the hub's own records
    (reveals, renewals) end the session, counted apart from the console's
    own records; while a loosening approved at `:review` is being saved, a
    renewal asked from lockhub may see its fingerprint, and goes stale at
    the run if the save fails.

- Pinned to lockkit v0.7.1.

- **Plan hash coverage** (#119). The plan hash also covers the operators
  a view, rule, policy, default or `CHECK` (of a table or a domain) uses,
  with their functions and those of their commutators and negators
  (`pg_depend` records them against the operator, not its function), the
  enum labels in their sort order and the attributes of the composite
  types of the columns, and, for a `DROP` or `ALTER` with `CASCADE`, every
  relation `pg_depend` says it would drop or change along with its
  relations (views over them, policies, constraints, defaults and
  triggers that use them, inheritance children, owned sequences and their
  users, columns of their row type, recursively; the functions and
  domains it would drop are not hashed, and `DROP FUNCTION/DOMAIN/SCHEMA
  ... CASCADE` or `DROP TYPE` of an enum are not walked). The function of
  an operator counts as one more level of the 8-level bound. Plan hash
  version 3: plans made by v0.10.0 are answered `E_STALE`.

- **Hub-mode rowcount bound follow-ups** (#120). On MySQL/MariaDB and
  SQLite the ticket of a write also names the triggers of the tables it
  names. An `INSERT`/`REPLACE ... VALUES` is bounded by at least its
  number of rows (EXPLAIN gives no estimate for them on MySQL and SQLite;
  twice that for `REPLACE` and `ON DUPLICATE KEY UPDATE` on
  MySQL/MariaDB). A write whose rows cannot be checked before a commit (a
  non-transactional table on MySQL/MariaDB) is refused with
  `E_STATEMENT_KIND` instead of the generic failure, so the agent does
  not retry it. The MySQL/MariaDB check reads only the tables of the
  current database and of the schemas the statement qualifies a name
  with: a non-transactional table of another schema no longer refuses an
  unrelated write that uses the same word, and the server's own schemas
  are no longer exempt when named bare from within them.

## v0.10.0 (2026-10-30)

### Changed

- **Approvals are decided by lockkit's console.** The console closes its
  approval screen with lockkit's `console.Asker` (same prompt, same answers,
  same audit records): the screens are pinned byte for byte by golden tests
  (`internal/console/testdata/screens`). The upcoming hub mode then plugs
  into one place shared by every Lock.
- **Chained audit log.** Each audit record now ends with `prev_hash`, the
  hash of the line before it (lockkit's `audit.Verify`
  checks the chain and names the first record edited, removed, inserted or
  reordered). Apart from `prev_hash` a record is the 0.9 line, byte for byte. Existing logs
  are not rewritten: new records chain onto their last line. Records of
  hub mode will also carry `ticket`, `approver`, `facade` and `hub_sig`.
  `locksql stats` reads old and new logs alike.

- **Plan hash.** `query.plan` answers a `plan_hash` (`sha256:…`) of the
  normalised statement, the profile, the policy fingerprint and, on
  PostgreSQL, the effective `search_path` and the definitions of every
  object the statement resolves to: functions and operators (body,
  settings, `SECURITY DEFINER`, grants), views (`pg_get_viewdef`), rules,
  triggers and their functions, row-level policies and the row-level
  security switches, grants, column defaults and generated columns,
  constraints, partitions and inheritance, followed through views, rules,
  triggers, policies, defaults and constraints (and, for a write, into the
  tables whose foreign keys cascade from it). Objects nested deeper than 8
  levels refuse the plan rather than go unhashed. Not followed: the
  functions a PL/pgSQL body calls (only its own source is hashed) and what
  dynamic SQL reaches. `query.run` checks it before the approval, then again in the
  statement's own transaction just before and just after the statement: a
  plan whose objects changed is refused with the new code `E_STALE` (the
  statement rolled back when they changed during it). `CREATE OR REPLACE`
  keeps the OIDs, so the definitions are hashed, not the OIDs.
  The hash also covers the domains of the columns (base type, `NOT NULL`,
  default, `CHECK` constraints and their functions, through a domain over
  a domain) and, for a DDL statement, the event triggers and their
  functions (#105). A write follows only the tables whose foreign keys
  reference it with an action that changes their rows (`CASCADE`, `SET
  NULL`, `SET DEFAULT`): a `NO ACTION`/`RESTRICT` key only refuses the
  write (the key itself is hashed), so a change in a wide graph of such
  tables no longer answers `E_STALE`. Plan hash version 2.

- **Hub mode** (`locksql console --hub URL --hub-key-file PATH --instance
  NAME`, written by `lock up`; `locksql hub-key --instance NAME` prints the
  instance key to pin). The human decides in lockhub instead of this
  terminal: `query.run` answers `{"status":"pending","ticket":…,"instance":…}` (a result,
  not an error; over MCP, lockkit's standard pending answer), the plan kept in lockkit's persistent plans store, bound to
  the client's account, the policy fingerprint and the plan hash; the ticket
  carries the approval screen with every value of the statement masked.
  `locksql_run` with `ticket` (CLI: `locksql run TICKET`) runs it once the
  hub's signed decision approves it: the statement is planned again from
  its stored text and its plan hash compared before anything runs, then
  checked again in the statement's transaction. A changed plan answers
  `{"status":"stale","ticket":<new>}` with a new ticket; a denial carries the
  human's reason. `--auto` is refused with `--hub`, Shift+Tab does not turn
  auto mode on, and statements with `${placeholders}` are refused (values
  are typed in the console).
- **Plans and tickets bound to the requesting agent** (hub mode, #91).
  `query.plan` and `query.run` carry `requester` (the agent's lea name and
  the hash of its `LEA_AGENT_TOKEN`, from lockkit's
  `mcpkit.RequesterFromEnv`; the CLI and the MCP server send it). A plan id
  (in every mode) or ticket presented by another agent is refused with
  `CodeWrongRequester` (-32007) and stays its requester's. Not a security
  boundary: agents of one account can read each other's token.
- **Rowcount re-check of a hub-mode write** (#91). A write's ticket shows
  `rows changed: at most N` (twice the planner's estimate from an `EXPLAIN`
  of the write, at least 10 more); the run counts the rows it changed in
  its own transaction before the commit, and past the bound rolls back and
  answers stale with a new ticket whose screen says how many rows it would
  have changed. PostgreSQL, MySQL/MariaDB and SQLite. The bound counts the
  statement's own rows: the ticket names the triggers, rules and cascading
  foreign keys it does not count (PostgreSQL); a data-modifying `WITH` is
  refused in hub mode; on MySQL/MariaDB a write to a non-transactional table
  or a view is not run, and a `ROLLBACK` that warns is a failure. The
  screen names the requester by its kernel identity, the lea name as its
  unverified claim.

- Pinned to the lockkit v0.3.1 release (hub support) instead of a commit of lockkit main.

### Fixed

- **Becoming production at runtime re-applies the start-up refusals**
  (#93, as lockkit#34). When the policy in force becomes production while
  the console runs (a tightening, applied at once), an X11 session or core
  dumps that could not be disabled now end the session (`refused after the
  profile became production`), as they refuse a production profile at
  start-up; before, only the privilege audit was run again.

- **The separated-setup handoff keeps `--hub-plain-http`** (#111). The
  console-account command printed (or run) for `locksql console --hub
  http://… --hub-plain-http` now carries the flag; without it the console
  refused the http:// hub (lockkit v0.3.1). The console usage line lists
  the flag.

- **Audit writes fail closed** (lockkit #5). An approved or
  auto-approved query whose approval record cannot be written runs
  nothing: the agent gets `CodeInternal` ("the console could not record
  the approval in its audit log"), the human sees why; three failed
  writes in a row end the session. Denials stay denials.

- **Widenings take effect only once recorded** (#102). Auto mode on,
  clear results shown, `:unmask` allowed and a loosened policy approved
  (at `:review` or at start) write their audit record first; if it cannot
  be written they stay off (the policy is neither saved nor applied, and
  the console does not start), and the console says so. Narrowing still
  applies at once.

- **No widening switch while a prompt waits.** Shift+Tab (auto mode on),
  Ctrl-O (clear results on) and `:unmask` are refused, with a line saying to
  answer the prompt first, while the console waits for an approval, a typed
  value, a refusal to acknowledge or a reconnection; switching auto mode or
  clear results off stays allowed. At level 2 a second finger prompt no
  longer nests in the pending one (lockkit #2).

- **`DISTINCT` over a PII column is counted.** Like `GROUP BY`, a
  `SELECT DISTINCT` that outputs a PII column now runs the k-anonymity row
  count of its `FROM`/`WHERE`, and warns under `k`. In a correlated
  subquery, a recursive CTE, a `SELECT` without `FROM` or a write, such a
  `DISTINCT` is now refused, as a grouping already was.
- **`MIN` and `MAX` of a PII column are redacted like other aggregates.**
  Their result is now plain `<redacted>` in every mode: no `partial` or
  `email` mask, no cell reference, and it cannot be compared or joined.
  `MIN`/`MAX` of an unmasked column and `ANY_VALUE` are unchanged.

## v0.9.0 (2026-10-28)

### Changed

- **One `locksql` command, backed by Docker.** `scripts/install.sh` now
  installs the `locksql` launcher, a shell script, instead of a binary:
  every command, `locksql console`, `locksql version`, `locksql mcp` and the
  others, runs in the release image `ghcr.io/davidgodefroid/locksql:X.Y.Z`
  (`-vault` with the vault CLI, `LOCKSQL_VAULT=1`), with the account and the
  volumes it needs (console as `locksql`, `init`/`profile` as you,
  `doctor --fix` as root, the rest as `agent`). The `locksql mcp` that
  `locksql init` writes now works as is: the `claude mcp add ... sh -c
  'exec docker run ...'` step is gone (such entries keep working).
  `locksql version` prints the launcher's and the image's versions;
  `locksql update` replaces the launcher (signature and checksum checked)
  and pulls the image. The image's cosign signature is verified at install
  and update, and the launcher runs it by that verified digest. `LOCKSQL_IMAGE` runs an image of your own,
  `LOCKSQL_DOCKER_ARGS` adds `docker run` arguments. The release publishes
  the image, signed with cosign, and no longer the `.deb`, `.rpm` and `.apk`
  packages of the binary; the archives keep the binary, for an agent that
  runs in a container of its own, and now hold the launcher.
- **The launcher's console is confined and per project.** It runs with no
  capability, no privilege gain, a read-only root with a small `/tmp`, at
  most 256 processes and 1 GB, in a container of its own per project
  (`locksql-console-<n>`, `LOCKSQL_CONSOLE_NAME` to name it). An explicit
  `--project DIR` of `console` or `profile` is the project mounted.
  `LOCKSQL_READONLY_PROJECT=1` mounts the project read-only but for
  `.locksql/`, which on Linux the console checks by device and inode
  against what the launcher checked (lea runs its console this way).
  `VAULT_CACERT` reaches the console with its file. Release signatures
  (archive and images) are bound to the exact tag installed.

### Removed

- **The host install.** The binary refuses `locksql install`,
  `locksql setup` and its own `locksql update` ("locksql runs in Docker"),
  and bare `locksql` prints the help instead of leading to the host setup.
  Migrating from a host install: run the new `install.sh`, which replaces
  the binary with the launcher; what `sudo locksql install` created (the
  `locksql` account and `locksql-clients` group, `/etc/locksql/`, the socket
  directory and `/etc/tmpfiles.d/locksql.conf`) stays until you remove it
  ([docs/docker.md](docs/docker.md#migrating-from-a-host-install)). The
  code goes in a later release.

### Added

- **`locksql config export` / `locksql config import`.** Share profiles
  and PII rule sets with a team as one versioned JSON file. The export
  holds no secret, no `user` (unless `--include-user`) and no file of one
  machine (`tls_ca`, `tls_cert`, `tls_key`, `ssh.key` are named in
  `needs_local` and given on import with `--local`). The import is strict,
  validates the merged result before writing, refuses any loosening
  without `--allow-loosen` (the console still asks at its next start),
  keeps `*.bak` backups and writes a `config_import` audit record. See
  docs/usage.md, "Share a configuration with your team".
- **Wildcards inside a PII rule segment.** A `*` may now start or end a
  segment of a `db.table.column` rule, so `*.*.*email*` covers
  `contact_email`, `email_backup` and `Email`, and `app.user*.phone` covers
  every table whose name starts with `user`. A `*` anywhere else in a
  segment is still refused. A new wildcard mask rule only tightens; a new
  wildcard allow rule is a loosening the human confirms in `:review`, as
  every added allow rule.
- **More column names in the startup PII scan.** The scan now proposes
  `mail`, `e_mail`, `login` (not a date or time column such as
  `last_login`), `username`, `nickname`, `displayname`, `pseudo` and
  `handle` for masking, and asks about free-text columns (`notes`,
  `comment`, `bio`, `remarks`, ...) and coordinates (`lat`, `lng`,
  `latitude`, `longitude`) as quasi-identifiers (`[y/N]`). `mail_id`,
  `login_count` and other metadata columns stay out (lockkit#21, v0.2.1).
- **`write_functions = "allowlist"`.** An opt-in profile setting that
  applies the read function allowlist to writes: every function an
  `INSERT`, `REPLACE`, `UPDATE` or `DELETE` calls, at any depth, must be
  allowlisted (plus key generators such as `gen_random_uuid`, `nextval`,
  `UUID`, `SYS_GUID`, `randomblob`, MySQL `VALUES(col)` in `ON DUPLICATE
  KEY UPDATE`), or the write is refused with
  `E_FUNCTION`. Schema-qualified calls, calls through quoted or non-ASCII
  names or with a blank before `(`, `CALL`, `MERGE` and writes the parser
  does not read are refused, and every column the write names is resolved
  against the catalog (PostgreSQL attribute notation `t.f` calls `f(t)`).
  The default stays `"denylist"`; turning the allowlist off is a policy
  loosening confirmed in the console, and existing approved policies keep
  their fingerprint.
- **Databases that publish no port** (#35). A profile can set
  `proxy_command`, an argv whose stdin and stdout carry each database
  connection, as OpenSSH's `ProxyCommand`: `docker exec`, `podman exec`,
  `kubectl exec`, or `ssh ... socat` to a server bound to its container's
  loopback or to a Unix socket on a remote host. It runs without a shell, as
  the console account, in an empty private directory, without a terminal and with a scrubbed
  environment, and may not name a file inside the project (symbolic links
  resolved, case folded on macOS and Windows) nor carry a secret
  (`--password=`, `MYSQL_PWD=`, mysql's `-pSECRET`); closing the connection
  ends the command and every process it started (a process group, a job
  object on Windows). The argv is part of the approved policy (any change
  loosens it), its stderr ends a connection error, and `locksql doctor`
  checks the program. `docs/usage.md` gains "Databases that publish no
  port" with the recipes; `docs/docker.md` shows how to add the client a
  recipe needs to the console's image, which ships none, and why not to
  mount the Docker socket there.

### Changed

- **Function names are matched exactly.** A function call must use an
  unquoted name in ASCII letters, and in MySQL no blank between the name and
  `(`, so that the allowlist checks the function the server calls:
  `"lower"(x)`, `` `lower`(x) ``, non-ASCII spellings and MySQL `lower (x)`
  are now refused with `E_FUNCTION`. Write `lower(x)`.
- **Release supply chain pinned.** `scripts/install.sh` checks the cosign
  signature of `checksums.txt` against the release workflow run for a
  version tag (`^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v[0-9]`,
  as `locksql update` does), instead of any workflow or ref of the
  repository, and now requires cosign: without it the script stops, and
  `LOCKSQL_SKIP_COSIGN=1` installs without the signature check (the former
  `LOCKSQL_REQUIRE_COSIGN` is gone). `locksql install` prints the sha256 of
  the binary it copies beside its prompt, and its root script checks its
  copy against it for every source, not only with `--trust-binary`.
  `locksql update`'s package instructions check the signature and checksum
  before `apt`, `dnf` or `apk`, and stop at the first failed step. The
  workflows' actions are pinned to commit SHAs, and the release job pins GoReleaser, cosign and syft.
- **PostgreSQL: allowlisted functions overloaded in the database are
  refused.** PostgreSQL picks the best match for an unqualified function
  over every schema of the search path, so a `public.lower(varchar)` runs
  instead of `pg_catalog.lower(text)` for a `varchar` argument. Before a
  read (and a write under `write_functions = "allowlist"`) is planned, and
  again just before it runs, the console looks up the functions and
  operators it uses and refuses it with `E_FUNCTION` when one is also
  defined outside `pg_catalog`. Those owned by an extension are not
  counted.
- **PII rules in named sets, one per profile by default.** PII rules no
  longer live in one `pii.toml` shared by every profile of a scope: each
  profile uses the set named by its new `pii_rules` key, by default its own
  name, kept in `pii/<set>.toml` next to the config. Profiles on unrelated
  servers no longer see each other's rules (an `[[allow]]` or a wildcard
  rule written for one product no longer reaches another); profiles on
  isomorphic databases (dev, uat, prod) share rules by naming the same set.
  Changing `pii_rules` is a loosening, approved again at the next start.
  Upgrading: at the first start the existing `pii.toml` is moved to
  `pii/default.toml` (the set `default`), with a one-time notice; profiles
  approved before keep using it until they get a `pii_rules` key, and any
  new profile starts with its own, empty set.
  The console warns at start when a profile without `pii_rules` shares
  its set by accident (names that differ only by case, a name another
  profile uses as its `pii_rules`, or a profile named `default`). Two
  consoles starting together no longer fail on the migration.
- **Docker is the only documented deployment.** The README Quick start and
  Install, `docs/usage.md` and the site now describe only the Docker setup:
  build the image, `locksql init`, `locksql profile add`, `locksql doctor
  --fix` as root in the image, wire the agent with `docker run ... locksql
  mcp`, run the console container. `docs/docker.md` is the setup guide, and
  for the stronger boundary it recommends running the agent in its own
  container without the Docker socket. The install script, packages,
  `locksql install`, `locksql setup`, `locksql update`, the desktop and
  session setups and WSL2 are no longer documented or supported; their code
  is unchanged.
- **Vault token asked at start (#51).** With `credentials = "vault"` the
  console asks `Vault token for <VAULT_ADDR>:` (no echo) before the first
  Vault read, instead of relying on a `vault login` of the console account
  and its `~/.vault-token`. The token is passed to the `vault` CLI as
  `VAULT_TOKEN` in the child's environment only (never argv, disk, logs or
  the audit trail), kept in memory for the session so reconnects and lease
  renewals do not ask again, and wiped when the console ends. When Vault
  refuses a read (an expired or revoked token, or a policy that may not
  read `vault_path`: Vault does not tell which), the console says `Vault
  refused the read` and asks for a token again, mid-session too; three
  refusals in a row stop the connection. Needs lockkit v0.2.0.
- **Clear results refused at desktop security level 1.** When the console
  runs in a desktop terminal of the console account without a fingerprint
  reader, the agent's account can read its window, so the clear results
  would reach the agent. `locksql console --show-results` is now a
  configuration error there (`level 1 does not accept --show-results: the
  agent's account can read this window`), raised before any prompt or file
  write, and Ctrl-O or `:results` leave the results masked with `results
  stay masked at level 1: the agent's account can read this window`
  (nothing audited), as at level 2. `--auto` and `--allow-unmask` are
  unchanged. Levels 0 (session shape, Docker) and 2 are unchanged.
- **More statements refused at every tier.** The classifier's denylist
  now also refuses PostgreSQL notification, logical decoding, replication
  slot and origin, backup and recovery control and statistics reset or
  override functions; MariaDB Spider, MySQL keyring, audit log, group
  replication, version token and locking service functions and more
  lib_mysqludf_sys names; SQLite `fsdir` and `zipfile`. DDL that reaches the
  server's filesystem, another server or native code is refused too:
  `DATA|INDEX DIRECTORY`, `ENGINE=FEDERATED|CONNECT|SPIDER`, `CREATE SERVER`,
  foreign tables and data wrappers, `CREATE TABLESPACE`, `ADD DATAFILE`,
  `LANGUAGE C`, `internal` and untrusted languages, `CREATE LANGUAGE` and the
  SQLite `fsdir`, `zipfile` and `csv` modules. The security model now says
  the denylist is best-effort above tier `read`, where approval is the
  control.
- **Internal: locksql runs on lockkit.** The product-neutral half of
  locksql moved to [lockkit](https://github.com/DavidGodefroid/lockkit),
  shared with the other lock* tools (see CONTRIBUTING.md). No user-visible
  change: same commands, flags, messages, config keys, IPC protocol, audit
  lines, approved-policy fingerprints (no re-approval after the upgrade),
  exit codes, paths and wired agent files, each pinned by a golden test.

### Fixed

- **Value detectors (#17).** Unicode e-mail addresses
  (`müller.hans@exämple.de`) are masked whole; phone, IBAN, card and
  national-id values grouped with U+00A0, U+202F or U+2009, or written
  with full-width digits, are masked; integral `float4`/`float8` cells go
  through the detectors like integers. A new opt-in detector,
  `phone_loose`, masks national numbers without a trunk 0
  (`(415) 555-2671`, `612 345 678`); the default `phone` rule is unchanged
  and now documented next to the `detectors` setting. Detectors only mask
  more than before (lockkit v0.2.0).
- **`.locksql/` in Docker.** The console account exists only in the image,
  so nothing gave it the project's `.locksql/` directory, and an agent
  running as your uid could replace `pii.toml`. `locksql doctor --fix` now
  runs as root in the image (`docker run --user 0 … locksql doctor --fix
  --yes`, see docs/docker.md) without `sudo`, and its hint names the
  console account by uid, which the host can use.
- **Root repairs no longer follow symbolic links.** `doctor --fix` and
  `setup` changed `.locksql/` and its files by path as root; a symbolic
  link put there by the agent's account would have handed its target to the
  console account, or made it world-readable. The root script now enters
  the directory, checks its real path and changes `.`; a `.locksql` that is
  a link fails the check with no repair. A `config.toml` or `pii.toml`
  that is a symbolic or hard link is refused, with a message, rather than
  made readable.

## v0.8.0 (2026-10-19)

### Added

- **`locksql profile add`.** The database profile step of `locksql setup`
  alone, for a console in a container (docs/docker.md): it appends a profile
  to `.locksql/config.toml` from its questions or its flags. In a container
  the wizard offers `host.docker.internal` as the host and never the
  keychain.
- **The setup wizard asks for TLS and Vault.** A remote host gets a `tls`
  question (default `verify-full`), and the password source is now `ask`,
  `keychain` or `vault` with its path (`--tls`, `--credentials vault`,
  `--vault-path`).
- **A Docker image with the vault CLI.** `docker build --target vault`
  adds the HashiCorp Vault CLI, checked against pinned sums, for
  `credentials = "vault"`. The default image stays without it.

- **`locksql update`.** Replaces `/usr/local/bin/locksql` with the latest
  release, or the one `--version` names, from your own account, asking for
  `sudo` only for the final copy. Before that copy it checks the cosign
  signature of `checksums.txt` against this repository's release workflow
  (cosign is required: there is no unsigned path), the archive's checksum and
  the new binary's version. The root script checks a root-owned copy against
  the printed sha256 before installing it. A package's `/usr/bin/locksql`, or
  a binary root does not own alone, is refused with how to upgrade it. An
  older release needs `--allow-downgrade`.
- **New-version notice.** `locksql console` and `locksql doctor` print on
  stderr when a newer release exists, with how to upgrade for the way
  locksql was installed. At most one request a day: a single GET of
  `releases/latest`, without added header or identifier, 2 s timeout, cached
  in `$XDG_CACHE_HOME/locksql/update-check` (0700/0600). Failures print
  nothing; the output and exit codes do not change. In a separated setup the
  console checks in the console account only. `LOCKSQL_NO_UPDATE_CHECK=1`
  turns it off, and is passed on through the console handoff. `locksql mcp`
  never checks.

### Upgrading

- From this release on, `locksql update` replaces running `scripts/install.sh`
  again. Restart the console after an update.

## v0.7.0 (2026-10-18)

### Added

- **Credentials from HashiCorp Vault.** `credentials = "vault"` with
  `vault_path = "database/creds/<role>"` (or a KV secret) makes the console
  read the database user and password with `vault read -format=json` at
  every connection, as the console account and with its Vault token. The
  login is kept in memory only, never in the keychain or on disk. Before a
  dynamic login's lease ends, the console reconnects with a fresh one, and
  the audit log names the user of each login. Errors tell apart a missing
  CLI, a missing or refused token, an invalid path and an invalid role.
  `locksql doctor` checks the CLI and, in separated mode, fails when the
  agent's account holds a Vault token.

### Upgrading

- Nothing to do. Switching a profile to `credentials = "vault"` or changing
  its `vault_path` is a loosening the console asks you to approve.

## v0.6.0 (2026-10-14)

### Added

- **Approval mode in the audit log.** Every approval record (a run, a
  policy change, an unmask) now carries `approval`: how the human approved.
  The existing separated setup writes `"session"`, a console in a login
  session of the console account.
- **Groundwork for a desktop console.** The console can now run in a
  window of the console account on the agent user's Wayland desktop, with
  approvals typed (`desktop+typed`) or confirmed with a fingerprint read by
  `fprintd` (`desktop+fingerprint`). Nothing starts it yet: the launcher
  comes in a later release, and existing installs keep the session setup.
  `system.toml` accepts a `finger` key, the fprintd name of the finger
  enrolled for the console account (for example `left-index-finger`); an
  unknown name is refused.

### Changed

- The console checks its isolation before any prompt or state change. A
  production profile in an X11 session is now refused before the policy
  review: before, an approval could be saved and only then refused.
- The startup line of the separated setup reads
  `session mode: boundary: kernel` instead of
  `separated mode: console account …, clients of group …, display …`.

### Upgrading

- Nothing to do. A script that reads the console's startup line must match
  the new text.

## v0.5.2 (2026-10-11)

### Changed

- **k-anonymity warns instead of refusing.** A PII filter, group or
  aggregate that covers fewer than `limits.k_anonymity` rows is no longer
  refused after approval with `E_K_ANON`. The counts now run before the
  approval prompt, and each count under k adds a `▲ k-anonymity` warning
  to the approval frame, just above `Approve? [y/N]`: the statement could
  single out one person or infer a masked value by cross-checking. You
  decide: `y` runs it, `n` denies it as usual. In auto mode the statement
  runs, and the warning is printed in its frame and kept in the audit
  record's `warnings`. A count that cannot run warns the same way.
- The agent learns nothing of the counts: no refusal code, the same answer
  whether a count is under k or not, and in auto mode a response time
  levelled from the counts on. Row estimates stay hidden under a PII filter.
- The structural PII rules are unchanged: equality only on PII columns, no
  `LIKE`, range or negation, masking, cell references and placeholders still
  refuse as before.
- `E_K_ANON` is retired. No refusal carries it; it stays a known code so
  that `locksql stats` still counts it in older audit logs. The MCP server
  instructions and the agent instructions written by `locksql init` no
  longer say that a k-anonymity refusal is final: rerun `locksql init` to
  refresh them.
- [docs/security-model.md](docs/security-model.md) now describes
  k-anonymity as a decision aid for the human, not a guarantee.
