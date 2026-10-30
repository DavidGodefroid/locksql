# Changelog

Release notes also list every commit on the
[GitHub releases](https://github.com/DavidGodefroid/locksql/releases) page.
This file records the changes a user or an agent has to know about.

## Unreleased

### Fixed

- **`DISTINCT` over a PII column is counted.** Like `GROUP BY`, a
  `SELECT DISTINCT` that outputs a PII column now runs the k-anonymity row
  count of its `FROM`/`WHERE`, and warns under `k`. In a correlated
  subquery, a recursive CTE, a `SELECT` without `FROM` or a write, such a
  `DISTINCT` is now refused, as a grouping already was.

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
