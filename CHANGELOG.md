# Changelog

Release notes also list every commit on the
[GitHub releases](https://github.com/DavidGodefroid/locksql/releases) page.
This file records the changes a user or an agent has to know about.

## Unreleased

### Changed

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
