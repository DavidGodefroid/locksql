# Changelog

Release notes also list every commit on the
[GitHub releases](https://github.com/DavidGodefroid/locksql/releases) page.
This file records the changes a user or an agent has to know about.

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
