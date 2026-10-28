# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
open <https://github.com/DavidGodefroid/locksql/security/advisories/new>
(the "Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the locksql version (`locksql version`) and your OS;
- the database engine and version, if relevant;
- the steps or input needed to reproduce the issue, and its impact.

Never include real credentials or real personal data in a report.

You will get an acknowledgement within a week. Fixes are released as soon as
possible, and the advisory is published with credit to the reporter unless
you ask otherwise.

## Scope

The threat model is in [docs/security-model.md](docs/security-model.md).
Issues of interest include, among others:

- a way for a client (CLI or MCP) to run a statement without the human's
  approval, or to loosen the policy without confirmation;
- a secret reaching argv, the environment, a file, a log, the socket or an
  error message;
- a statement that the classifier accepts in a lower class than it belongs
  to, or a forbidden construct that it accepts;
- unmasked personal data in a result where a rule or detector should apply;
- client-controlled text that can spoof the console's approval screen.

Attacks that require running code as the same OS user as the console are out
of scope, as documented in the threat model.

## External review

No external review of locksql has been done yet. The threat model
([docs/security-model.md](docs/security-model.md)) and the parser and
analyzer that decide what is masked (`internal/sqlast`, explained in
[docs/pii-analysis.md](docs/pii-analysis.md)) have been reviewed by the
maintainer only. An external review is a criterion for 1.0
([docs/1.0.md](docs/1.0.md)).

To contribute one:

- Review the threat model, `internal/sqlast`, `internal/pii` or
  `internal/console`, or try to break them: a statement that returns an
  unmasked value, runs without approval or loosens the policy.
- Report vulnerabilities privately, as above. Write up the rest (scope,
  version or commit reviewed, method, findings, and what you did not
  cover) in a public issue or a pull request adding the report under
  `docs/reviews/`.
- Reports are linked here with the reviewer's name (or anonymously if you
  prefer) and the fixes they led to.

## Verifying a release

Each release's `checksums.txt` covers its archives and Linux packages, and is
signed keylessly by `.github/workflows/release.yml` run for the release's tag.
Check the signature against that workflow and a version tag, not any
workflow of the repository, then the file you downloaded against
`checksums.txt`:

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v[0-9]' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

`scripts/install.sh` and `locksql update` run the same check and refuse to
install without cosign (`LOCKSQL_SKIP_COSIGN=1` is the script's explicit
way past it). `locksql install` prints the sha256 of the binary it copies
beside its prompt, and its root script checks the copy against it.

The actions the workflows run are pinned to full commit SHAs, and the
release job pins the versions of GoReleaser, cosign and syft.

Release tags are annotated, not yet signed (`v0.1.0` to `v0.8.1`). From
the first signed tag on, its key is published on the maintainer's GitHub
profile (<https://github.com/DavidGodefroid.gpg>, or the SSH signing keys),
and a tag can be checked before you build from it:

```sh
git verify-tag vX.Y.Z
```

## Supported versions

Only the latest release receives security fixes.
