# Contributing to locksql

Thanks for your interest. Bug reports, fixes and new test cases are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach. locksql is a security tool: features that loosen a default, add a
  way around the console, or add a dependency need a clear case.
- Code, comments, docs and commit messages are in English.
- Changes to the parser, the analyzer or the masking start with
  [docs/pii-analysis.md](docs/pii-analysis.md), which explains how they fit
  together.
- By contributing you agree that your work is licensed under the Apache
  License 2.0.

## Where the code lives

The product-neutral half of locksql (console socket and protocol, peer
checks, approvals, terminal, isolation checks, secrets, audit log, config
lookup and the approved-policy store, personal-data detectors, output
caps, error scrubbing, signature checks, MCP plumbing, agent wiring) lives
in [lockkit](https://github.com/DavidGodefroid/lockkit), shared with the
other lock* tools; its GUIDE.md is the contract. This repository keeps what
is SQL: engines, the classifier, the parser and provenance analyzer, the
SQL policy (tiers, limits, column rules), the SQL refusal codes, locksql's
console modes and start-up, its MCP tools and its agent texts.

A fix in a shared package goes to lockkit first; locksql then pins the new
lockkit version in `go.mod`. To work on both at once, add an uncommitted
`go.work` (`use (. ../lockkit)`, listed in `.git/info/exclude`).

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later. Every target builds with `CGO_ENABLED=0`; keep
dependencies pure Go.

## Tests

```sh
go vet ./...
go test ./...
```

Unit tests need no database: SQLite runs in-process, and the EXPLAIN
fixtures under `testdata/explain/` cover the other engines.

The module also builds for Windows, where locksql refuses to run (it runs
in Docker, see [docs/docker.md](docs/docker.md)), and CI runs the unit tests on
`windows-latest`. A test file that needs Unix accounts, file modes, sockets
or terminals starts with `//go:build unix`; a single test skips with
`t.Skip` and the reason. To check that the tests still compile for
Windows:

```sh
GOOS=windows go vet ./...
GOOS=windows go test -exec /bin/true ./...
```

### Integration tests

Integration tests run real servers in Docker (MariaDB 10.11 and 11.4, MySQL
8.0 and 8.4, PostgreSQL 13 and 17). Containers are named `ls-it-*`, bound to
`127.0.0.1` and removed at the end.

```sh
go test -tags integration ./test/integration/
```

- `LOCKSQL_IT_MYSQL` and `LOCKSQL_IT_POSTGRES` select a subset of versions.
- The canary suite (`test/integration/canary_test.go`, `-run Canary`) seeds
  masked columns with random `CANARY-<id>` values on every server and on
  SQLite, runs a generated corpus of reads (joins, CTEs, unions, casts,
  JSON, string, aggregate and window functions) through plan, approval, run
  and masking, and fails when an answer to the agent holds a canary, 4
  letters of one, or its hex, base64 or reversed form. A refusal is safe. A
  leak it finds is fixed in the analyzer or the masker, with a regression
  case in `internal/sqlast/adversarial_test.go` or the `pii` tests; a new
  construct goes in `canaryDialectFor`.
- The console test drives the binary in a pseudo-terminal and runs on Linux
  only.
- `LOCKSQL_TEST_KEYCHAIN=1` also runs the keychain test against the real OS
  backend (it writes and deletes a test item).

Never point a test at a real or remote database.

### Fixtures and fuzzing

- Classifier corpus: `internal/sqlclass/corpus_test.go`. A bypass you find
  belongs there, in every dialect it applies to.
- SQLite plan fixtures are regenerated with
  `go test ./internal/engine/sqlite -update`. MySQL, MariaDB and PostgreSQL
  fixtures are raw `EXPLAIN` JSON captured from real servers, one directory
  per version.
- Fuzz targets run nightly in CI; run one locally with, for example,
  `go test -run '^$' -fuzz '^FuzzLexNoPanic$' -fuzztime 30s ./internal/sqlclass/`.
  A failing input is written under the package's `testdata/fuzz/`; commit it
  with the fix, so `go test` replays it from then on.
- The SQL parser and provenance analyzer (`internal/sqlast`) have
  `FuzzParseNoPanic` and `FuzzAnalyzeNoPanic`, seeded from the classifier
  corpus and the package's tests. Besides panics, the analyze target checks
  the provenance of every accepted statement (an output that reveals column
  values names its sources; a value of a masked column is never returned
  unmasked). `metamorphic_test.go` checks that rewrites which keep a
  statement's meaning (alias, CTE, subquery, swapped join, `UNION ALL` with
  itself) keep its provenance in every dialect: a rewrite may be refused,
  never accepted with a cleaner provenance. New syntax should get a base
  statement there.

## Pull requests

- Write the failing test first, then the fix.
- Keep `gofmt`, `go vet`, `staticcheck` and `govulncheck` clean.
- Keep the security invariants: no secret in argv, environment, files, logs,
  the socket protocol or error strings; no protocol method that loosens the
  policy; fail closed on anything ambiguous.
- One logical change per pull request, with a commit message that explains
  why.

Pull requests target `main`, which is protected:

- the CI checks (`test` on Linux and macOS, `lint`, `integration`) must pass
  and the branch must be up to date with `main`;
- a review from a code owner is required, and every review thread must be
  resolved;
- pull requests are squash-merged: the title becomes the commit subject and
  the description its body, so write both for the history. Use a
  conventional prefix (`feat:`, `fix:`, `docs:`, `chore:`, ...).

Workflows on pull requests from forks run after a maintainer approves them.
Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Releases

Releases are built by GoReleaser (`.goreleaser.yaml`) when a `v*` tag is
pushed: `.github/workflows/release.yml` runs the unit tests, then builds
linux and darwin on amd64 and arm64, signs `checksums.txt` with cosign
(keyless), attaches an SBOM per archive and the Linux packages. To
check the configuration locally without signing or publishing (needs
`goreleaser`, and `syft` for the SBOMs):

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

The output goes to `dist/`, which is ignored by git.

Once the archives and the images are published and signed, the workflow's last
job (`tap`) asks the [Homebrew tap](https://github.com/DavidGodefroid/homebrew-tap)
to bump the `locksql` formula to the tag (a `repository_dispatch` of type
`bump`); the tap verifies the release with cosign before rewriting the
formula. It needs the secret `TAP_DISPATCH_TOKEN`, a fine-grained token
limited to DavidGodefroid/homebrew-tap (Contents: read and write); without
it the step is skipped.

The release chain is pinned end to end:

- every `uses:` in `.github/workflows/` names a full commit SHA with its
  version as a comment (`actions/checkout@<sha> # v7.0.1`); Dependabot bumps
  both. Check a new SHA is the tag's commit (`gh api
  repos/OWNER/REPO/commits/vX.Y.Z --jq .sha`) and keep the comment exact:
  `TestWorkflowActionsArePinnedBySHA` fails on a tag or a missing version;
- `release.yml` pins the GoReleaser, cosign and syft versions and does not
  use `check-latest`;
- the cosign identity is the release workflow run for the exact tag
  installed in `scripts/install.sh` and the launcher `scripts/locksql`
  (`TestScriptsPinTheExactReleaseTag`), and for a version tag in
  `.goreleaser.yaml`'s comment (`ReleaseCertIdentityRegexp`).

Tags are created by the maintainer only (the `protect release tags` ruleset
restricts creating, moving and deleting `v*` tags; `protect main` requires a
pull request and the CI checks). Sign release tags:

```sh
git tag -s vX.Y.Z -m "locksql vX.Y.Z"   # with gpg.format=ssh for an SSH key
git verify-tag vX.Y.Z
```

with a key published on the maintainer's GitHub profile, which is where
`SECURITY.md` sends users to verify it.
