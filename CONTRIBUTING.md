# Contributing to locksql

Thanks for your interest. Bug reports, fixes and new test cases are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach. locksql is a security tool: features that loosen a default, add a
  way around the console, or add a dependency need a clear case.
- Code, comments, docs and commit messages are in English.
- By contributing you agree that your work is licensed under the Apache
  License 2.0.

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

### Integration tests

Integration tests run real servers in Docker (MariaDB 10.11 and 11.4, MySQL
8.0 and 8.4, PostgreSQL 13 and 17). Containers are named `ls-it-*`, bound to
`127.0.0.1` and removed at the end.

```sh
go test -tags integration ./test/integration/
```

- `LOCKSQL_IT_MYSQL` and `LOCKSQL_IT_POSTGRES` select a subset of versions.
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

## Pull requests

- Write the failing test first, then the fix.
- Keep `gofmt`, `go vet`, `staticcheck` and `govulncheck` clean.
- Keep the security invariants: no secret in argv, environment, files, logs,
  the socket protocol or error strings; no protocol method that loosens the
  policy; fail closed on anything ambiguous.
- One logical change per pull request, with a commit message that explains
  why.
