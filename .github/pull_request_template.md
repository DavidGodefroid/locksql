## Why

<!-- The problem this solves. Link the issue: "Fixes #123". -->

## What changes

<!-- The approach, and anything a reviewer should look at first. -->

## Checklist

- [ ] A test fails without this change and passes with it.
- [ ] `go vet ./...`, `go test ./...` and `staticcheck ./...` are clean.
- [ ] No secret can reach argv, the environment, a file, a log, the socket or an error message.
- [ ] No default is loosened and no way around the console is added (or the issue discusses it).
- [ ] Docs (`README.md`, `docs/`) are updated if behaviour changes.
