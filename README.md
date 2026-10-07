# locksql

locksql lets AI agents query MariaDB, MySQL, PostgreSQL and SQLite databases
only through a human-approved console.

- `locksql console` runs in your terminal. It holds the credentials, the only
  database connection, the policy and the approval prompt.
- `locksql <client command>` and `locksql mcp` are secret-free clients that the
  agent uses. They talk to the console over a local socket.

Status: under development, not usable yet.

## Client commands

The agent runs these from inside the project. Each one talks to the console of
one profile and never handles a secret.

```sh
locksql status   [--profile P]
locksql tables   --profile P --db D
locksql describe --profile P --db D TABLE
locksql plan     --profile P --db D [--unmask] "SQL" | -    # "-" reads SQL from stdin
locksql run      --profile P PLAN_ID                         # waits for the human's approval
locksql pii      list|add --profile P [DB.TABLE.COLUMN]
locksql request  --profile P "tier=write"                    # queued for the human, never applied
locksql logout   --profile P
```

- `--profile` may be left out when exactly one profile is configured.
- `--json` gives machine-readable output on every client command. A failure
  prints `{"error": {"kind": ..., "message": ...}}`.
- Exit codes: 0 ok · 1 refused, denied or failed · 2 no console running (the
  error names the `locksql console --profile P` command to start) · 3 usage or
  configuration error.
- `run` has no client-side timeout. The console's approval timeout (5 minutes)
  applies.

### Environment

- `LOCKSQL_RUNTIME_DIR`: when set to an absolute path, the console sockets live in
  `$LOCKSQL_RUNTIME_DIR/locksql/` instead of the OS runtime directory. The console
  and its clients must see the same value. The tests use it to keep sockets in a
  temporary directory.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
