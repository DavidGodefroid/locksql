# locksql

locksql lets AI agents query MariaDB, MySQL, PostgreSQL and SQLite databases
only through a human-approved console.

- `locksql console` runs in your terminal. It holds the credentials, the only
  database connection, the policy and the approval prompt.
- `locksql <client command>` and `locksql mcp` are secret-free clients that the
  agent uses. They talk to the console over a local socket.

Status: under development, not usable yet.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
