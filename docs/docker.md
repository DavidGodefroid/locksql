# Running locksql in Docker

The image runs locksql with nothing installed on your machine but Docker. It
holds the separated setup that `sudo locksql install` makes on a host:

- the console runs as `locksql` (uid 10001), the only account that holds the
  database credentials;
- the agent's MCP server and CLI run as `agent` (uid 10002), a member of
  `locksql-clients`;
- `/etc/locksql/system.toml` is owned by root and the binary by root;
- the socket directory `/run/locksql` (mode 2710, `locksql:locksql-clients`)
  is a named volume, `locksql-run`, shared by the console container and the
  agent's containers. The kernel checks every peer on the socket as on a
  host.

## Build

From a clone:

```sh
docker build -t locksql .
```

or without cloning:

```sh
docker build -t locksql https://github.com/DavidGodefroid/locksql.git
```

`--build-arg VERSION=v0.4.0` sets the version that `locksql version` prints.

## Set up a project

Mount the project at its own path (`-v "$PWD:$PWD" -w "$PWD"`): the socket name
is derived from the project path, so the console and the agent must see the
same one, and the console's hints then name real paths.

In the project directory, `init` writes `.locksql/config.toml` with a
commented example profile, and the agent files (here Claude Code's):

```sh
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:$PWD" -w "$PWD" locksql init claude
```

`--user` and `HOME` make the files yours. `init` writes `locksql mcp` as the
MCP command, which is not on your machine: replace the `locksql` entry as in
[Wire the agent](#wire-the-agent).

Edit the profile in `.locksql/config.toml`. Inside a container,
`localhost` is the container itself:

- a database on your machine is `host = "host.docker.internal"` (Docker
  Desktop; on Linux add `--add-host=host.docker.internal:host-gateway` to the
  console's `docker run`). That is not a loopback host, so `tls` defaults to
  `verify-full`: set `tls = "disable"` or `"prefer"` for a local server
  without TLS;
- a database in another container is reached by its name on a shared
  network (`--network NAME` on the console's `docker run`);
- `credentials = "keychain"` needs an OS keychain, which the container does
  not have: keep `credentials = "ask"`;
- a SQLite `path` is relative to the project root, which is mounted.

## Run the console

In a terminal you keep in view, from the project directory:

```sh
docker run -it --rm --name locksql-console --user locksql \
  -v "$PWD:$PWD" \
  -v locksql-run:/run/locksql \
  -v locksql-home:/home/locksql \
  locksql console --project "$PWD"
```

Add `--profile P`, `--show-results`, `--skip-permissions` or
`--allow-unmask` after `console` as on a host. The `locksql-home` volume
keeps the console account's state from one run to the next: the approved
policy, the audit log and `~/.ssh/known_hosts` for an `ssh` profile. A key
for `auth = "key"` must be in that volume, owned by `locksql` with mode 0600;
`auth = "password"` needs nothing there.

## Wire the agent

The agent starts the MCP server in a throwaway container, as `agent`, with
the socket volume and the project mounted. `sh -c` expands `$PWD`, the
directory the agent runs in (start the agent at the project root).

Claude Code, for every project:

```sh
claude mcp add --scope user locksql -- \
  sh -c 'exec docker run -i --rm -v "$PWD:$PWD" -w "$PWD" -v locksql-run:/run/locksql locksql mcp'
```

or for one project, in `.mcp.json`:

```json
{
  "mcpServers": {
    "locksql": {
      "type": "stdio",
      "command": "sh",
      "args": ["-c", "exec docker run -i --rm -v \"$PWD:$PWD\" -w \"$PWD\" -v locksql-run:/run/locksql locksql mcp"]
    }
  }
}
```

Codex, Gemini CLI and Cursor take the same `command` and `args` in the files
listed in [Agent wiring](usage.md#agent-wiring) (keep `tool_timeout_sec` or
`timeout` there: the console waits up to 5 minutes for an approval).

The client commands run the same way:

```sh
docker run --rm -v "$PWD:$PWD" -w "$PWD" -v locksql-run:/run/locksql locksql status
```

`locksql doctor` runs as `agent` by default and as the console account with
`--user locksql`. It warns that `locksql` has no login session: in Docker the
container takes the place of that session.

## What Docker does and does not separate

Inside Docker the boundary is the same as on a host: the agent's container
holds no credential, has no database connection and reaches the console only
through the socket; a process that is neither the console account nor in
`locksql-clients` is refused.

Your own account is another matter. Whoever can run `docker` commands can
`docker attach` to the console and type an approval, `docker exec` into it
and read its memory, or open the `locksql-home` volume. An agent that runs
shell commands in your account usually can: the MCP server above is itself a
`docker run`. The console cannot see this (its terminal belongs to the
container), so treat Docker mode like the in-agent approval it improves on:
it keeps credentials out of the agent's reach and the approval in your
terminal, but it does not stop an agent determined to go around it. For that
boundary, either use `sudo locksql install` on the host, or run the agent
itself in a container with no access to the Docker socket.
