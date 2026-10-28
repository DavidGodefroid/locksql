# Setting up locksql in Docker

locksql runs in Docker, with nothing installed on your machine but Docker.
This guide is its setup. The image holds the separated setup:

- the console runs as `locksql` (uid 10001), the only account that holds the
  database credentials;
- the agent's MCP server and CLI run as `agent` (uid 10002), a member of
  `locksql-clients`;
- `/etc/locksql/system.toml` is owned by root and the binary by root;
- the socket directory `/run/locksql` (mode 2710, `locksql:locksql-clients`)
  is a named volume, `locksql-run`, shared by the console container and the
  agent's containers. The kernel checks every peer on the socket.

Other deployment modes (a host install, packages, desktop and session
setups) still exist in the code but are no longer documented or supported.

## Build

From a clone:

```sh
docker build -t locksql .
```

or without cloning:

```sh
docker build -t locksql https://github.com/DavidGodefroid/locksql.git
```

`--build-arg VERSION=v0.8.0` sets the version that `locksql version` prints.

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

Add a database profile with the wizard (the accounts and the socket are the
image's own):

```sh
docker run -it --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:$PWD" -w "$PWD" locksql profile add
```

It asks for the engine, host, port, TLS and where the password comes from,
never for the password itself, and appends the profile to
`.locksql/config.toml`. `--engine` and its flags (`locksql profile add
--engine postgres --host db.internal --credentials vault --vault-path
database/creds/ro`) skip the questions. Inside a container, `localhost` is
the container itself, and the wizard knows it:

- a database on your machine is `host = "host.docker.internal"` (Docker
  Desktop; on Linux add `--add-host=host.docker.internal:host-gateway` to the
  console's `docker run`). That is not a loopback host, so `tls` defaults to
  `verify-full`: set `tls = "disable"` or `"prefer"` for a local server
  without TLS;
- a database in another container is reached by its name on a shared
  network (`--network NAME` on the console's `docker run`);
- `credentials = "keychain"` needs an OS keychain, which the container does
  not have: use `credentials = "ask"`, or `"vault"` with the image below;
- a SQLite `path` is relative to the project root, which is mounted.

Then give `.locksql/` to the console account. The console writes
`pii.toml` there, and a directory your account owns would let the agent
replace that file, and with it the masking rules. The account exists only in
the image, so run the repair there, as root:

```sh
docker run --rm --user 0 -v "$PWD:$PWD" -w "$PWD" locksql doctor --fix --yes
```

It makes uid 10001 the owner of `.locksql/` (mode 0755) and makes
`config.toml` readable; `config.toml` stays yours to edit. The checks of the
console and its profiles fail from this container, which runs no console:
read the `project` lines. Run it again whenever `.locksql/` is created anew,
by `locksql init` for example.

## Run the console

In a terminal you keep in view, from the project directory:

```sh
docker run -it --rm --name locksql-console --user locksql \
  -v "$PWD:$PWD" \
  -v locksql-run:/run/locksql \
  -v locksql-home:/home/locksql \
  locksql console --project "$PWD"
```

Add `--profile P`, `--show-results`, `--auto` or
`--allow-unmask` after `console`
([Start the console](usage.md#2-start-the-console)). The `locksql-home` volume
keeps the console account's state from one run to the next: the approved
policy, the audit log and `~/.ssh/known_hosts` for an `ssh` profile. A key
for `auth = "key"` must be in that volume, owned by `locksql` with mode 0600;
`auth = "password"` needs nothing there.

## Credentials from Vault

`credentials = "vault"` runs the `vault` CLI in the console's container. The
default image leaves it out (it adds some 550 MB); the `vault` target has it:

```sh
docker build --target vault -t locksql .
```

The console reads `VAULT_ADDR` (and `VAULT_CACERT`, `VAULT_NAMESPACE`) from
its environment: add `-e VAULT_ADDR=https://vault.example.com` to its
`docker run`, nothing else. No `vault login` is needed: at start the
console asks `Vault token for <VAULT_ADDR>:` in its terminal (no echo, which
the `-it` of its `docker run` allows) and keeps the token in memory for the
session, never in `locksql-home` or anywhere on disk:

```sh
docker run -it --rm --name locksql-console --user locksql \
  -e VAULT_ADDR=https://vault.example.com \
  -v "$PWD:$PWD" \
  -v locksql-run:/run/locksql \
  -v locksql-home:/home/locksql \
  locksql console --project "$PWD"
```

Get the token from your Vault login on your own machine (for example
`vault print token` after `vault login -method=oidc`) and paste it at the
prompt. When Vault refuses a read (`not authenticated or not allowed`: the
token is expired or revoked, or its policy may not read `vault_path`), the
console asks for a token again; three refusals in a row stop the
connection.

## Wire the agent

The agent starts the MCP server in a throwaway container, as `agent`, with
the socket volume and the project mounted. `sh -c` expands `$PWD`, the
directory the agent runs in (start the agent at the project root).

Claude Code, for the project, replacing the entry `init claude` wrote in
`.mcp.json`:

```sh
claude mcp remove --scope project locksql
claude mcp add --scope project locksql -- \
  sh -c 'exec docker run -i --rm -v "$PWD:$PWD" -w "$PWD" -v locksql-run:/run/locksql locksql mcp'
```

which leaves in `.mcp.json`:

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

For every project instead, `claude mcp add --scope user` with the same
command; a project's `.mcp.json` entry takes precedence over it, so remove the
one `init claude` wrote. Codex, Gemini CLI and Cursor take the same `command`
and `args` in the files listed in [Agent wiring](usage.md#agent-wiring) (keep `tool_timeout_sec` or
`timeout` there: the console waits up to 5 minutes for an approval).

The client commands run the same way:

```sh
docker run --rm -v "$PWD:$PWD" -w "$PWD" -v locksql-run:/run/locksql locksql status
```

`locksql doctor` runs as `agent` by default and as the console account with
`--user locksql`. It warns that `locksql` has no login session: in Docker the
container takes the place of that session, and the checks of
[`locksql doctor`](usage.md#locksql-doctor) about the host do not apply.

## Agent in its own container

When the agent itself runs in a container that cannot reach the Docker
socket, it cannot start `docker run` for the MCP server: it runs the
`locksql` binary inside its own container instead, as a client of the
console container. The two containers share only the socket volume.

The console checks every peer by uid against its own container's accounts,
where the agent's uid has none: name it at build time.

```sh
docker build -t locksql --build-arg ALLOWED_UIDS=1000 .
```

`ALLOWED_UIDS` is a comma-separated list of uids, written to `allowed_uids`
in the image's `/etc/locksql/system.toml`. It is the uid the kernel reports
for the agent's process, as the console sees it: the agent container's uid
when neither container remaps user namespaces.

The agent's image needs what a client host has:

- the `locksql` binary, the same version as the console's;
- `/etc/locksql/system.toml`, owned by root, mode 0644, with the image's
  `service_user`, `client_group` and `socket_dir`: without it the client looks
  for the socket in the user's runtime directory;
- an account `locksql` with uid 10001: the client refuses a socket served by
  any uid but `service_user`'s;
- a group `locksql-clients` with gid 10000 that holds the agent's account:
  the socket directory is mode 2710 and the socket 0660, group
  `locksql-clients`.

Start the agent's container with the socket volume and the project at the
same path as the console's, for example:

```sh
docker run … -v locksql-run:/run/locksql -v "$PWD:$PWD" -w "$PWD" agent-image
```

`locksql init claude` then needs no change: the `locksql mcp` it writes in
`.mcp.json` runs inside the agent's container. Check from there with
`locksql status`. `locksql doctor` run there also checks the project: a
`.locksql/` the console account does not own is repaired by the root
command of [Set up a project](#set-up-a-project).

## What Docker does and does not separate

Inside Docker the agent's container holds no credential, has no database
connection and reaches the console only through the socket; a process that
is neither the console account nor in `locksql-clients` (or `allowed_uids`)
is refused.

Your own account is another matter. Whoever can run `docker` commands can
`docker attach` to the console and type an approval, `docker exec` into it
and read its memory, or open the `locksql-home` volume. An agent that runs
shell commands in your account usually can: the MCP server above is itself a
`docker run`. The console cannot see this (its terminal belongs to the
container), so treat this setup like the in-agent approval it improves on:
it keeps credentials out of the agent's reach and the approval in your
terminal, but it does not stop an agent determined to go around it. For that
boundary, run the agent itself in a container with no access to the Docker
socket ([Agent in its own container](#agent-in-its-own-container)): it then
reaches the console only through the socket volume.
