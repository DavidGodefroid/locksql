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
the PII rule sets there (`pii/<set>.toml`), and a directory your account owns would let the agent
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

Get the token without storing it, then paste it at the prompt:

```sh
vault login -method=oidc -no-store -token-only
```

`-no-store -token-only` prints the token and writes no `~/.vault-token`.
A plain `vault login` would store the token in your account, where the
agent runs: the agent could read it and fetch the login from Vault itself,
bypassing the console (`locksql doctor` fails on it). For the same reason,
do not leave `VAULT_TOKEN` set in that shell. When Vault refuses a read (`not authenticated or not allowed`: the
token is expired or revoked, or its policy may not read `vault_path`), the
console asks for a token again; three refusals in a row stop the
connection.

## Databases that publish no port

A profile with `proxy_command`
([usage.md](usage.md#databases-that-publish-no-port)) runs its command in the
console's container, as the `locksql` account. The image has none of the
clients the recipes use (`ssh`, `docker`, `kubectl`), so a profile using one
fails with `proxy_command: exec: "ssh": executable file not found in $PATH`.
Build an image of your own on top of it, with only the client you need:

```dockerfile
# Dockerfile.proxy
FROM locksql
USER root
RUN apk add --no-cache openssh-client
USER agent
```

```sh
docker build -t locksql -f Dockerfile.proxy .   # after docker build -t locksql .
docker run --rm --entrypoint ssh locksql -V     # the client is there
```

Tagging it `locksql` again keeps the commands of this guide unchanged. Add
`docker-cli` for a `docker exec` reached through `DOCKER_HOST=ssh://...`;
for `kubectl`, copy a release binary checked against its published SHA-256,
as the `Dockerfile` does for `vault`, and keep the kubeconfig in
`locksql-home`. Pass `DOCKER_HOST`, `DOCKER_CONTEXT` or `KUBECONFIG` with
`-e` on the console's `docker run`; the command inherits them.

**Prefer `ssh` to the Docker host**, even when it is the machine the console
runs on (`deploy@host.docker.internal`, with
`--add-host=host.docker.internal:host-gateway` on Linux). The command runs
without a terminal, so `ssh` needs a key without passphrase and the host key
already known. Create both in `locksql-home`, as the console account, and
check the fingerprint `ssh-keyscan` prints against the host's own
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there):

```sh
docker run -it --rm --user locksql -v locksql-home:/home/locksql \
  --add-host=host.docker.internal:host-gateway --entrypoint sh locksql -c '
    mkdir -p -m 0700 ~/.ssh &&
    ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519 &&
    ssh-keyscan -t ed25519 host.docker.internal >> ~/.ssh/known_hosts &&
    ssh-keygen -lf ~/.ssh/known_hosts && cat ~/.ssh/id_ed25519.pub'
```

Authorize that public key for a dedicated account on the host, and limit it
to the one relay it needs (`command="docker exec -i shop-db socat -
TCP:127.0.0.1:3306",restrict` in its `authorized_keys`): an account that may
run `docker` is root on that host.

**Do not mount the Docker socket into the console's container** unless you
accept what follows. With `-v /var/run/docker.sock:/var/run/docker.sock` (and
`--group-add` the socket's group, since the console does not run as root),
`docker exec` works from the console's container, but **the console's
container becomes root on the host**: any process in it, the console or the
command it runs, can start a privileged container that mounts the host's `/`.
The agent's container does not get the socket; anything that takes over the
console, or a `proxy_command` you approve without reading it, does. The
`ssh` route above confines the same need to one relay command.

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
