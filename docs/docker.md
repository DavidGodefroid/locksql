# Setting up locksql in Docker

locksql runs in Docker, with nothing on your machine but Docker and the
`locksql` launcher. The launcher is a short shell script
([`scripts/locksql`](../scripts/locksql)): every command you type,
`locksql console`, `locksql version`, `locksql mcp` and the others, runs in
the locksql image, never in a binary of its own on your machine. The image
holds the separated setup:

- the console runs as `locksql` (uid 10001), the only account that holds the
  database credentials;
- the agent's MCP server and CLI run as `agent` (uid 10002), a member of
  `locksql-clients`;
- `/etc/locksql/system.toml` is owned by root and the binary by root;
- the socket directory `/run/locksql` (mode 2710, `locksql:locksql-clients`)
  is a named volume, shared by the console container and the agent's
  containers (read-only there): `lox up`'s socket volume of the lock
  (`lockfamily-<hash>_<instance>-run`, named in `.lockfamily/up.json`). The
  kernel checks every peer on the socket.

## Install

Download the install script from the release you install, read it, then
run it with that release:

```sh
V=vX.Y.Z
curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/locksql/$V/scripts/install.sh"
less install.sh
LOCKSQL_VERSION=$V sh install.sh
```

It checks the release's cosign signature and checksum, and installs the
launcher as `/usr/local/bin/locksql` (with `sudo` when needed; set
`LOCKSQL_INSTALL_DIR` for another directory). The launcher runs the image of
its own release, `ghcr.io/davidgodefroid/locksql:X.Y.Z`, which Docker pulls
on first use: `install.sh` checks the image's cosign signature too (and its
`-vault` variant's) and writes the verified digests into the launcher, which
runs the image by digest, never by a tag that could be moved. Linux and macOS (Docker Desktop); on Windows, install it in
WSL 2 with Docker Desktop's WSL integration and run it there.

```sh
locksql version    # the launcher's version and its image's
locksql update     # the latest release: a new launcher, then docker pull
locksql update vX.Y.Z
```

`locksql update` checks the signatures and the checksum as `install.sh`
does, and needs cosign the same way. With `LOCKSQL_SKIP_COSIGN=1` nothing is
verified and the launcher runs the image by its tag.

### What runs where

The launcher mounts the project (the nearest directory up from where you
are that holds `.locksql/`, or that directory itself, or the `--project`
you name) at its own path, and
runs each command with the account it needs:

| Command | Runs as | Volumes |
|---|---|---|
| `console` | `locksql`, in a container of its own (`locksql-console-<n>`, one per project; `LOCKSQL_CONSOLE_NAME` names it), confined (no capability, no privilege gain, read-only root with a small `/tmp`, at most 256 processes and 1 GB), with `--add-host=host.docker.internal:host-gateway` and no log driver | `locksql-run`, `locksql-home` |
| `stats`, `forget` | `locksql` | `locksql-home` |
| `init`, `config` | you (your uid and gid), with your home mounted: they write the agents' files and your user config; a `config` file must be under the project or your home | |
| `profile` | you, with `HOME=/tmp` | |
| `doctor --fix` | root | |
| the agent commands: `mcp`, `status`, `tables`, `plan`, `run`, `doctor`... | `agent` | the socket volume of the workspace's locksql lock that `lox up` runs, read-only ([launcher.md](launcher.md#the-socket-of-lox-ups-lock)) |
| everything else: `help`... | `agent` | none |

The socket name is derived from the project path, so the console and the
agent see the same one, and the console's hints name real paths.

The launcher reads:

- `LOCKSQL_IMAGE`: the image to run instead of the release's, for example
  your own build (below);
- `LOCKSQL_VAULT=1`: the image with the `vault` CLI
  ([Credentials from Vault](#credentials-from-vault));
- `LOCKSQL_DOCKER_ARGS`: more `docker run` arguments, split on spaces, for
  example `LOCKSQL_DOCKER_ARGS="--network shop" locksql console`;
- `LOCKSQL_READONLY_PROJECT=1`: the console mounts the project read-only,
  but for `.locksql/`, for a project your agents write;
- `LOCKSQL_CONSOLE_NAME`: the console's container name (default
  `locksql-console-<n>`, from the project path);
- `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_CACERT`: passed to the console.

A path holding `:` (the project, your home) cannot be mounted: the launcher
refuses it. On macOS, `doctor --fix` (a `chown` through Docker Desktop's
file sharing) is untested.

### Your own build

From a clone, or without cloning:

```sh
docker build -t locksql .
docker build -t locksql https://github.com/DavidGodefroid/locksql.git
```

then `LOCKSQL_IMAGE=locksql locksql ...`. The launcher of a clone
(`sh scripts/locksql ...`) runs the image tagged `locksql` by default.
`--build-arg VERSION=v0.8.0` sets the version that `locksql version` prints.

### Migrating from a host install

Earlier releases installed a `locksql` binary on the host, and
`sudo locksql install` a console account, its group, `/etc/locksql/` and a
socket directory there. `install.sh` replaces that binary with the launcher;
the image refuses `locksql install`, `locksql setup` and its own
`locksql update`. What the host install created stays until you remove it:
the `locksql` account and the `locksql-clients` group, `/etc/locksql/`, the
socket directory (`/run/locksql`, `/etc/tmpfiles.d/locksql.conf` on Linux),
and the console account's state in its home (approved policy, audit log).
Agents wired with `locksql mcp` now reach the image through the launcher;
an `.mcp.json` entry that runs `docker run ... locksql mcp` itself keeps
working.

## Set up a project

In the project directory, `init` writes `.locksql/config.toml` with a
commented example profile, and the agent files (here Claude Code's):

```sh
locksql init claude
```

The MCP command it writes, `locksql mcp`, is the launcher: the agent starts
the MCP server in a throwaway container ([Wire the agent](#wire-the-agent)).

Add a database profile with the wizard:

```sh
locksql profile add
```

It asks for the engine, host, port, TLS and where the password comes from,
never for the password itself, and appends the profile to
`.locksql/config.toml`. `--engine` and its flags (`locksql profile add
--engine postgres --host db.internal --credentials vault --vault-path
database/creds/ro`) skip the questions. Inside a container, `localhost` is
the container itself, and the wizard knows it:

- a database on your machine is `host = "host.docker.internal"`, which the
  launcher maps to your machine. That is not a loopback host, so `tls`
  defaults to `verify-full`: set `tls = "disable"` or `"prefer"` for a local
  server without TLS;
- a database in another container is reached by its name on a shared
  network (`LOCKSQL_DOCKER_ARGS="--network NAME" locksql console`);
- `credentials = "keychain"` needs an OS keychain, which the container does
  not have: use `credentials = "ask"`, or `"vault"` with the image below;
- a SQLite `path` is relative to the project root, which is mounted.

Then give `.locksql/` to the console account. The console writes
the PII rule sets there (`pii/<set>.toml`), and a directory your account owns would let the agent
replace that file, and with it the masking rules. The account exists only in
the image, where the launcher runs the repair as root:

```sh
locksql doctor --fix --yes
```

It makes uid 10001 the owner of `.locksql/` (mode 0755) and makes
`config.toml` readable; `config.toml` stays yours to edit. The checks of the
console and its profiles fail from this container, which runs no console:
read the `project` lines. Run it again whenever `.locksql/` is created anew,
by `locksql init` for example.

## Run the console

The console runs attached to lockhub only: from the project directory,

```sh
lox add locksql sql-dev
lox up
```

`lox up` starts the console with its hub flags, through the launcher
(`locksql console --hub URL --hub-key-file PATH --instance NAME`, plus
`--profile P`, `--show-results` or `--allow-unmask` from the lock's
settings: [Start the console](usage.md#2-start-the-console)). Started
without them, `locksql console` exits with ``launched by `lox up` only``. The
`locksql-home` volume keeps the console account's state from one run to the
next: the approved policy, the audit log and `~/.ssh/known_hosts` for an
`ssh` profile. A key for `auth = "key"` must be in that volume, owned by
`locksql` with mode 0600; `auth = "password"` needs nothing there.

## Credentials from Vault

`credentials = "vault"` runs the `vault` CLI in the console's container. The
default image leaves it out (it adds some 550 MB); the release's `-vault`
image has it (`ghcr.io/davidgodefroid/locksql:X.Y.Z-vault`), which
`LOCKSQL_VAULT=1` selects. For your own build, `docker build --target vault
-t locksql:vault .` and `LOCKSQL_IMAGE=locksql:vault`.

The console reads `VAULT_ADDR` and `VAULT_NAMESPACE` from its environment,
which the launcher passes on, nothing else. The console account needs no
`vault login`: at start the console asks `Vault token for <VAULT_ADDR>:` in its terminal (no
echo) and keeps the token in memory for the session, never in
`locksql-home` or anywhere on disk:

```sh
LOCKSQL_VAULT=1 VAULT_ADDR=https://vault.example.com locksql console
```

`VAULT_CACERT` (a CA bundle for Vault's certificate) is passed too, its file
mounted read-only at its own path: it must be readable by the console
account (uid 10001), mode 0644 for example.

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
docker build -t locksql-proxy -f Dockerfile.proxy .   # after docker build -t locksql .
docker run --rm --entrypoint ssh locksql-proxy -V     # the client is there
LOCKSQL_IMAGE=locksql-proxy locksql console
```

`FROM ghcr.io/davidgodefroid/locksql:X.Y.Z` builds on the release's image
instead. Add
`docker-cli` for a `docker exec` reached through `DOCKER_HOST=ssh://...`;
for `kubectl`, copy a release binary checked against its published SHA-256,
as the `Dockerfile` does for `vault`, and keep the kubeconfig in
`locksql-home`. Pass `DOCKER_HOST`, `DOCKER_CONTEXT` or `KUBECONFIG` with
`LOCKSQL_DOCKER_ARGS="-e DOCKER_HOST=..."` on `locksql console`; the command
inherits them.

**Prefer `ssh` to the Docker host**, even when it is the machine the console
runs on (`deploy@host.docker.internal`, which the launcher maps to your
machine). The command runs
without a terminal, so `ssh` needs a key without passphrase and the host key
already known. Create both in `locksql-home`, as the console account, and
check the fingerprint `ssh-keyscan` prints against the host's own
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there):

```sh
docker run -it --rm --user locksql -v locksql-home:/home/locksql \
  --add-host=host.docker.internal:host-gateway --entrypoint sh \
  ghcr.io/davidgodefroid/locksql:X.Y.Z -c '
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
`--group-add` the socket's group, since the console does not run as root,
through `LOCKSQL_DOCKER_ARGS`; the launcher never mounts it),
`docker exec` works from the console's container, but **the console's
container becomes root on the host**: any process in it, the console or the
command it runs, can start a privileged container that mounts the host's `/`.
The agent's container does not get the socket; anything that takes over the
console, or a `proxy_command` you approve without reading it, does. The
`ssh` route above confines the same need to one relay command.

## Wire the agent

`locksql init claude` wrote `locksql mcp` as the MCP command in `.mcp.json`:
the agent runs the launcher, which starts the MCP server in a throwaway
container, as `agent`, with the socket volume and the project mounted. Start
the agent at the project root, or below it.

```json
{
  "mcpServers": {
    "locksql": {
      "type": "stdio",
      "command": "locksql",
      "args": ["mcp"]
    }
  }
}
```

For every project instead, `claude mcp add --scope user locksql -- locksql
mcp`. Codex, Gemini CLI and Cursor take the same `command` and `args` in the
files listed in [Agent wiring](usage.md#agent-wiring) (keep
`tool_timeout_sec` or `timeout` there: the console waits up to 5 minutes for
an approval).

The client commands run the same way: `locksql status`, `locksql tables`...

`locksql doctor` runs as `agent`; `docker run --rm --user locksql -v
locksql-run:/run/locksql -v locksql-home:/home/locksql
ghcr.io/davidgodefroid/locksql:X.Y.Z doctor` checks the console account. It
warns that `locksql` has no login session: in Docker the container takes the
place of that session, and the checks of
[`locksql doctor`](usage.md#locksql-doctor) about the host do not apply.

## Agent in its own container

When the agent itself runs in a container that cannot reach the Docker
socket, the launcher cannot start the MCP server: the agent runs the
`locksql` binary inside its own container instead, as a client of the
console container. The two containers share only the socket volume.

The console checks every peer by uid against its own container's accounts,
where the agent's uid has none: name it when you start the console, with
the release image as it is:

```sh
locksql console --allowed-uids 1000
```

or at build time, in an image of your own:

```sh
docker build -t locksql --build-arg ALLOWED_UIDS=1000 .
LOCKSQL_IMAGE=locksql locksql console
```

`--allowed-uids` and `ALLOWED_UIDS` are comma-separated lists of uids: the
build writes them to `allowed_uids` in the image's
`/etc/locksql/system.toml`, the flag adds them to it for that console only
(the console prints them at start). Both refuse root (0), the console's own
uid (10001) and 65534 (nobody, the kernel's overflow uid). Only whoever
starts the console sets them: you, through the launcher (which passes the
flag on) or through `lox up` (lockhub v0.2.5 or later: a lock's
`allowed_uids` in the lockfamily.yaml lox up reviews with you); no client
can. Every process of that uid, in any container that mounts the socket
volume, may then use the console. It is the uid the kernel reports
for the agent's process, as the console sees it: the agent container's uid
when neither container remaps user namespaces.

The agent's image needs what a client host has:

- the `locksql` binary, not the launcher: the one in the release archive
  (`locksql_X.Y.Z_linux_ARCH.tar.gz`, checked as `install.sh` checks it),
  the same version as the console's image;
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
is neither the console account nor in `locksql-clients` (or `allowed_uids`,
`--allowed-uids`) is refused.

Your own account is another matter. Whoever can run `docker` commands can
`docker attach` to the console and type an approval, `docker exec` into it
and read its memory, or open the `locksql-home` volume. An agent that runs
shell commands in your account usually can: the launcher it runs for the
MCP server is itself a `docker run`. The console cannot see this (its terminal belongs to the
container), so treat this setup like the in-agent approval it improves on:
it keeps credentials out of the agent's reach and the approval in your
terminal, but it does not stop an agent determined to go around it. For that
boundary, run the agent itself in a container with no access to the Docker
socket ([Agent in its own container](#agent-in-its-own-container)): it then
reaches the console only through the socket volume.
