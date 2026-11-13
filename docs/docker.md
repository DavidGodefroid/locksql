# Setting up locksql in Docker

locksql runs in Docker, with nothing on your machine but Docker and the
`locksql` launcher. The launcher is a short shell script
([`scripts/locksql`](../scripts/locksql)): every command you type,
`locksql version`, `locksql mcp` and the others, runs in the locksql image,
never in a binary of its own on your machine. The console runs in that
image too, but `lox run` starts it, not the launcher
([Run the console](#run-the-console)). The image holds the separated setup:

- the console runs as `locksql` (uid 10001), the only account that holds the
  database credentials;
- the agent's MCP server and CLI run as `agent` (uid 10002), a member of
  `locksql-clients`;
- `/etc/locksql/system.toml` is owned by root and the binary by root;
- the socket directory `/run/locksql` (mode 2710, `locksql:locksql-clients`)
  is a named volume, shared by the console container and the agent's
  containers (read-only there): `lox run`'s socket volume of the lock
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
| `stats`, `forget` | `locksql` | the home volume of the workspace's locksql lock that `lox run` runs, `lockfamily-<8 hex>_<instance>-home`, the one its console keeps its state in (`--instance NAME` for one of several; [launcher.md](launcher.md#the-home-of-lox-runs-lock)) |
| `init`, `config` | you (your uid and gid), with your home mounted: they write the agents' files and your user config; a `config` file must be under the project or your home | |
| `profile` | you, with `HOME=/tmp` | |
| `doctor --fix` | you, with your home mounted (your agents' wiring); first as root, only to give back `.locksql/` entries that are not yours | |
| the agent commands: `mcp`, `status`, `tables`, `plan`, `run`, `doctor`... | `agent` | the socket volume of the workspace's locksql lock that `lox run` runs, read-only ([launcher.md](launcher.md#the-socket-of-lox-runs-lock)) |
| everything else: `help`... | `agent` | none |

The socket name is derived from the project path, so the console and the
agent see the same one, and the console's hints name real paths.

The launcher reads:

- `LOCKSQL_IMAGE`: the image to run instead of the release's, for example
  your own build (below);
- `LOCKSQL_VAULT=1`: the release's `-vault` image;
- `LOCKSQL_DOCKER_ARGS`: more `docker run` arguments, split on spaces.

They apply to the launcher's own commands only. The console is not one of
them: `lox run` starts it with the image, volumes, networks and environment
of the lock in `lockfamily.yaml` ([Run the console](#run-the-console)), and
`locksql console` exits 2 with `the console is started by lox run only
(lockhub): run lox run in the workspace`.

A path holding `:` (the project, your home) cannot be mounted: the launcher
refuses it. On macOS, `doctor --fix` giving back `.locksql/` entries that
are not yours (a `chown` as root through Docker Desktop's
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

Your build runs the launcher's commands, never the console: `lox run`
starts a lock only from a release image, pinned by digest and checked
against its release's cosign signature (`locks.<name>.image:
ghcr.io/davidgodefroid/locksql@sha256:...`).

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
`.locksql/config.toml`. `--engine` and its flags skip their questions, and
`--non-interactive` asks none (`locksql profile add --non-interactive
--engine postgres --host db.internal --credentials vault --vault-path
database/creds/ro`). Inside a container, `localhost` is
the container itself, and the wizard knows it:

- a database on your machine is `host = "host.docker.internal"`, which the
  lock's egress gateway maps to your machine. `tls` defaults to `prefer`,
  as for any host: a local server without TLS connects in plain TCP, with a
  warning;
- a database in another container: publish its port on your machine
  (`docker run -p 127.0.0.1:5432:5432 ...`, or `ports:` in its compose
  file) and name `host.docker.internal` with that port. Under `lox run` the
  lock sits on an internal network of its own and reaches only its
  profile's endpoints, through its gateway
  ([lockhub: egress](https://github.com/DavidGodefroid/lockhub/blob/main/docs/lox-run.md#egress-each-lock-reaches-its-reviewed-endpoints-only)):
  it cannot join the container's network to reach it by name
  ([lockhub#194](https://github.com/DavidGodefroid/lockhub/issues/194));
- `credentials = "keychain"` needs an OS keychain, which the container does
  not have: use `credentials = "ask"`, or `"vault"` with the image below;
- a SQLite `path` is relative to the project root, which is mounted.

Then check the setup, and repair what can be:

```sh
locksql doctor --fix --yes
```

It wires your agents and keeps `.locksql/` as `lox run` reads it: `lox run`
copies it, once, for the console, which never reads the project itself, and
takes only directories and regular files that are yours and that no one
else can write. `doctor --fix` runs as you and removes the write bits of
group and others there (`chmod go-w`); entries owned by the console account
(uid 10001), which `doctor --fix` up to v0.13.0 gave it and `lox run`
refuses, it gives back to you as root, in a container of its own run only
then. The checks of the console and its profiles warn from this container,
which runs no console. Run it again whenever `.locksql/` changes hands, by a
copy from another account for example.

## Run the console

The console runs attached to lockhub only: from the project directory,

```sh
lox add locksql sql-dev
lox run                # a terminal of its own, outside the agent: keep it open
lox attach sql-dev     # in another terminal
```

`lox run` starts the hub and the workspace's locks, then serves the
decisions in its terminal. It runs the console in a container of its own,
from the image `lockfamily.yaml` pins for the lock, with its hub flags
(`console --hub URL --hub-key-file PATH --instance NAME`, plus `--profile P`
from the lock's `profile:`: [Start the console](usage.md#2-start-the-console));
clear results (Ctrl-O) and unmasking (`:unmask`) are switched on at the
console. The launcher starts no console: `locksql console` exits 2 with
`the console is started by lox run only (lockhub): run lox run in the
workspace`, and the console binary started without its hub flags exits with
``launched by `lox run` only``. `lox run` shows the console's start-up
questions in its own terminal, again when it restarts; `lox attach sql-dev`
attaches yours to the console instead (detach: Ctrl-P Ctrl-Q).

The lock's home volume, `<compose project>_<instance>-home`
(`lockfamily-<8 hex of sha256(workspace)>_sql-dev-home`), keeps the console
account's state from one run to the next: the approved policy, the audit
log, the PII rule sets and `~/.ssh/known_hosts` for an `ssh` profile. The
files a profile names under `~/` (`tls_ca`, `tls_cert`, `tls_key`, the key
of `auth = "key"`, owned by `locksql` with mode 0600) are in that volume
too: `lox add` and `lox run` check them and print the command that copies a
missing one there
([lockhub: the files a locksql profile names](https://github.com/DavidGodefroid/lockhub/blob/main/docs/lox-add.md#the-files-a-locksql-profile-names)).
`auth = "password"` needs nothing there. The launcher's `stats` and
`forget` mount that volume. The `locksql-home` volume of earlier releases
holds no console's state any more: they mount it only in a directory that
`lox run` runs no lock for, when it exists, to read what a console started
by hand left there.

## Credentials from Vault

`credentials = "vault"` runs the `vault` CLI in the console's container. The
default image leaves it out (it adds some 550 MB); the release's `-vault`
image has it (`ghcr.io/davidgodefroid/locksql:X.Y.Z-vault`). Under `lox
run`, Vault is a setting of the lock, not of the launcher: declare the lock
with Vault credentials, and `lox add` pins the `-vault` image, marks the
lock `vault: true` and writes the workspace's one `vault:` block (address,
namespace, CA file) in `lockfamily.yaml`:

```sh
lox add locksql sql-dev --credentials vault --vault-path database/creds/ro \
  --vault-address https://vault.example.com:8200   # [--vault-namespace NS] [--vault-ca-file PATH]
lox run
```

`lox vault set --address URL [--namespace NS] [--ca-file PATH]` changes the
block later. `lox run` reviews it, then gives the console `VAULT_ADDR`, and
`VAULT_NAMESPACE` when set, nothing else; the CA file, copied once reviewed,
is mounted read-only in the lock. The launcher's `LOCKSQL_VAULT` and the
`VAULT_*` variables of your shell play no part. See [lockhub: Vault, per
lock](https://github.com/DavidGodefroid/lockhub/blob/main/docs/lox-add.md#vault-per-lock).

The console account needs no `vault login`: at start the console asks
`Vault token for <VAULT_ADDR>:` (no echo), which `lox run` shows on a card
in its terminal, and keeps the token in memory for the session, never in
the lock's home volume or anywhere on disk. Get the token without storing
it, then type it there:

```sh
vault login -method=oidc -no-store -token-only
```

`-no-store -token-only` prints the token and writes no `~/.vault-token`.
A plain `vault login` would store the token in your account, where the
agent runs: the agent could read it and fetch the login from Vault itself,
bypassing the console (`locksql doctor` fails on it). For the same reason,
do not leave `VAULT_TOKEN` set in that shell. If you accept a token stored
in your account, `vault_token: cli` on the lock lets `lox run` answer the
prompt with your Vault CLI's token, checked first ([lockhub: the host's
Vault CLI
token](https://github.com/DavidGodefroid/lockhub/blob/main/docs/lox-add.md#the-hosts-vault-cli-token-vault_token)).
When Vault refuses a read (`not authenticated or not allowed`: the token is
expired or revoked, or its policy may not read `vault_path`), the console
asks for a token again; three refusals in a row stop the connection.

## Databases that publish no port

A profile with `proxy_command`
([usage.md](usage.md#databases-that-publish-no-port)) is **not supported
under `lox run` yet**
([lockhub#193](https://github.com/DavidGodefroid/lockhub/issues/193)):

- a lock reaches only the endpoints its gateway can name, and a program is
  not one: the review shows the lock's egress `unreachable`
  (`proxy_command runs a program the gateway cannot follow`), and the
  console reaches nothing;
- the command's client (`ssh`, `docker`, `kubectl`) is not in the release
  image, and `lox run` runs no image of your own
  ([Your own build](#your-own-build)).

For a database behind an SSH host, use the profile's `ssh` table instead
([usage.md](usage.md#reaching-a-remote-server-through-ssh)): the console
opens the tunnel itself, and `lox run` allows the bastion, and only it, as
the lock's endpoint. For a database in a container on your machine, publish
its port ([Set up a project](#set-up-a-project)).

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

`locksql doctor` runs as `agent`. To check the console account, run it as
`locksql` with the volumes `lox run` gives the lock (compose project
`lockfamily-<8 hex of sha256(workspace)>`; `up.json` names the socket one
as `socket_volume`): `docker run --rm --user locksql -v
lockfamily-<hash>_<instance>-run:/run/locksql -v
lockfamily-<hash>_<instance>-home:/home/locksql
ghcr.io/davidgodefroid/locksql:X.Y.Z doctor`. It
warns that `locksql` has no login session: in Docker the container takes the
place of that session, and the checks of
[`locksql doctor`](usage.md#locksql-doctor) about the host do not apply.

## Agent in its own container

When the agent itself runs in a container that cannot reach the Docker
socket, the launcher cannot start the MCP server: the agent runs the
`locksql` binary inside its own container instead, as a client of the
console container. The two containers share only the socket volume.

The console checks every peer by uid against its own container's accounts,
where the agent's uid has none: name it in the lock's `allowed_uids`, in
the `lockfamily.yaml` that `lox run` reviews with you (it passes
`console --allowed-uids 1000` on), with the release image as it is.

`--allowed-uids` is a comma-separated list of uids, which the console adds
to `allowed_uids` of the image's `/etc/locksql/system.toml` for itself only
(it prints them at start). It refuses root (0), the console's own uid
(10001) and 65534 (nobody, the kernel's overflow uid). Only whoever starts
the console sets it: you, through `lox run` (lockhub v0.3.0 or later); no
client can. (`docker build --build-arg ALLOWED_UIDS=1000` writes the same
list into an image of your own, which `lox run` does not run: [Your own
build](#your-own-build).) Every process of that uid, in any container that mounts the socket
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

Start the agent's container with lox run's socket volume of the lock
(`socket_volume` in `.lockfamily/up.json`), read-only, and the workspace at
the same path as the console's, for example:

```sh
docker run … --mount type=volume,src=lockfamily-<hash>_<instance>-run,dst=/run/locksql,readonly \
  -v "$PWD:$PWD" -w "$PWD" agent-image
```

`locksql init claude` then needs no change: the `locksql mcp` it writes in
`.mcp.json` runs inside the agent's container. Check from there with
`locksql status`. `locksql doctor` run there also checks the project's
`.locksql/` as `lox run` reads it: yours, writable by you only
([Set up a project](#set-up-a-project)).

## What Docker does and does not separate

Inside Docker the agent's container holds no credential, has no database
connection and reaches the console only through the socket; a process that
is neither the console account nor in `locksql-clients` (or `allowed_uids`,
`--allowed-uids`) is refused.

Your own account is another matter. Whoever can run `docker` commands can
`docker attach` to the console and type an approval, `docker exec` into it
and read its memory, or open the lock's home volume. An agent that runs
shell commands in your account usually can: the launcher it runs for the
MCP server is itself a `docker run`. The console cannot see this (its terminal belongs to the
container), so treat this setup like the in-agent approval it improves on:
it keeps credentials out of the agent's reach and the approval in your
terminal, but it does not stop an agent determined to go around it. For that
boundary, run the agent itself in a container with no access to the Docker
socket ([Agent in its own container](#agent-in-its-own-container)): it then
reaches the console only through the socket volume.
