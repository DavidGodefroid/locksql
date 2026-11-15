# Installing locksql, in detail

The [README](../README.md#install) has the short path (Homebrew, `lox add`, `lox run`). This page keeps the full text: the first query by hand, the install script, the launcher and its image, lea, and building from source. The Docker setup itself is in [docker.md](docker.md).

## First query, step by step

locksql runs in Docker: nothing on your machine but Docker and the
`locksql` launcher, which runs every command in the image. The console runs
under [lockhub](https://github.com/DavidGodefroid/lockhub), which starts it
and where you decide each query.

The shortest path is the Lock Family's: install it with Homebrew, then let
[`lox add locksql`](https://github.com/DavidGodefroid/lockhub/blob/main/docs/lox-add.md)
ask where your database is and set up its lock, then start it with `lox run`.
locksql takes lockhub's `lox` v0.12.0 or later and cosign v2.5.0 or later
(`lox add` and `lox run` verify every image with cosign); the `lockfamily`
formula installs both, the `locksql` formula neither:

```sh
brew trust davidgodefroid/tap                # Homebrew asks you to trust a third-party tap once
brew install davidgodefroid/tap/lockfamily   # or only this tool: brew install davidgodefroid/tap/locksql davidgodefroid/tap/lox cosign
cd ~/projects                                 # with lea: its projects directory; with claude: the project
lox add locksql                               # asks about the database, sets up the lock
lox run                                       # a terminal of its own, outside the agent: starts the hub and the lock, approves
lea                                           # in another terminal; or: claude
```

If a lea container already runs for the project, `lox add` says `lea gets lock
NAME at its next start: lea stop, then lea`: lea mounts the locks' sockets
when its container starts, so `lea stop`, then `lea` brings the new lock in.

By hand, with locksql's own installer, a first approved query from your
project directory:

```sh
# 1. Install the launcher (it runs every locksql command in Docker);
#    needs cosign on PATH to check the release's signatures
V=vX.Y.Z
curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/locksql/$V/scripts/install.sh"
less install.sh && LOCKSQL_VERSION=$V sh install.sh

# 2. In your project: your agent's files (its MCP server is `locksql mcp`),
#    a database profile, then doctor --fix (your agents, .locksql/ as lox run reads it)
locksql init                 # or: locksql init claude|codex|cursor|gemini
locksql profile add
locksql doctor --fix --yes

# 3. Declare the lock in lockhub and start it: lox run, in a terminal of its
#    own outside the agent, starts the hub and the console, asks the
#    console's questions (the policy, the PII rules, the password) in its
#    cards and serves the decisions
lox add locksql sql-dev
lox run
```

Then ask your agent, in the project: "how many orders were placed
yesterday?". Each query is decided in the `lox run` terminal: reads pass by
rule in auto mode, writes and connections are asked there (`lox approve`
answers too). `lox attach sql-dev` reaches the console's own terminal, for
debugging.

`locksql console` is started by `lox run` only: on the host the launcher
refuses it (`the console is started by lox run only (lockhub): run lox run
in the workspace`, exit code 2).

The console runs as the `locksql` account (uid 10001) in its own container,
the only one that holds the database credentials. The agent's MCP server runs
as `agent` (uid 10002) in a throwaway container. The two share only the
console's socket volume, which `lox run` names in `.lockfamily/up.json` and the
launcher mounts read-only once Docker confirms it is lox run's
([docs/launcher.md](launcher.md#the-socket-of-lox-runs-lock)); the kernel
checks every peer on the socket.

`init` writes each detected agent's MCP config (`.mcp.json` for Claude Code,
`.cursor/mcp.json`, `.gemini/settings.json`; for Codex it prints the
`~/.codex/config.toml` snippet) with `locksql mcp`: the launcher, which
starts the MCP server in the image. (`lox add` runs only `init claude`.) `profile add` asks for the engine, host, TLS and where the
password comes from (typed at console start, or Vault), never for the
password itself; `--non-interactive` takes them from flags instead, and
`--json` answers in one line of JSON, as `lox add` calls it
([docs/usage.md](usage.md#locksql-profile-add)). Inside a container `localhost` is the container: a database
on your machine is `host.docker.internal`, which the lock's egress gateway
(started by `lox run`) maps to your machine. The launcher adds no mapping. `locksql version` prints the launcher's version and its image's,
`locksql update` updates both. What runs where, Vault, and an agent that
itself runs in a container are in [docs/docker.md](docker.md).

## Install

locksql runs in Docker. On the host, `scripts/install.sh` installs only the
`locksql` launcher, a shell script that runs every command in the release's
image (`ghcr.io/davidgodefroid/locksql`, pinned by its cosign-verified
digest; by its tag `:X.Y.Z` only when the check was skipped), each with the account it
needs: the console as `locksql` in one container, the agent's MCP server as
`agent` in another. With Homebrew, trust the tap once (Homebrew asks you to
trust a third-party tap before it loads its formulas), then install:

```sh
brew trust davidgodefroid/tap
brew install davidgodefroid/tap/locksql davidgodefroid/tap/lox cosign   # or davidgodefroid/tap/lockfamily for the whole family
```

Otherwise, download the script from the release tag you install, read it,
then run it. It needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
v2.5.0 or later on PATH, and exits with `cosign is required…` without it (unless
`LOCKSQL_SKIP_COSIGN=1`, which skips the checks only when cosign is absent):

```sh
V=vX.Y.Z
curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/locksql/$V/scripts/install.sh"
less install.sh
LOCKSQL_VERSION=$V sh install.sh
```

It checks the release's cosign signatures (of `checksums.txt` and of the
images) and the checksum. `locksql version` prints the launcher's version
and its image's; `locksql update` installs a newer release's launcher,
checked the same way, and pulls its image (for an install.sh install; a
Homebrew install upgrades with `brew upgrade locksql`). Linux
and macOS; on Windows, WSL 2 with Docker Desktop. `LOCKSQL_IMAGE` runs an
image of your own (`docker build -t locksql .` from a clone), `LOCKSQL_VAULT=1`
the image with the vault CLI. Read what Docker does and does not separate
before you rely on it:
[docs/docker.md](docker.md#what-docker-does-and-does-not-separate).

The image refuses the former host install (`locksql install`, `setup` and
the binary's own `update`): [migrating from a host
install](docker.md#migrating-from-a-host-install).

With [lea](https://github.com/DavidGodefroid/lea), `lox add locksql`, run in lea's
projects directory (lea reads `.lockfamily/up.json` only there), sets up the
lock (with your uid in its `allowed_uids`, as lea's agents run as you) and
`lox run` runs the console; with locksql on in lea (on when `lox run` runs a
locksql lock, or `lea init --locksql`, `LEA_LOCKSQL=1`), its agents reach
the lock's socket read-only. lea starts
no console and puts no `locksql` command on the host.

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locksql
```

Requires Go 1.26 or later.
