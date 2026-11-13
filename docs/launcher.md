# The locksql launcher

locksql runs in Docker. On the host there is one `locksql` command, the
launcher [`scripts/locksql`](../scripts/locksql), a POSIX shell script that
runs every subcommand in the release image. There is no other `locksql` on
the host to explain: `locksql version`, `locksql mcp` and the others all
go through it; the console is started by `lox run` only (lockhub). This page is its design, the pattern for the other lock tools.

## What is installed

| Where | What |
|---|---|
| host | `/usr/local/bin/locksql`: the launcher, root-owned (the agent's account cannot replace it), put there by `scripts/install.sh` |
| registry | `ghcr.io/davidgodefroid/locksql:X.Y.Z` and `:X.Y.Z-vault`, amd64 and arm64, cosign-signed by the release workflow |
| release archives | the launcher (`scripts/locksql`) and the binary; the binary serves only an agent that runs in a container of its own ([docker.md](docker.md#agent-in-its-own-container)) |

No host packages (`.deb`, `.rpm`, `.apk`) and no host binary.

## Subcommand → `docker run` profile

Every run is `docker run --rm -v "$PROJECT:$PROJECT" -w "$PWD"
[-v "$MANAGED:/etc/lockfamily:ro"] $LOCKSQL_DOCKER_ARGS ... IMAGE
SUBCOMMAND ARGS`, where `PROJECT` is the nearest directory up from `$PWD`
holding `.locksql/` (else `$PWD`), mounted at its own path so that paths,
and the socket name derived from the project path, are the same inside and
outside. `MANAGED` is the company's managed directory, by `uname -s`
(`/Library/Application Support/lockfamily` on Darwin, else
`/etc/lockfamily`), mounted read-only on `/etc/lockfamily` as `lox run`
mounts it in its locks (lockhub#179): absent, no mount; a file, a dangling
link or a `:` in its path stops the launcher before `docker run`
([docker.md](docker.md#the-companys-managed-configuration)). `-it` when
stdin and stdout are terminals, else `-i`.

| Subcommand | Account | Extra | Why |
|---|---|---|---|
| `stats`, `forget` | `locksql` | lox run's home volume of the workspace's locksql lock, on `/home/locksql` (below) | they read and change the console account's state: its audit log, its keychain secrets |
| `init`, `config` | you (`id -u`:`id -g`) | `-e HOME=$HOME -v $HOME:$HOME` | they write your agents' files and your user config, owned by you |
| `profile` | you | `-e HOME=/tmp` | it writes `.locksql/config.toml`, yours to edit |
| `doctor --fix` | you (`id -u`:`id -g`), in the group `locksql-clients`; root (`--user 0`) first, only when `.locksql/` holds entries that are not yours | `-e HOME=$HOME -e USER -v $HOME:$HOME`, `-e LOCKSQL_DOCTOR_FOR=uid:gid`; no socket volume | it wires your agents and keeps `.locksql/` as `lox run` reads it: yours, writable by you only. The root run gives back to you what the console account owns in `.locksql/` (left by `doctor --fix` up to v0.13.0, which `lox run` refuses), nothing else, its output on stderr |
| `mcp` | `agent` (uid 10002, image default) | lox run's socket volume of the workspace's locksql lock, read-only (below), `-i` only | the agent speaks MCP on stdin/stdout |
| `status`, `tables`, `describe`, `plan`, `run`, `request`, `logout`, `pii` | `agent` | lox run's socket volume, read-only (below) | client commands reach the console through the socket only |
| `doctor` | `agent` | lox run's socket volume when there is one; else none, and the launcher says why; `-e LOCKSQL_DOCTOR_FOR=uid:gid` | the checks run either way; `.locksql/` is checked for you |
| anything else (`help`, ...) | `agent` | | no console to reach |
| `version` | | | prints `locksql launcher X (image I)`, then runs `I version` |
| `update [vX.Y.Z]` | (host) | | below |
| `console` | | | none: it exits 2, `the console is started by lox run only (lockhub): run lox run in the workspace`, and runs nothing; no client reaches a console started by hand |

Invariants: the Docker socket is never mounted; the agent's containers
share only the console's socket volume with it, read-only.

## The socket of lox run's lock

The consoles run hub-attached only, started by `lox run` (lockhub): each
under compose, with its socket in the volume
`lockfamily-<8 hex of sha256(workspace)>_<instance>-run`, which `lox run`
names in `<workspace>/.lockfamily/up.json` (lockhub's `docs/lox-run.md`).
The agent commands mount that volume on `/run/locksql`, read-only
(connecting to a socket needs no write), and no other: without it they stop
(exit 2) and say why, and what to do (`lox run`), never falling back to
another volume. The launcher takes the volume only after the checks
lea makes for its own agents:

- `up.json` is found in the nearest directory up from here whose
  `.lockfamily` holds one (that directory is the workspace); the
  `.lockfamily` directory and `up.json` are no link, are yours, and
  neither group nor others may write them; `up.json` is lox run's state
  (version 1, as `lox run` writes it: two-space indented JSON, the values
  the launcher reads unescaped) of this very workspace (its `workspace`,
  and its `project` `lockfamily-<8 hex of sha256(workspace)>`);
- the lock is the workspace's only locksql lock, or the one `--instance
  NAME` names (the launcher's own option, taken out of the command line;
  with several and no `--instance`, the error names them). In
  `.mcp.json`, add it to the arguments: `"args": ["mcp", "--instance",
  "NAME"]`;
- its socket volume is the one `lox run` names for it, its clients group
  the image's (10000);
- Docker confirms the volume: lox run's labels (compose's project and
  volume, `dev.lockfamily.role=socket`, its instance, type and workspace),
  read as JSON and compared whole; and every container that mounts it is
  lox run's own (compose ran it from lox run's state directory: its
  `project.working_dir` is `$XDG_STATE_HOME/lockfamily/<project>` or
  `~/.local/state/lockfamily/<project>`, its `config_files` `-` or that
  directory's `compose.yaml`) or mounts it read-only (the agents', as the
  launcher's own). A compose file written in the workspace, with lox run's
  project name and volume, or any container mounting the volume
  read-write, could serve the socket from an image of its own: the
  launcher then trusts none of that socket.

`up.json` only names the lock: what is mounted is what Docker's labels
prove. Anything else fails closed.

What these checks are for: mistakes (a stale or copied `up.json`, another
workspace's lock, a volume or compose file of the same name) and files
others than you can write. They are no boundary against an agent that
runs as you on the host with Docker access (Claude Code started in a
terminal usually does): it can write `up.json`, make volumes and
containers with any labels, or `docker exec` into lox run's containers.
Even then it holds none of the console's credentials and cannot sign a
decision (the hub signs them, the console checks the hub's key), but it
could serve an impostor socket to another agent. To contain the agent
itself, run it in lea, whose containers have no Docker access.

The socket's name derives from the project (`.locksql/config.toml` up from
the working directory) and the profile: run the agent from the workspace,
whose `.locksql` lox run's console serves. A sub-project with a
`.locksql/config.toml` of its own below the workspace would key its
socket on itself, which no console serves: there the agent commands stop
(exit 2) and say so (run locksql from the workspace, or make the
sub-project a workspace of its own with `lox init`). A workspace path
holding `&`, `<` or `>`, which `up.json` escapes, is refused too, with a
message that says so: move or rename the workspace.

## The home of lox run's lock

`stats` and `forget` run as the console account with the home volume
`lox run` gives the lock's console,
`lockfamily-<8 hex of sha256(workspace)>_<instance>-home`, mounted on
`/home/locksql`: there are the audit log `stats` counts and the keychain
secret `forget` removes. The lock is found as for the agent commands (the
checks above, its socket volume included; `--instance NAME` for one of
several), then Docker must confirm its home volume: compose's labels of
lox run's project and of `<instance>-home` (lox run gives it no others).
Anything else stops them (exit 2) with why.

Without lox run's state (no `.lockfamily/up.json` up from here), they
mount the volume `locksql-home` of a console started by hand (`locksql
console`, up to v0.17), and say so, when that volume exists; else they
stop (exit 2) and never create it. A `.lockfamily/up.json` the launcher
cannot trust is no such case: they stop.

## Version pinning

`install.sh` and `update` write three lines of the launcher:

```sh
launcher_version=X.Y.Z
image_digest=sha256:...        # ghcr.io/davidgodefroid/locksql:X.Y.Z
vault_image_digest=sha256:...  # ...:X.Y.Z-vault
```

The digests come from `cosign verify` of the two images against the release
workflow run for that exact tag
(`.../release.yml@refs/tags/vX.Y.Z`: an older release's signed image, retagged,
does not verify), and must differ; the launcher then runs
`registry@sha256:...`, never a tag that could move. With
`LOCKSQL_SKIP_COSIGN=1` nothing is verified: the digests stay empty and the
launcher runs `registry:X.Y.Z`. A launcher run from a clone
(`launcher_version=dev`) runs the local image `locksql`.

## Overrides

- `LOCKSQL_IMAGE`: the image to run, instead of the pinned one (your own
  build, an image with `ssh` for `proxy_command`, `ALLOWED_UIDS`);
- `LOCKSQL_VAULT=1`: the `-vault` image;
- `LOCKSQL_DOCKER_ARGS`: extra `docker run` arguments, split on spaces
  (`--network NAME`, `-e DOCKER_HOST=...`).

## Install and update

`scripts/install.sh` (read it, then run it with `LOCKSQL_VERSION`) and
`locksql update [vX.Y.Z]` do the same steps:

1. refuse anything but a release tag (`vX.Y.Z[-pre]`): it goes into URLs
   and into the launcher's text;
2. download the release archive for this OS and architecture,
   `checksums.txt` and its sigstore bundle;
3. `cosign verify-blob` the bundle against the release workflow run for
   that exact tag (`--certificate-identity .../release.yml@refs/tags/vX.Y.Z`),
   then check the archive's sha256;
4. `cosign verify` both images against the same identity and take their
   digests, which must differ;
5. extract `scripts/locksql`, write the version and digests into it, and
   install it root-owned (with `sudo` when the directory is not writable);
6. `update` then runs `docker pull` of the pinned image.

Any failed check stops before the launcher is replaced. cosign is required
(`LOCKSQL_SKIP_COSIGN=1` is the explicit way past it).

## Platforms

- Linux: Docker Engine; `host.docker.internal` comes from the
  `host-gateway` mapping the launcher adds.
- macOS: Docker Desktop; same launcher. Untested so far: `doctor --fix`
  giving back `.locksql/` entries that are not yours (a `chown` as root
  through Docker Desktop's file sharing).
- Windows: no native build. Install the launcher in WSL 2 with Docker
  Desktop's WSL integration and run it there; the Windows binary refuses
  every command but `version` and `help`, pointing there.

## Paths

A project path or `$HOME` (for `init`, `config`) holding `:` is refused: docker `-v` separates on it. `LOCKSQL_DOCKER_ARGS`
is split on spaces and never globbed.

An explicit `--project DIR` (or `--project=DIR`) of `profile`, the
subcommand that takes it, is
the project mounted instead of the one of the working directory: resolved
to its physical path, which replaces `DIR` in the command; the command runs
from there unless the working directory is inside it.

## Former host install

The image refuses `install`, `setup` and its own `update`, and bare
`locksql` prints the help. [Migrating from a host
install](docker.md#migrating-from-a-host-install) lists what a former
`sudo locksql install` leaves behind.

## For the other lock tools

Copy `scripts/locksql`, its tests (`cmd/locksql/launcher_test.go`: a fake
`docker` records each call; `installsh_test.go`: a fake release and a fake
`cosign`) and the release jobs (`image`, `image-manifest` in
`.github/workflows/release.yml`), then change the table above: the accounts,
the volumes and which subcommands run as you, as root or as the console.
