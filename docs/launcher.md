# The locksql launcher

locksql runs in Docker. On the host there is one `locksql` command, the
launcher [`scripts/locksql`](../scripts/locksql), a POSIX shell script that
runs every subcommand in the release image. There is no other `locksql` on
the host to explain: `locksql console`, `locksql version`, `locksql mcp` all
go through it. This page is its design, the pattern for the other lock tools.

## What is installed

| Where | What |
|---|---|
| host | `/usr/local/bin/locksql`: the launcher, root-owned (the agent's account cannot replace it), put there by `scripts/install.sh` |
| registry | `ghcr.io/davidgodefroid/locksql:X.Y.Z` and `:X.Y.Z-vault`, amd64 and arm64, cosign-signed by the release workflow |
| release archives | the launcher (`scripts/locksql`) and the binary; the binary serves only an agent that runs in a container of its own ([docker.md](docker.md#agent-in-its-own-container)) |

No host packages (`.deb`, `.rpm`, `.apk`) and no host binary.

## Subcommand → `docker run` profile

Every run is `docker run --rm -v "$PROJECT:$PROJECT" -w "$PWD"
$LOCKSQL_DOCKER_ARGS ... IMAGE SUBCOMMAND ARGS`, where `PROJECT` is the
nearest directory up from `$PWD` holding `.locksql/` (else `$PWD`), mounted
at its own path so that paths, and the socket name derived from the project
path, are the same inside and outside. `-it` when stdin and stdout are
terminals, else `-i`.

| Subcommand | Account | Extra | Why |
|---|---|---|---|
| `console` | `locksql` (uid 10001) | `--name locksql-console-<cksum of PROJECT>` (one console per project; `LOCKSQL_CONSOLE_NAME` overrides it), `--log-driver none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` with a 64 MB `/tmp` tmpfs, `--pids-limit 256`, `--memory 1g`, `--add-host=host.docker.internal:host-gateway`, `-e VAULT_ADDR -e VAULT_NAMESPACE`, `VAULT_CACERT`'s file mounted read-only at its own path, volumes `locksql-run` and `locksql-home`, `--project PROJECT` unless given | the only holder of credentials; no log driver so `docker logs` keeps no screen; a stopped container of the same name is removed first |
| `stats`, `forget` | `locksql` | volume `locksql-home` | they read the console account's state |
| `init`, `config` | you (`id -u`:`id -g`) | `-e HOME=$HOME -v $HOME:$HOME` | they write your agents' files and your user config, owned by you |
| `profile` | you | `-e HOME=/tmp` | it writes `.locksql/config.toml`, yours to edit |
| `doctor --fix` | root (`--user 0`) | | gives `.locksql/` to uid 10001, which exists only in the image |
| `mcp` | `agent` (uid 10002, image default) | volume `locksql-run`, `-i` only | the agent speaks MCP on stdin/stdout |
| anything else (`status`, `tables`, `plan`, `run`, `doctor`, `help`, ...) | `agent` | volume `locksql-run` | client commands reach the console through the socket only |
| `version` | | | prints `locksql launcher X (image I)`, then runs `I version` |
| `update [vX.Y.Z]` | (host) | | below |

Invariants: the Docker socket is never mounted; only the console's
container gets `locksql-home`; the agent's containers share only
`locksql-run` with it.

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
- `LOCKSQL_READONLY_PROJECT=1`: the console mounts the project read-only and
  only `.locksql/` writable (which must be a directory, not a link), for a
  project your agents write; lea sets it.

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
  giving `.locksql/` to uid 10001 (a `chown` through Docker Desktop's file
  sharing).
- Windows: no native build. Install the launcher in WSL 2 with Docker
  Desktop's WSL integration and run it there; the Windows binary refuses
  every command but `version` and `help`, pointing there.

## Paths

A project path, `$HOME` (for `init`, `config`) or a `VAULT_CACERT` path
holding `:` is refused: docker `-v` separates on it. `LOCKSQL_DOCKER_ARGS`
is split on spaces and never globbed.

An explicit `--project DIR` (or `--project=DIR`), for any subcommand, is
the project mounted instead of the one of the working directory: resolved
to its physical path, which replaces `DIR` in the command; the command runs
from there unless the working directory is inside it.

With `LOCKSQL_READONLY_PROJECT=1`, `.locksql/` must be a directory whose
physical path is itself; the launcher checks it twice, the second time
right before `docker run`. On Linux it also passes the device and inode it checked
(`LOCKSQL_EXPECT_DIR=DEV:INO`), and the console refuses to start on a
`.locksql` with others: a directory swapped in between the check and
Docker's mount never gets the console. On macOS (Docker Desktop's file
sharing reports other inodes) only the two checks run. lea also mounts
`.locksql` read-only in its agents' containers, which cannot swap it.

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
