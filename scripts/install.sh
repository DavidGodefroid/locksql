#!/bin/sh
# Installs the locksql launcher of a release on Linux or macOS (WSL 2 on
# Windows). locksql runs in Docker: the launcher, installed as `locksql`,
# runs every command in the release's image (scripts/locksql,
# docs/docker.md). Nothing else lands on the host.
#
# Download it from the tag you install, read it, then run it with that tag:
#
#   V=vX.Y.Z
#   curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/locksql/$V/scripts/install.sh"
#   less install.sh
#   LOCKSQL_VERSION=$V sh install.sh
#
# Environment:
#   LOCKSQL_VERSION      tag to install (default: the latest release), e.g. v0.8.1
#   LOCKSQL_INSTALL_DIR  target directory (default: /usr/local/bin, via sudo if needed)
#   LOCKSQL_SKIP_COSIGN=1  install without cosign: the signature is then NOT checked
#
# cosign is required: the keyless signature of checksums.txt must come from
# this repository's release workflow run for a version tag, and the archive is
# checked against checksums.txt. The checksum alone only detects corruption,
# since it comes from the same release. The launcher comes from that archive.
# `locksql update` later replaces it the same way.
set -eu

repo="DavidGodefroid/locksql"
dir="${LOCKSQL_INSTALL_DIR:-/usr/local/bin}"

say() { printf 'locksql: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL -o "$2" "$1"; }
	latest() { curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
	latest() { wget -q -S --spider "https://github.com/$repo/releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
else
	die "curl or wget is required"
fi

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS $(uname -s): Linux and macOS only" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m): amd64 and arm64 only" ;;
esac

tag="${LOCKSQL_VERSION:-}"
if [ -z "$tag" ]; then
	tag="$(latest)"
	tag="${tag##*/}"
	case "$tag" in
	v[0-9]*) ;;
	*) die "no published release found; set LOCKSQL_VERSION" ;;
	esac
fi
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
version="${tag#v}"

archive="locksql_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive ($tag)"
fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: checksums.txt"

# The release workflow run for a version tag, as locksql update checks it.
identity='^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v[0-9]'
if command -v cosign >/dev/null 2>&1; then
	fetch "$base/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" ||
		die "download failed: checksums.txt.sigstore.json"
	cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity-regexp "$identity" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		"$tmp/checksums.txt" >/dev/null 2>&1 || die "cosign: signature of checksums.txt does not verify"
	say "cosign: checksums.txt signature verified"
elif [ "${LOCKSQL_SKIP_COSIGN:-0}" = 1 ]; then
	say "WARNING: LOCKSQL_SKIP_COSIGN=1: the signature of checksums.txt is NOT checked; the checksum only detects corruption"
else
	die "cosign is required to check the release's signature (https://docs.sigstore.dev/cosign/system_config/installation/); LOCKSQL_SKIP_COSIGN=1 installs without it"
fi

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
	got="$(sha256sum "$tmp/$archive" | awk '{ print $1 }')"
else
	got="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
fi
[ "$want" = "$got" ] || die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" scripts/locksql 2>/dev/null ||
	die "$archive holds no launcher (scripts/locksql): $tag predates the Docker launcher"
# The launcher runs the image of its own version.
sed "s/^launcher_version=dev\$/launcher_version=$version/" "$tmp/scripts/locksql" >"$tmp/launcher"
grep -qx "launcher_version=$version" "$tmp/launcher" || die "the launcher of $tag does not take its version"

# Root-owned in a system directory, so that the agent's account cannot
# replace it. It replaces the binary of a former host install.
if [ -w "$dir" ] || { [ ! -e "$dir" ] && mkdir -p "$dir" 2>/dev/null; }; then
	install -m 0755 "$tmp/launcher" "$dir/locksql"
else
	command -v sudo >/dev/null 2>&1 || die "$dir is not writable and sudo is missing; set LOCKSQL_INSTALL_DIR"
	say "installing to $dir with sudo"
	sudo mkdir -p "$dir"
	sudo install -m 0755 "$tmp/launcher" "$dir/locksql"
fi

say "installed the locksql launcher $tag to $dir/locksql (image ghcr.io/davidgodefroid/locksql:$version)"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "$dir is not on your PATH" ;;
esac
command -v docker >/dev/null 2>&1 || say "docker is not installed: the launcher needs it (docs/docker.md)"
# A former host install (sudo locksql install) left its system file behind.
if [ -e /etc/locksql/system.toml ]; then
	say "a former host install remains (/etc/locksql/system.toml): see docs/docker.md#migrating-from-a-host-install"
fi
