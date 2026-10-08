#!/bin/sh
# Installs a released locksql binary on Linux or macOS, without Go.
#
#   curl -fsSL https://raw.githubusercontent.com/DavidGodefroid/locksql/main/scripts/install.sh | sh
#
# Better: download it, read it, then run it.
#
# Environment:
#   LOCKSQL_VERSION      tag to install (default: the latest release), e.g. v0.1.0
#   LOCKSQL_INSTALL_DIR  target directory (default: /usr/local/bin, via sudo if needed)
#   LOCKSQL_REQUIRE_COSIGN=1  fail instead of warning when cosign is not on PATH
#
# The archive is checked against checksums.txt; when cosign is available, the
# keyless signature of checksums.txt is checked too. This script only places
# the binary: `sudo locksql install` sets up separated mode afterwards.
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

if command -v cosign >/dev/null 2>&1; then
	fetch "$base/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" ||
		die "download failed: checksums.txt.sigstore.json"
	cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity-regexp "^https://github.com/$repo/" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		"$tmp/checksums.txt" >/dev/null 2>&1 || die "cosign: signature of checksums.txt does not verify"
	say "cosign: checksums.txt signature verified"
elif [ "${LOCKSQL_REQUIRE_COSIGN:-0}" = 1 ]; then
	die "cosign not found and LOCKSQL_REQUIRE_COSIGN=1"
else
	say "cosign not found: checking the checksum only, not its signature"
fi

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
	got="$(sha256sum "$tmp/$archive" | awk '{ print $1 }')"
else
	got="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
fi
[ "$want" = "$got" ] || die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" locksql

# Root-owned in a system directory: `locksql doctor` expects a binary that
# the agent's account cannot replace.
if [ -w "$dir" ] || { [ ! -e "$dir" ] && mkdir -p "$dir" 2>/dev/null; }; then
	install -m 0755 "$tmp/locksql" "$dir/locksql"
else
	command -v sudo >/dev/null 2>&1 || die "$dir is not writable and sudo is missing; set LOCKSQL_INSTALL_DIR"
	say "installing to $dir with sudo"
	sudo mkdir -p "$dir"
	sudo install -m 0755 "$tmp/locksql" "$dir/locksql"
fi

say "installed $("$dir/locksql" --version 2>/dev/null || echo "$tag") to $dir/locksql"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "$dir is not on your PATH" ;;
esac
