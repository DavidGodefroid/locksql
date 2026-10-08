// Package ipc is the console's local transport: a Unix domain socket in a
// directory private to the user (on Linux, macOS and Windows 10 1803+),
// newline-delimited JSON-RPC 2.0 framing capped at 1 MiB, and a peer check.
package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// maxSocketPath is the longest socket path the OS accepts: sizeof(sun_path)
// minus the terminating NUL (104 on macOS, 108 on Linux and Windows).
var maxSocketPath = func() int {
	if runtime.GOOS == "darwin" {
		return 103
	}
	return 107
}()

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func checkName(what, s string) error {
	if !nameRe.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Errorf("ipc: invalid %s %q", what, s)
	}
	return nil
}

// SocketPath returns the console socket of a project and profile:
// <runtime dir>/locksql/<project-hash>-<profile>.sock, where the runtime
// dir is $LOCKSQL_RUNTIME_DIR when set, else $XDG_RUNTIME_DIR (Linux),
// $TMPDIR (macOS) or, on Windows,
// %LOCALAPPDATA% with the path %LOCALAPPDATA%\locksql\run\... When
// $XDG_RUNTIME_DIR or $TMPDIR is unusable the directory is
// <temp>/locksql-<uid>. A name that would exceed the OS socket path limit
// is replaced by <project-hash>-~<sha256(profile)[:16]>.sock, which is still
// stable, so the client and the console agree on it.
func SocketPath(projectHash, profile string) (string, error) {
	if err := checkName("project hash", projectHash); err != nil {
		return "", err
	}
	if err := checkName("profile", profile); err != nil {
		return "", err
	}
	dir, err := runtimeDir()
	if err != nil {
		return "", err
	}
	return socketIn(dir, projectHash, profile)
}

// SharedSocketPath is SocketPath in the shared socket directory of a
// separated setup.
func SharedSocketPath(dir, projectHash, profile string) (string, error) {
	if err := checkName("project hash", projectHash); err != nil {
		return "", err
	}
	if err := checkName("profile", profile); err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("ipc: shared socket dir %q is not absolute", dir)
	}
	return socketIn(dir, projectHash, profile)
}

func socketIn(dir, projectHash, profile string) (string, error) {
	p := filepath.Join(dir, projectHash+"-"+profile+".sock")
	if len(p) <= maxSocketPath {
		return p, nil
	}
	sum := sha256.Sum256([]byte(profile))
	p = filepath.Join(dir, projectHash+"-~"+hex.EncodeToString(sum[:])[:16]+".sock")
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("ipc: socket path %s is longer than %d bytes", p, maxSocketPath)
	}
	return p, nil
}

// RuntimeDirEnv overrides the runtime dir on every OS when set to an
// absolute path: the sockets then live in $LOCKSQL_RUNTIME_DIR/locksql. The
// console and its clients must see the same value. Tests use it to keep
// sockets in a temp dir.
const RuntimeDirEnv = "LOCKSQL_RUNTIME_DIR"

func runtimeDir() (string, error) {
	if d := os.Getenv(RuntimeDirEnv); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "locksql"), nil
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" || !filepath.IsAbs(base) {
			d, err := os.UserCacheDir() // %LocalAppData% on Windows
			if err != nil {
				return "", fmt.Errorf("ipc: no local app data dir: %w", err)
			}
			base = d
		}
		return filepath.Join(base, "locksql", "run"), nil
	case "darwin":
		if d := os.Getenv("TMPDIR"); d != "" && filepath.IsAbs(d) && d != "/tmp" && d != "/tmp/" {
			return filepath.Join(d, "locksql"), nil
		}
	default:
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, "locksql"), nil
		}
	}
	// Shared temp dir fallback: the per-user directory itself is the private
	// one, so Listen checks its owner and mode (the sticky /tmp keeps others
	// from renaming it).
	uid := os.Getuid()
	if uid < 0 {
		return "", errors.New("ipc: no runtime dir")
	}
	return filepath.Join("/tmp", fmt.Sprintf("locksql-%d", uid)), nil
}
