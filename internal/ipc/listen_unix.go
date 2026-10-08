package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// privateDir creates the socket's parent directory with mode 0700 and
// checks that it is a real directory (not a symlink) owned by the user.
func privateDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("ipc: socket dir %s is not a directory (symlink?)", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ipc: cannot read the owner of %s", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("ipc: socket dir %s is owned by uid %d, not by you", dir, st.Uid)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("ipc: %w", err)
		}
	}
	return nil
}

func restrictSocket(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	return nil
}

// ListenShared opens a console socket in the shared socket directory of a
// separated setup (see package sysconf): the directory must already exist
// (locksql install creates it), belong to the console's user and to the
// client group gid, and give others no access; the socket is made
// read-write for that group only (0660). The peer check still decides who
// is served.
func ListenShared(path string, gid int) (net.Listener, error) {
	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("ipc: shared socket dir: %w (run locksql install)", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return nil, fmt.Errorf("ipc: shared socket dir %s is not a directory", dir)
	case !ok:
		return nil, fmt.Errorf("ipc: cannot read the owner of %s", dir)
	case int(st.Uid) != os.Getuid():
		return nil, fmt.Errorf("ipc: shared socket dir %s is owned by uid %d, not by the console's user", dir, st.Uid)
	case int(st.Gid) != gid:
		return nil, fmt.Errorf("ipc: shared socket dir %s does not belong to the client group (gid %d)", dir, gid)
	case fi.Mode().Perm()&0o027 != 0 || fi.Mode().Perm()&0o010 == 0:
		return nil, fmt.Errorf("ipc: shared socket dir %s has mode %04o; want 0710 or 0750", dir, fi.Mode().Perm())
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		if alive(path) {
			return nil, fmt.Errorf("%w (%s)", ErrAlreadyRunning, path)
		}
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return ln, nil
}
