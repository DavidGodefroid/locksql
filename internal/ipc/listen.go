package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Cred is what the kernel says about the process at the other end of a
// socket. PID is -1 when the platform does not report it; on Windows UID is
// -1 too (no peer credentials).
type Cred struct {
	UID, GID, PID int
}

// ErrAlreadyRunning means a live console already listens on the socket.
var ErrAlreadyRunning = errors.New("ipc: a console is already running for this profile")

// Listen opens the console socket at path. The parent directory is made
// private (0700 and owned by the user on Unix; the user's ACL under
// %LOCALAPPDATA% on Windows) and the socket is 0600 on Unix. A socket left
// by a dead console is replaced; one with a live console gives
// ErrAlreadyRunning; any other kind of file at path is left alone and
// refused. Closing the listener removes the socket.
func Listen(path string) (net.Listener, error) {
	if err := privateDir(path); err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		// Two consoles started together: the loser finds a live socket.
		if alive(path) {
			return nil, fmt.Errorf("%w (%s)", ErrAlreadyRunning, path)
		}
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := restrictSocket(path); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func alive(path string) bool {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func clearStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("ipc: %s exists and is not a socket; refusing to replace it", path)
	}
	if alive(path) {
		return fmt.Errorf("%w (%s)", ErrAlreadyRunning, path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ipc: removing stale socket: %w", err)
	}
	return nil
}

func unixConn(c net.Conn) (*net.UnixConn, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("ipc: peer check needs a unix socket, got %T", c)
	}
	return uc, nil
}
