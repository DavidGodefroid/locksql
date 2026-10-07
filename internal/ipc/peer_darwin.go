//go:build darwin

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// PeerAllowed reports whether the process at the other end of c runs as the
// same user as the console (LOCAL_PEERCRED, as getpeereid does).
func PeerAllowed(c net.Conn) (bool, error) {
	uc, err := unixConn(c)
	if err != nil {
		return false, err
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("ipc: peer check: %w", err)
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return false, fmt.Errorf("ipc: peer check: %w", err)
	}
	if cerr != nil {
		return false, fmt.Errorf("ipc: peer check: %w", cerr)
	}
	return int(cred.Uid) == os.Getuid(), nil
}
