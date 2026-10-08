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
	cred, err := PeerCred(c)
	if err != nil {
		return false, err
	}
	return cred.UID == os.Getuid(), nil
}

// PeerCred returns the kernel's record of the process at the other end of
// c (LOCAL_PEERCRED and LOCAL_PEERPID): it cannot be forged by the peer.
func PeerCred(c net.Conn) (Cred, error) {
	uc, err := unixConn(c)
	if err != nil {
		return Cred{}, err
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	var cred *unix.Xucred
	var cerr error
	pid := -1
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if p, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			pid = p
		}
	}); err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	if cerr != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", cerr)
	}
	gid := -1
	if cred.Ngroups > 0 {
		gid = int(cred.Groups[0])
	}
	return Cred{UID: int(cred.Uid), GID: gid, PID: pid}, nil
}
