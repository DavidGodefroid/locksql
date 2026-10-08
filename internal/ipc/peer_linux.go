//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// PeerAllowed reports whether the process at the other end of c runs as the
// same user as the console (SO_PEERCRED).
func PeerAllowed(c net.Conn) (bool, error) {
	cred, err := PeerCred(c)
	if err != nil {
		return false, err
	}
	return cred.UID == os.Getuid(), nil
}

// PeerCred returns the kernel's record of the process at the other end of
// c (SO_PEERCRED): it cannot be forged by the peer.
func PeerCred(c net.Conn) (Cred, error) {
	uc, err := unixConn(c)
	if err != nil {
		return Cred{}, err
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	if cerr != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", cerr)
	}
	return Cred{UID: int(cred.Uid), GID: int(cred.Gid), PID: int(cred.Pid)}, nil
}
