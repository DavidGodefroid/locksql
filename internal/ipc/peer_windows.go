//go:build windows

package ipc

import "net"

// PeerAllowed always accepts a unix socket peer on Windows: AF_UNIX has no
// peer credentials there, so the socket directory's ACL is the only check.
// This is a documented limitation.
func PeerAllowed(c net.Conn) (bool, error) {
	if _, err := unixConn(c); err != nil {
		return false, err
	}
	return true, nil
}

// PeerCred has no kernel record to read on Windows: UID is -1.
func PeerCred(c net.Conn) (Cred, error) {
	if _, err := unixConn(c); err != nil {
		return Cred{}, err
	}
	return Cred{UID: -1, GID: -1, PID: -1}, nil
}
