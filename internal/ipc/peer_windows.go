package ipc

import (
	"fmt"
	"net"
)

// PeerAllowed refuses every peer on Windows: there is no kernel record of
// the process at the other end to check.
func PeerAllowed(net.Conn) (bool, error) {
	return false, fmt.Errorf("ipc: peer check %w", ErrUnsupported)
}

// PeerCred refuses on Windows.
func PeerCred(net.Conn) (Cred, error) {
	return Cred{}, fmt.Errorf("ipc: peer check %w", ErrUnsupported)
}
