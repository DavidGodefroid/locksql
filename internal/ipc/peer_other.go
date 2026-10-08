//go:build !linux && !darwin && !windows

package ipc

import (
	"errors"
	"net"
)

// PeerAllowed refuses every peer on platforms without a supported peer
// credential check.
func PeerAllowed(net.Conn) (bool, error) {
	return false, errors.New("ipc: peer check not supported on this platform")
}

// PeerCred is not supported on this platform.
func PeerCred(net.Conn) (Cred, error) {
	return Cred{}, errors.New("ipc: peer check not supported on this platform")
}
