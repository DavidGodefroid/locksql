package ipc

import (
	"fmt"
	"net"
)

// On Windows the console's socket is not served: it would need a named
// pipe ACL'd to a dedicated account, which locksql does not implement.
// Every entry point refuses, so a console never listens without its peer
// checks.

func privateDir(string) error { return fmt.Errorf("ipc: console socket %w", ErrUnsupported) }

func restrictSocket(string) error { return fmt.Errorf("ipc: console socket %w", ErrUnsupported) }

// ListenShared refuses on Windows.
func ListenShared(string, int) (net.Listener, error) {
	return nil, fmt.Errorf("ipc: console socket %w", ErrUnsupported)
}
