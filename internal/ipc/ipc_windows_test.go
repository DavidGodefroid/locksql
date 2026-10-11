package ipc

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
)

// On Windows no console socket is served and no peer is accepted.
func TestWindowsRefusesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.sock")
	if ln, err := Listen(path); !errors.Is(err, ErrUnsupported) {
		if ln != nil {
			ln.Close()
		}
		t.Fatalf("Listen: %v, want ErrUnsupported", err)
	}
	if _, err := ListenShared(path, 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenShared: %v", err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if ok, err := PeerAllowed(a); ok || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("PeerAllowed: %v %v", ok, err)
	}
}
