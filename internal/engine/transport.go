package engine

import "github.com/DavidGodefroid/locksql/internal/config"

// Transport is how a session reached its server, for the notices: the
// profile's tls mode and whether the established TCP connection runs
// without TLS. Transport security is the driver's and the infrastructure's
// business: locksql only says when the connection is plaintext.
type Transport struct {
	Mode  string
	Plain bool
}

// Notices reports a plaintext TCP connection, the one transport fact
// locksql tells the human. A TLS connection gets no notice, whatever its
// verification mode, and neither does a Unix socket.
func (t Transport) Notices() []string {
	if !t.Plain {
		return nil
	}
	mode := t.Mode
	if mode == "" {
		mode = config.TLSPrefer
	}
	return []string{"the connection to the database is NOT encrypted (tls = \"" + mode + "\")"}
}
