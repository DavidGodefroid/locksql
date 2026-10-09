package engine

import (
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// Transport is how a session reached its server, for the notices: the
// profile's tls mode, tls_ca and host, whether the TCP connection runs
// without TLS, and whether it was dialled through an SSH tunnel.
type Transport struct {
	Mode, CA, Host string
	Plain          bool
	Tunneled       bool
}

// Notices reports a connection an attacker on the path could read or stand
// in for: plain TCP, or TLS whose certificate chain is not verified. A
// tunnelled session is not advised to use an ssh tunnel.
func (t Transport) Notices() []string {
	mode := t.Mode
	if mode == "" {
		mode = config.TLSPrefer
	}
	switch {
	case t.Plain:
		advice := "set tls = \"verify-full\" or use an ssh tunnel"
		if t.Tunneled {
			advice = "set tls = \"verify-full\", or run the ssh tunnel to the database's own host"
		}
		return []string{"the connection is NOT encrypted (tls = \"" + mode + "\"); " + advice}
	case !config.TLSVerifiesChain(t.Mode, t.CA) && !strings.HasPrefix(t.Host, "/") && !config.IsLoopback(t.Host):
		return []string{"the server certificate is not verified (tls = \"" + mode + "\"); set tls = \"verify-full\""}
	}
	return nil
}
