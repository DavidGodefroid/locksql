package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TLSProber is implemented by the engines whose protocol starts TLS before
// authentication. ProbeTLS connects to the profile's server directly (not
// through an ssh tunnel), starts TLS as the engine does and returns the
// certificates the server presents, leaf first, verifying nothing. It sends
// no user name and no secret, and presents no client certificate: locksql
// doctor uses it from an account that holds none.
type TLSProber interface {
	ProbeTLS(ctx context.Context, p config.Profile) ([]*x509.Certificate, error)
}

// ErrNoServerTLS reports a server that does not offer TLS.
var ErrNoServerTLS = errors.New("the server does not offer TLS")

// ProbeDial opens the TCP connection of a probe to the profile's host and
// port (def when the profile has none), bounded by ctx.
func ProbeDial(ctx context.Context, p config.Profile, def int) (net.Conn, error) {
	port := p.Port
	if port <= 0 {
		port = def
	}
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(d)
	}
	return nc, nil
}

// ProbeHandshake makes the TLS client handshake of a probe on nc and
// returns the server's certificates. A server that then refuses the
// handshake for want of a client certificate has already shown its own:
// they are returned with the error.
func ProbeHandshake(nc net.Conn, p config.Profile) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // the caller verifies, to say what fails
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range raw {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			return nil
		},
	}
	if name := p.TLSServerName; name != "" {
		cfg.ServerName = name
	} else if net.ParseIP(p.Host) == nil {
		cfg.ServerName = p.Host // SNI
	}
	tc := tls.Client(nc, cfg)
	err := tc.Handshake()
	tc.Close()
	if len(certs) == 0 && err == nil {
		err = errors.New("the server sent no certificate")
	}
	return certs, err
}
