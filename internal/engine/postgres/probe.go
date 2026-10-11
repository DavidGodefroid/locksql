package postgres

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// sslRequest is the SSLRequest message: length 8, code 80877103.
var sslRequest = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

// ProbeTLS sends the SSL request, which precedes the startup message (so
// no user name, database or password), and makes the TLS handshake. See
// engine.TLSProber.
func (Engine) ProbeTLS(ctx context.Context, p config.Profile) ([]*x509.Certificate, error) {
	nc, err := engine.ProbeDial(ctx, p, 5432)
	if err != nil {
		return nil, err
	}
	defer nc.Close()
	if _, err := nc.Write(sslRequest); err != nil {
		return nil, err
	}
	answer := make([]byte, 1)
	if _, err := io.ReadFull(nc, answer); err != nil {
		return nil, err
	}
	switch answer[0] {
	case 'S':
		return engine.ProbeHandshake(nc, p)
	case 'N':
		return nil, engine.ErrNoServerTLS
	}
	return nil, fmt.Errorf("postgres: unexpected answer %q to the SSL request", answer[0])
}
