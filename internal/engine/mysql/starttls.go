package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// clientSSL is the CLIENT_SSL capability flag.
const clientSSL = 0x00000800

// errNoServerTLS is the refusal of a server that does not offer TLS. Its
// text matches go-mysql's, which noServerTLS recognises for prefer.
var errNoServerTLS = errors.New("the MySQL Server does not support TLS required by the client")

// startTLS makes MySQL's in-band TLS upgrade below the driver, which is
// given no TLS configuration and so sees a plain connection. go-mysql then
// answers a request for the password as it does on plain TCP (never in
// clear), and the guard above can read the authentication in clear.
//
// The protocol: the server greeting arrives in clear; the client's
// handshake response is preceded by an SSL request (its first 32 bytes,
// with CLIENT_SSL) and sent inside TLS. So startTLS checks that the
// greeting offers TLS, turns the driver's handshake response into the SSL
// request, the TLS handshake and the response with CLIENT_SSL, and shifts
// the sequence numbers by one (the SSL request took one) until the first OK
// or ERR packet of the server ends the authentication. Then it only passes
// bytes through the TLS connection.
type startTLS struct {
	net.Conn // the raw connection: deadlines and addresses
	cfg      *tls.Config
	conn     net.Conn // the raw connection, then the TLS one
	state    int
	in       []byte // server bytes not yet framed into a packet
	out      []byte // server packets ready for the driver
	pending  []byte // driver bytes not yet framed into a packet
}

const (
	stGreeting = iota // reading the server greeting
	stResponse        // waiting for the driver's handshake response
	stAuth            // in TLS, authenticating: sequence numbers shift
	stPass            // authenticated: bytes pass through
)

func newStartTLS(raw net.Conn, cfg *tls.Config) *startTLS {
	return &startTLS{Conn: raw, cfg: cfg, conn: raw}
}

func (c *startTLS) Read(b []byte) (int, error) {
	for len(c.out) == 0 {
		if c.state == stPass {
			if len(c.in) > 0 {
				c.out, c.in = c.in, nil
				break
			}
			return c.conn.Read(b)
		}
		buf := make([]byte, 4096)
		n, err := c.conn.Read(buf)
		c.in = append(c.in, buf[:n]...)
		if ferr := c.frame(); ferr != nil {
			return 0, ferr
		}
		if err != nil && len(c.out) == 0 {
			return 0, err
		}
	}
	n := copy(b, c.out)
	c.out = c.out[n:]
	return n, nil
}

// frame moves the complete server packets of in to out, checking the
// greeting and shifting sequence numbers during the authentication.
func (c *startTLS) frame() error {
	for c.state != stPass && len(c.in) >= 4 {
		size := int(c.in[0]) | int(c.in[1])<<8 | int(c.in[2])<<16
		if size == maxPacket {
			return errHugePacket
		}
		if len(c.in) < 4+size {
			return nil
		}
		pkt := c.in[:4+size]
		c.in = c.in[4+size:]
		switch c.state {
		case stGreeting:
			if size > 0 && pkt[4] != 0xff { // not an ERR packet
				if !greetingOffersTLS(pkt[4:]) {
					return errNoServerTLS
				}
				c.state = stResponse
			}
		case stAuth:
			pkt[3]--
			if size > 0 && (pkt[4] == 0x00 || pkt[4] == 0xff) { // OK or ERR
				c.state = stPass
			}
		}
		c.out = append(c.out, pkt...)
	}
	if c.state == stPass && len(c.in) > 0 {
		c.out, c.in = append(c.out, c.in...), nil
	}
	return nil
}

// greetingOffersTLS reads the lower capability flags of a protocol 10
// greeting: version, server version (NUL-terminated), connection id,
// 8 bytes of scramble and a filler precede them.
func greetingOffersTLS(p []byte) bool {
	if len(p) < 1 || p[0] != 10 {
		return false
	}
	i := 1
	for i < len(p) && p[i] != 0 {
		i++
	}
	i += 1 + 4 + 8 + 1
	if i+2 > len(p) {
		return false
	}
	return binary.LittleEndian.Uint16(p[i:])&clientSSL != 0
}

func (c *startTLS) Write(b []byte) (int, error) {
	if c.state == stPass {
		return c.conn.Write(b)
	}
	c.pending = append(c.pending, b...)
	for len(c.pending) >= 4 {
		size := int(c.pending[0]) | int(c.pending[1])<<8 | int(c.pending[2])<<16
		if size == maxPacket {
			return 0, errHugePacket
		}
		if len(c.pending) < 4+size {
			break
		}
		pkt := append([]byte{}, c.pending[:4+size]...)
		c.pending = c.pending[4+size:]
		if err := c.send(pkt); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// send writes one driver packet.
func (c *startTLS) send(pkt []byte) error {
	switch c.state {
	case stResponse:
		if len(pkt) < 4+32 {
			return errors.New("mysql: handshake response too short for TLS")
		}
		caps := binary.LittleEndian.Uint32(pkt[4:])
		binary.LittleEndian.PutUint32(pkt[4:], caps|clientSSL)
		req := make([]byte, 4+32)
		copy(req, pkt[:4+32])
		req[0], req[1], req[2] = 32, 0, 0
		if _, err := c.conn.Write(req); err != nil {
			return err
		}
		tc := tls.Client(c.conn, c.cfg)
		if err := tc.Handshake(); err != nil {
			return err
		}
		c.conn = tc
		c.state = stAuth
		pkt[3]++
	case stAuth:
		pkt[3]++
	}
	_, err := c.conn.Write(pkt)
	return err
}

func (c *startTLS) Close() error { return c.conn.Close() }

// ProbeTLS reads the server greeting, sends the SSL request (capabilities
// only: no user, no password) and makes the TLS handshake. See
// engine.TLSProber.
func (Engine) ProbeTLS(ctx context.Context, p config.Profile) ([]*x509.Certificate, error) {
	nc, err := engine.ProbeDial(ctx, p, 3306)
	if err != nil {
		return nil, err
	}
	defer nc.Close()
	h := make([]byte, 4)
	if _, err := io.ReadFull(nc, h); err != nil {
		return nil, err
	}
	size := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if size > 1<<16 {
		return nil, errors.New("mysql: oversized server greeting")
	}
	greeting := make([]byte, size)
	if _, err := io.ReadFull(nc, greeting); err != nil {
		return nil, err
	}
	if size > 0 && greeting[0] == 0xff {
		return nil, errors.New("mysql: the server refused the connection")
	}
	if !greetingOffersTLS(greeting) {
		return nil, engine.ErrNoServerTLS
	}
	req := make([]byte, 4+32)
	req[0], req[3] = 32, 1
	caps := uint32(clientSSL | gomysql.CLIENT_PROTOCOL_41 | gomysql.CLIENT_SECURE_CONNECTION)
	binary.LittleEndian.PutUint32(req[4:], caps)
	binary.LittleEndian.PutUint32(req[8:], maxPacket)
	req[12] = 0x21 // utf8_general_ci
	if _, err := nc.Write(req); err != nil {
		return nil, err
	}
	return engine.ProbeHandshake(nc, p)
}
