package mysql

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

func packet(seq byte, payload []byte) []byte {
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, uint32(len(payload)))
	h[3] = seq
	return append(h, payload...)
}

func handshakeV10() []byte {
	caps := uint32(gomysqlProtocol41 | gomysqlSecureConn | gomysqlPluginAuth | 1)
	var p bytes.Buffer
	p.WriteByte(10)
	p.WriteString("8.4.0-fake\x00")
	p.Write([]byte{1, 0, 0, 0})
	p.WriteString("abcdefgh")
	p.WriteByte(0)
	p.Write([]byte{byte(caps), byte(caps >> 8)})
	p.WriteByte(0x21)
	p.Write([]byte{2, 0})
	p.Write([]byte{byte(caps >> 16), byte(caps >> 24)})
	p.WriteByte(21)
	p.Write(make([]byte, 10))
	p.WriteString("ijklmnopqrst\x00")
	p.WriteString("mysql_native_password\x00")
	return p.Bytes()
}

const (
	gomysqlProtocol41 = 0x00000200
	gomysqlSecureConn = 0x00008000
	gomysqlPluginAuth = 0x00080000
)

func readPacket(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(append(h[:3:3], 0)))
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

// clearTextSwitch is an auth switch to mysql_clear_password, which makes
// the client send the password as is.
var clearTextSwitch = append([]byte{0xfe}, []byte("mysql_clear_password\x00")...)

// fakeServer is a local MySQL-protocol stub that offers TLS when cert is
// set, accepts the client's handshake response, then asks for an auth
// switch to mysql_clear_password. It records every byte the client sends
// after TLS, in clear, and whether TLS was negotiated.
type fakeServer struct {
	ln      net.Listener
	cert    *tls.Certificate
	mu      sync.Mutex
	got     bytes.Buffer
	tlsDone bool
	done    sync.WaitGroup
}

func (f *fakeServer) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.done.Add(1)
		go func() {
			defer f.done.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			greeting := handshakeV10()
			if f.cert != nil {
				greeting[26] |= 0x08 // CLIENT_SSL
			}
			if _, err := c.Write(packet(0, greeting)); err != nil {
				return
			}
			var conn net.Conn = c
			seq := byte(2)
			if f.cert != nil {
				if _, err := readPacket(c); err != nil { // the SSL request
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*f.cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				f.mu.Lock()
				f.tlsDone = true
				f.mu.Unlock()
				conn, seq = tc, 3
			}
			resp, err := readPacket(conn)
			f.mu.Lock()
			f.got.Write(resp)
			f.mu.Unlock()
			if err != nil {
				return
			}
			if _, err := conn.Write(packet(seq, clearTextSwitch)); err != nil {
				return
			}
			pw, _ := readPacket(conn) // the answer, then hang up
			f.mu.Lock()
			f.got.Write(pw)
			f.mu.Unlock()
		}()
	}
}

// remoteDial routes the profile's remote host to a local listener, so that
// the host the engine decides on is not a loopback one.
func remoteDial(addr string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}
