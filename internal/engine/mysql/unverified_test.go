package mysql

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// tlsServer plays a MySQL server, or an attacker on the path, that offers
// TLS with a certificate of its own. After the handshake response it sends
// reply (an auth switch or an auth-more-data packet), or an OK packet when
// reply is nil. It records every byte it reads after TLS, in clear.
type tlsServer struct {
	ln      net.Listener
	cert    tls.Certificate
	plugin  string
	reply   []byte
	mu      sync.Mutex
	got     bytes.Buffer
	sslReq  []byte // the SSL request packet, as received
	resp    []byte // the handshake response packet, as received (decrypted)
	tlsDone bool
	done    sync.WaitGroup
}

func (f *tlsServer) serve() {
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
			greeting := handshakeWith(f.plugin)
			greeting[26] |= 0x08 // CLIENT_SSL
			if _, err := c.Write(packet(0, greeting)); err != nil {
				return
			}
			h := make([]byte, 4)
			if _, err := io.ReadFull(c, h); err != nil {
				return
			}
			req := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			f.mu.Lock()
			f.sslReq = append(h, req...)
			f.mu.Unlock()
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			f.mu.Lock()
			f.tlsDone = true
			f.mu.Unlock()
			if _, err := io.ReadFull(tc, h); err != nil {
				return
			}
			resp := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
			if _, err := io.ReadFull(tc, resp); err != nil {
				return
			}
			f.mu.Lock()
			f.resp = append(append([]byte{}, h...), resp...)
			f.got.Write(resp)
			f.mu.Unlock()
			if f.reply == nil {
				_, _ = tc.Write(packet(3, []byte{0, 0, 0, 2, 0, 0, 0}))
				_, _ = io.Copy(io.Discard, tc)
				return
			}
			if _, err := tc.Write(packet(3, f.reply)); err != nil {
				return
			}
			rest, _ := io.ReadAll(tc)
			f.mu.Lock()
			f.got.Write(rest)
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

// TestRefusesPasswordRequestsOnUnverifiedTLS checks that, below verify-ca,
// an attacker who terminates TLS with a certificate of its own cannot get
// the password: by an auth switch to mysql_clear_password or
// sha256_password, or by a caching_sha2_password full authentication, all
// of which go-mysql answers in clear over TLS.
func TestRefusesPasswordRequestsOnUnverifiedTLS(t *testing.T) {
	const secret = "S3cr3t-pa55word"
	replies := map[string][]byte{
		"clear switch":      append([]byte{0xfe}, []byte("mysql_clear_password\x00")...),
		"sha256 switch":     append([]byte{0xfe}, []byte("sha256_password\x00"+salt+"\x00")...),
		"caching full auth": {0x01, 0x04},
	}
	for _, mode := range []string{config.TLSPrefer, config.TLSRequire} {
		for name, reply := range replies {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			f := &tlsServer{ln: ln, cert: selfSigned(t), plugin: "caching_sha2_password", reply: reply}
			go f.serve()
			p := config.Profile{Name: "t", Engine: config.EngineMySQL, Host: "db.example", Port: 3306, User: "u",
				TLS: mode, Tier: config.TierRead, Limits: config.DefaultLimits(false)}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err = Engine{}.Connect(ctx, p, []byte(secret), remoteDial(ln.Addr().String()))
			cancel()
			ln.Close()
			f.done.Wait()
			if err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), `tls = "verify-full"`) {
				t.Errorf("%s, %s: connect error = %v, want the refusal naming the remedy", mode, name, err)
			}
			if !f.tlsDone {
				t.Errorf("%s, %s: the connection did not use TLS", mode, name)
			}
			if bytes.Contains(f.got.Bytes(), []byte(secret)) {
				t.Errorf("%s, %s: the password reached the server", mode, name)
			}
		}
	}
}

// TestUnverifiedTLSHandshake checks the upgrade made below the driver: the
// SSL request carries CLIENT_SSL and the handshake response follows it in
// TLS with the next sequence number, and a login that needs no clear
// password still works.
func TestUnverifiedTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &tlsServer{ln: ln, cert: selfSigned(t), plugin: "mysql_native_password"}
	go f.serve()
	defer func() { ln.Close(); f.done.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	c, err := dial(ctx, "db.example:3306", "u", "pw", "", 0, tlsCfg, config.TLSRequire, remoteDial(ln.Addr().String()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sslReq) != 4+32 || f.sslReq[3] != 1 || f.sslReq[5]&0x08 == 0 {
		t.Errorf("SSL request = %x, want 32 bytes, sequence 1, CLIENT_SSL", f.sslReq)
	}
	if len(f.resp) < 4+32 || f.resp[3] != 2 || f.resp[5]&0x08 == 0 {
		t.Errorf("handshake response header = %x, want sequence 2 with CLIENT_SSL", f.resp[:min(len(f.resp), 8)])
	}
	if !bytes.Equal(f.resp[4:4+32], f.sslReq[4:]) {
		t.Errorf("the handshake response does not start with the SSL request")
	}
}
