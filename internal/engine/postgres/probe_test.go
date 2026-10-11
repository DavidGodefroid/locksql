package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// probeServer answers the SSL request with answer ('S' or 'N') and, on
// 'S', makes the TLS handshake; it records whether anything followed.
func probeServer(t *testing.T, answer byte, cert tls.Certificate) (port int, after chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	after = make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			after <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		req := make([]byte, 8)
		if _, err := io.ReadFull(c, req); err != nil {
			after <- nil
			return
		}
		if _, err := c.Write([]byte{answer}); err != nil || answer != 'S' {
			after <- nil
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			after <- nil
			return
		}
		rest, _ := io.ReadAll(tc)
		after <- rest
	}()
	return ln.Addr().(*net.TCPAddr).Port, after
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "db.example"},
		DNSNames: []string{"db.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestProbeTLS(t *testing.T) {
	cert := testCert(t)
	port, after := probeServer(t, 'S', cert)
	p := config.Profile{Engine: config.EnginePostgres, Host: "127.0.0.1", Port: port, User: "u", TLS: config.TLSVerifyFull}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var prober engine.TLSProber = Engine{}
	certs, err := prober.ProbeTLS(ctx, p)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(certs) != 1 || string(certs[0].Raw) != string(cert.Certificate[0]) {
		t.Fatalf("probe returned %d certificates, want the server's", len(certs))
	}
	if rest := <-after; len(rest) != 0 {
		t.Errorf("the probe sent %q after the TLS handshake, want nothing (no startup message)", rest)
	}
}

func TestProbeTLSNoServerTLS(t *testing.T) {
	port, _ := probeServer(t, 'N', testCert(t))
	p := config.Profile{Engine: config.EnginePostgres, Host: "127.0.0.1", Port: port, TLS: config.TLSRequire}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (Engine{}).ProbeTLS(ctx, p); err != engine.ErrNoServerTLS {
		t.Errorf("probe of a server without TLS: err = %v, want ErrNoServerTLS", err)
	}
}
