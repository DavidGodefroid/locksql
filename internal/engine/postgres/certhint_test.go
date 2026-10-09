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
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// selfSigned is a server certificate no root pool knows.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestConnectHintsOnCertificateFailure checks that a server certificate
// that does not verify, as a private CA after the verify-full default, is
// reported with the way out.
func TestConnectHintsOnCertificateFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cert := selfSigned(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, make([]byte, 8)); err != nil { // SSLRequest
					return
				}
				if _, err := c.Write([]byte("S")); err != nil {
					return
				}
				_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
			}()
		}
	}()
	p := config.Profile{Engine: config.EnginePostgres, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u", TLS: config.TLSVerifyFull}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Engine{}.Connect(ctx, p, []byte("pw"), nil)
	want := `(tls = "verify-full": set tls_ca to the server's CA, or tls = "require" to encrypt without verifying)`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("connect error = %v, want the hint %s", err, want)
	}
}
