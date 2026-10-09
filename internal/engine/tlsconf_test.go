package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// testCA writes a CA to a PEM file and returns it with a server
// certificate for name, signed by the CA.
func testCA(t *testing.T, name string) (caFile string, server tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

// handshake runs one TLS handshake of cfg against a server presenting cert.
func handshake(t *testing.T, cfg *tls.Config, cert tls.Certificate) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	return tls.Client(nc, cfg).Handshake()
}

func TestTLSConfigModes(t *testing.T) {
	caFile, good := testCA(t, "db.example")
	_, otherCA := testCA(t, "db.example") // same name, unknown CA
	// The name check of verify-full uses a profile host ("other.name") that
	// the good certificate does not carry.
	p := func(mode, host, ca string) config.Profile {
		return config.Profile{Engine: config.EnginePostgres, Host: host, TLS: mode, TLSCA: ca}
	}
	cases := []struct {
		name string
		prof config.Profile
		cert tls.Certificate
		ok   bool
	}{
		{"prefer any cert", p(config.TLSPrefer, "db.example", ""), otherCA, true},
		{"require any cert", p(config.TLSRequire, "db.example", ""), otherCA, true},
		{"require with ca good, wrong name", p(config.TLSRequire, "other.name", caFile), good, true},
		{"require with ca unknown CA", p(config.TLSRequire, "db.example", caFile), otherCA, false},
		{"verify-ca good", p(config.TLSVerifyCA, "other.name", caFile), good, true},
		{"verify-ca unknown CA", p(config.TLSVerifyCA, "db.example", caFile), otherCA, false},
		{"verify-full good", p(config.TLSVerifyFull, "db.example", caFile), good, true},
		{"verify-full wrong name", p(config.TLSVerifyFull, "other.name", caFile), good, false},
		{"verify-full unknown CA", p(config.TLSVerifyFull, "db.example", caFile), otherCA, false},
	}
	for _, c := range cases {
		cfg, err := TLSConfig(c.prof)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := handshake(t, cfg, c.cert); (err == nil) != c.ok {
			t.Errorf("%s: handshake err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTLSConfigEmptyModeIsPrefer(t *testing.T) {
	cfg, err := TLSConfig(config.Profile{Engine: config.EngineMySQL, Host: "db"})
	if err != nil || cfg == nil || !cfg.InsecureSkipVerify {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestTLSConfigDisableAndSocket(t *testing.T) {
	for _, prof := range []config.Profile{
		{Engine: config.EngineMySQL, Host: "db", TLS: config.TLSDisable},
		{Engine: config.EngineMySQL, Host: "/run/mysqld.sock", TLS: config.TLSPrefer},
	} {
		if cfg, err := TLSConfig(prof); cfg != nil || err != nil {
			t.Errorf("%+v: cfg = %v, err = %v", prof, cfg, err)
		}
	}
}

func TestTLSConfigBadCA(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := TLSConfig(config.Profile{Host: "db", TLS: config.TLSVerifyFull, TLSCA: bad}); err == nil {
		t.Error("garbage tls_ca accepted")
	}
	if _, err := TLSConfig(config.Profile{Host: "db", TLS: config.TLSVerifyFull, TLSCA: "/nonexistent.pem"}); err == nil {
		t.Error("missing tls_ca accepted")
	}
}
