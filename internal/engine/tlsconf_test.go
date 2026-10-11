package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestTLSVerifyHint(t *testing.T) {
	_, otherCA := testCA(t, "db.example")
	cfg, err := TLSConfig(config.Profile{Engine: config.EnginePostgres, Host: "db.example", TLS: config.TLSVerifyFull})
	if err != nil {
		t.Fatal(err)
	}
	herr := handshake(t, cfg, otherCA)
	if herr == nil {
		t.Fatal("handshake with an unknown CA succeeded")
	}
	want := ` (tls = "verify-full": set tls_ca to the server's CA, or tls = "require" to encrypt without verifying)`
	if got := TLSVerifyHint(fmt.Errorf("connect: %w", herr), config.TLSVerifyFull); got != want {
		t.Errorf("hint = %q, want %q", got, want)
	}
	for _, err := range []error{x509.HostnameError{}, x509.CertificateInvalidError{}, x509.UnknownAuthorityError{}} {
		if TLSVerifyHint(err, config.TLSVerifyCA) == "" {
			t.Errorf("%T: no hint", err)
		}
	}
	if got := TLSVerifyHint(errors.New("password authentication failed"), config.TLSVerifyFull); got != "" {
		t.Errorf("hint of another error = %q", got)
	}
}

// clientPair writes a client certificate signed by a new CA, and its key,
// to PEM files; caPool holds the CA, for the server to check it.
func clientPair(t *testing.T, keyMode os.FileMode) (certFile, keyFile string, caPool *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "app"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, keyMode); err != nil {
		t.Fatal(err)
	}
	caPool = x509.NewCertPool()
	caPool.AddCert(ca)
	return certFile, keyFile, caPool
}

// handshakeClientAuth is handshake against a server that requires a client
// certificate signed by clients.
func handshakeClientAuth(t *testing.T, cfg *tls.Config, cert tls.Certificate, clients *x509.CertPool) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- c.(*tls.Conn).Handshake()
		c.Close()
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	cerr := tls.Client(nc, cfg).Handshake()
	if serr := <-srvErr; serr != nil {
		return serr
	}
	return cerr
}

func TestTLSConfigClientCertificate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no group or other mode bits on Windows: every file reads as 0666")
	}
	caFile, server := testCA(t, "db.example")
	certFile, keyFile, clients := clientPair(t, 0o600)
	for _, mode := range []string{config.TLSRequire, config.TLSVerifyCA, config.TLSVerifyFull} {
		p := config.Profile{Engine: config.EnginePostgres, Host: "db.example", TLS: mode, TLSCA: caFile, TLSCert: certFile, TLSKey: keyFile}
		cfg, err := TLSConfig(p)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if err := handshakeClientAuth(t, cfg, server, clients); err != nil {
			t.Errorf("%s: handshake with the client certificate: %v", mode, err)
		}
	}
	// Without the certificate the server refuses.
	cfg, err := TLSConfig(config.Profile{Engine: config.EnginePostgres, Host: "db.example", TLS: config.TLSVerifyFull, TLSCA: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := handshakeClientAuth(t, cfg, server, clients); err == nil {
		t.Error("handshake without a client certificate succeeded")
	}
}

func TestTLSConfigClientKeyChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no group or other mode bits on Windows: every file reads as 0666")
	}
	caFile, _ := testCA(t, "db.example")
	certFile, keyFile, _ := clientPair(t, 0o640)
	p := config.Profile{Engine: config.EngineMySQL, Host: "db.example", TLS: config.TLSVerifyFull, TLSCA: caFile, TLSCert: certFile, TLSKey: keyFile}
	if _, err := TLSConfig(p); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("group-readable tls_key: err = %v", err)
	}
	p.TLSKey = filepath.Join(t.TempDir(), "missing.key")
	if _, err := TLSConfig(p); err == nil || !strings.Contains(err.Error(), "tls_key") {
		t.Errorf("missing tls_key: err = %v", err)
	}
	_, otherKey, _ := clientPair(t, 0o600)
	p.TLSKey = otherKey
	if _, err := TLSConfig(p); err == nil || !strings.Contains(err.Error(), "tls_cert") {
		t.Errorf("mismatched pair: err = %v", err)
	}
}

func TestTLSConfigServerName(t *testing.T) {
	caFile, good := testCA(t, "db.example")
	p := config.Profile{Engine: config.EnginePostgres, Host: "10.1.2.3", TLS: config.TLSVerifyFull, TLSCA: caFile}
	cfg, err := TLSConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if handshake(t, cfg, good) == nil {
		t.Error("verify-full accepted a certificate that does not name host")
	}
	p.TLSServerName = "db.example"
	if cfg, err = TLSConfig(p); err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, cfg, good); err != nil {
		t.Errorf("verify-full with tls_server_name: %v", err)
	}
	p.TLSServerName = "other.example"
	if cfg, err = TLSConfig(p); err != nil {
		t.Fatal(err)
	}
	if handshake(t, cfg, good) == nil {
		t.Error("verify-full accepted a certificate that does not name tls_server_name")
	}
}
