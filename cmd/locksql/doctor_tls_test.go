package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// doctorCA is a CA and a function issuing leaves it signs.
type doctorCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newDoctorCA(t *testing.T, notAfter time.Time) doctorCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "doctor CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return doctorCA{c, k}
}

func (ca doctorCA) leaf(t *testing.T, name string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func writePEM(t *testing.T, dir, name string, mode os.FileMode, certs ...*x509.Certificate) string {
	t.Helper()
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if len(certs) == 0 {
		b = []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func tlsDoctor(probe func(config.Profile) ([]*x509.Certificate, error)) doctorEnv {
	d := fakeDoctor(nil)
	d.stat = os.Stat
	d.readFile = os.ReadFile
	d.tlsProbe = probe
	return d
}

func TestDoctorTLSFiles(t *testing.T) {
	dir := t.TempDir()
	month := time.Now().Add(30 * 24 * time.Hour)
	ca := newDoctorCA(t, time.Now().Add(10*24*time.Hour)) // expires soon
	caFile := writePEM(t, dir, "ca.pem", 0o644, ca.cert)
	expired := ca.leaf(t, "app", time.Now().Add(-time.Hour))
	certFile := writePEM(t, dir, "client.pem", 0o644, expired)
	keyFile := writePEM(t, dir, "client.key", 0o644)
	p := config.Profile{Name: "p", Engine: config.EnginePostgres, Host: "db.example", TLS: config.TLSVerifyFull,
		TLSCA: caFile, TLSCert: certFile, TLSKey: keyFile, Credentials: config.CredentialsAsk}
	checks := profileChecks(tlsDoctor(nil), p, nil, t.TempDir())
	if !hasCheck(checks, checkWarn, "tls_ca") {
		t.Errorf("a CA expiring in 10 days is not a warning: %+v", findCheck(checks, "tls_ca"))
	}
	if !hasCheck(checks, checkFail, "tls_cert") {
		t.Errorf("an expired client certificate is not a failure: %+v", findCheck(checks, "tls_cert"))
	}
	if !hasCheck(checks, checkFail, "tls_key") {
		t.Errorf("a world-readable key is not a failure: %+v", findCheck(checks, "tls_key"))
	}

	good := newDoctorCA(t, month.Add(365*24*time.Hour))
	p.TLSCA = writePEM(t, dir, "good-ca.pem", 0o644, good.cert)
	p.TLSCert = writePEM(t, dir, "good.pem", 0o644, good.leaf(t, "app", month.Add(24*time.Hour)))
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	checks = profileChecks(tlsDoctor(nil), p, nil, t.TempDir())
	for _, title := range []string{"tls_ca", "tls_cert", "tls_key"} {
		if !hasCheck(checks, checkOK, title) {
			t.Errorf("%s: %+v, want ok", title, findCheck(checks, title))
		}
	}

	p.TLSCA = writePEM(t, dir, "garbage.pem", 0o644)
	if !hasCheck(profileChecks(tlsDoctor(nil), p, nil, t.TempDir()), checkFail, "tls_ca") {
		t.Error("a tls_ca without certificates is not a failure")
	}
}

// In a separated setup the files live in the console account's home: an
// unreadable file is not a failure of the agent's account.
func TestDoctorTLSFilesSeparated(t *testing.T) {
	d := fakeDoctor(separatedSys())
	d.readFile = func(string) ([]byte, error) { return nil, fs.ErrPermission }
	d.stat = func(string) (os.FileInfo, error) { return nil, fs.ErrPermission }
	p := config.Profile{Name: "p", Engine: config.EnginePostgres, Host: "db.example", TLS: config.TLSVerifyFull,
		TLSCA: "/home/locksql/ca.pem", TLSCert: "/home/locksql/c.pem", TLSKey: "/home/locksql/c.key", Credentials: config.CredentialsAsk}
	for _, c := range profileChecks(d, p, separatedSys(), t.TempDir()) {
		if c.state == checkFail {
			t.Errorf("unexpected failure %+v", c)
		}
	}
}

func TestDoctorTLSServerCertificate(t *testing.T) {
	dir := t.TempDir()
	year := time.Now().Add(365 * 24 * time.Hour)
	ca := newDoctorCA(t, year)
	caFile := writePEM(t, dir, "ca.pem", 0o644, ca.cert)
	other := newDoctorCA(t, year)
	otherFile := writePEM(t, dir, "other.pem", 0o644, other.cert)
	leaf := ca.leaf(t, "db.example", year)
	soon := ca.leaf(t, "db.example", time.Now().Add(5*24*time.Hour))
	probe := func(chain ...*x509.Certificate) func(config.Profile) ([]*x509.Certificate, error) {
		return func(config.Profile) ([]*x509.Certificate, error) { return chain, nil }
	}
	base := config.Profile{Name: "p", Engine: config.EngineMySQL, Host: "db.example", TLS: config.TLSVerifyFull,
		TLSCA: caFile, Credentials: config.CredentialsAsk}
	with := func(f func(p *config.Profile)) config.Profile { p := base; f(&p); return p }
	cases := []struct {
		name  string
		prof  config.Profile
		probe func(config.Profile) ([]*x509.Certificate, error)
		want  string
	}{
		{"verified", base, probe(leaf), checkOK},
		{"expires soon", base, probe(soon), checkWarn},
		{"unknown CA", with(func(p *config.Profile) { p.TLSCA = otherFile }), probe(leaf), checkFail},
		{"name mismatch", with(func(p *config.Profile) { p.Host = "10.0.0.5" }), probe(leaf), checkFail},
		{"server name", with(func(p *config.Profile) { p.Host, p.TLSServerName = "10.0.0.5", "db.example" }), probe(leaf), checkOK},
		{"verify-ca ignores the name", with(func(p *config.Profile) { p.Host, p.TLS = "10.0.0.5", config.TLSVerifyCA }), probe(leaf), checkOK},
		{"no TLS on require", with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSRequire, "" }),
			func(config.Profile) ([]*x509.Certificate, error) { return nil, engine.ErrNoServerTLS }, checkFail},
		{"unreachable", base, func(config.Profile) ([]*x509.Certificate, error) { return nil, errors.New("connection refused") }, checkWarn},
		{"require would verify", with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSRequire, "" }),
			probe(leaf), checkWarn},
	}
	for _, c := range cases {
		checks := profileChecks(tlsDoctor(c.probe), c.prof, nil, t.TempDir())
		got := findCheck(checks, "server certificate")
		if got == nil || got.state != c.want {
			t.Errorf("%s: server certificate check = %+v, want %s", c.name, got, c.want)
		}
	}

	// Through an ssh bastion the doctor cannot reach the server: no probe.
	called := false
	p := with(func(p *config.Profile) {
		p.SSH = &config.SSHProfile{Host: "bastion", Port: 22, User: "u", Auth: config.SSHAuthAgent, Credentials: config.CredentialsAsk}
	})
	checks := profileChecks(tlsDoctor(func(config.Profile) ([]*x509.Certificate, error) { called = true; return nil, nil }), p, nil, t.TempDir())
	if called || findCheck(checks, "server certificate") != nil {
		t.Error("the doctor probed a server behind an ssh bastion")
	}
}
