//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// TLSPassword is the password of the TLS test accounts.
const TLSPassword = "tls-test-only"

// tlsServerName is the only name the test server certificate carries: a
// connection to 127.0.0.1 verifies it with tls_server_name.
const tlsServerName = "db.test"

// testPKI is a private CA, a server certificate for tlsServerName and a
// client certificate for certuser, written as PEM files; otherCA is a CA
// that signed none of them.
type testPKI struct {
	dir                                string // server files, readable by the container
	ca, otherCA, clientCert, clientKey string
	caPEM, serverPEM, serverKeyPEM     []byte
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	keyPEM := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	certPEM := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	newCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k := newKey()
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	ca, caKey, caDER := newCA("locksql test CA")
	_, _, otherDER := newCA("locksql other CA")
	leaf := func(cn string, dns []string, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		k := newKey()
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	srvDER, srvKey := leaf(tlsServerName, []string{tlsServerName}, x509.ExtKeyUsageServerAuth)
	cliDER, cliKey := leaf("certuser", nil, x509.ExtKeyUsageClientAuth)

	p := testPKI{caPEM: certPEM(caDER), serverPEM: certPEM(srvDER), serverKeyPEM: keyPEM(srvKey)}
	dir, err := os.MkdirTemp("", "ls-it-tls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// The container's server account reads these through a bind mount.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p.dir = dir
	write := func(dir, name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write(dir, "server.pem", p.serverPEM, 0o644)
	write(dir, "server.key", p.serverKeyPEM, 0o644)
	p.ca = write(dir, "ca.pem", p.caPEM, 0o644)
	own := t.TempDir()
	p.otherCA = write(own, "other-ca.pem", certPEM(otherDER), 0o600)
	p.clientCert = write(own, "client.pem", certPEM(cliDER), 0o600)
	p.clientKey = write(own, "client.key", keyPEM(cliKey), 0o600)
	return p
}

// remoteDial reaches the container under a host name that is not a
// loopback one, as a remote server would be.
func remoteDial(srv Server) engine.DialFunc {
	addr := net.JoinHostPort(srv.Host, fmt.Sprint(srv.Port))
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

// tlsConnect connects p with secret and runs SELECT 1.
func tlsConnect(t *testing.T, p config.Profile, secret string, dial engine.DialFunc) (engine.Session, error) {
	t.Helper()
	e, err := engine.Get(p.Engine)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name == "" {
		p.Name, p.Tier, p.Limits = "tls", config.TierRead, config.Limits{StatementTimeout: 10 * time.Second, MaxRows: 10}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var pw []byte
	if secret != "" {
		pw = []byte(secret)
	}
	s, err := e.Connect(ctx, p, pw, dial)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Run(ctx, "", read("SELECT 1"), 10); err != nil {
		t.Fatalf("SELECT 1: %v", err)
	}
	return s, nil
}

func noNotices(t *testing.T, s engine.Session) {
	t.Helper()
	if n, ok := s.(engine.Noticer); ok && len(n.Notices()) > 0 {
		t.Errorf("notices on a verified connection: %q", n.Notices())
	}
}

// probeLeaf checks that the doctor's probe, which sends no secret, gets the
// server certificate.
func probeLeaf(t *testing.T, p config.Profile) {
	t.Helper()
	e, err := engine.Get(p.Engine)
	if err != nil {
		t.Fatal(err)
	}
	prober, ok := e.(engine.TLSProber)
	if !ok {
		t.Fatalf("engine %s is not a TLSProber", p.Engine)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certs, err := prober.ProbeTLS(ctx, p)
	if err != nil || len(certs) == 0 || certs[0].Subject.CommonName != tlsServerName {
		t.Errorf("probe: %d certificates, err = %v, want the server certificate", len(certs), err)
	}
}

func TestTLS(t *testing.T) {
	if !DockerAvailable() {
		t.Skip("docker is not available")
	}
	pki := newPKI(t)
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) { testMySQLTLS(t, m, pki) })
	}
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) { testPostgresTLS(t, v, pki) })
	}
}

func startMySQLTLS(t *testing.T, m mysqlTarget, pki testPKI) Server {
	env := []string{"MYSQL_ROOT_PASSWORD=" + RootPassword}
	cli := "mysql"
	if m.flavor == engine.FlavorMariaDB {
		env = []string{"MARIADB_ROOT_PASSWORD=" + RootPassword}
		cli = "mariadb"
	}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := client.ConnectWithContext(ctx, fmt.Sprintf("%s:%d", host, port), "root", RootPassword, "", 3*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Execute("SELECT 1")
		return err
	}
	seed := `CREATE USER 'tlsu'@'%' IDENTIFIED BY '` + TLSPassword + `';
CREATE USER 'x509u'@'%' IDENTIFIED BY '` + TLSPassword + `' REQUIRE X509;
`
	return StartVariant(t, "tls", m.image(), 3306, env,
		[]string{"-v", pki.dir + ":/certs:ro"},
		[]string{"--ssl-ca=/certs/ca.pem", "--ssl-cert=/certs/server.pem", "--ssl-key=/certs/server.key"},
		ready, func(s Server) error { return Exec(s, seed, cli, "-uroot", "-p"+RootPassword) })
}

func testMySQLTLS(t *testing.T, m mysqlTarget, pki testPKI) {
	srv := startMySQLTLS(t, m, pki)
	cli := "mysql"
	if m.flavor == engine.FlavorMariaDB {
		cli = "mariadb"
	}
	base := config.Profile{Engine: string(m.flavor), Host: srv.Host, Port: srv.Port, User: "tlsu"}
	with := func(f func(p *config.Profile)) config.Profile { p := base; f(&p); return p }
	mysql8 := m.flavor == engine.FlavorMySQL
	probeLeaf(t, base)

	// An unverified TLS connection to a remote host never answers a request
	// for the password in clear. A MySQL 8 account (caching_sha2_password)
	// whose password the server has not cached needs a full authentication,
	// which is refused; a MariaDB account (mysql_native_password) logs in.
	if err := Exec(srv, "FLUSH PRIVILEGES;", cli, "-uroot", "-p"+RootPassword); err != nil {
		t.Fatal(err)
	}
	remote := with(func(p *config.Profile) { p.Host, p.Port, p.TLS = tlsServerName, 3306, config.TLSRequire })
	_, err := tlsConnect(t, remote, TLSPassword, remoteDial(srv))
	switch {
	case mysql8 && (err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), `tls = "verify-full"`)):
		t.Errorf("require, cold cache: err = %v, want the refusal naming verify-full", err)
	case !mysql8 && err != nil:
		t.Errorf("require on MariaDB: %v", err)
	}

	// verify-full: the certificate names db.test, not 127.0.0.1.
	if _, err := tlsConnect(t, with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSVerifyFull, pki.ca }), TLSPassword, nil); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full on a name the certificate lacks: err = %v", err)
	}
	if _, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSCA, p.TLSServerName = config.TLSVerifyFull, pki.otherCA, tlsServerName
	}), TLSPassword, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full with another CA: err = %v", err)
	}
	// No tls_ca: the system roots do not hold the private CA.
	if _, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSServerName = config.TLSVerifyFull, tlsServerName
	}), TLSPassword, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full without tls_ca: err = %v", err)
	}
	s, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSCA, p.TLSServerName = config.TLSVerifyFull, pki.ca, tlsServerName
	}), TLSPassword, nil)
	if err != nil {
		t.Fatalf("verify-full: %v", err)
	}
	noNotices(t, s)
	if _, err := tlsConnect(t, with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSVerifyCA, pki.ca }), TLSPassword, nil); err != nil {
		t.Errorf("verify-ca: %v", err)
	}

	// The verified login filled MySQL's authentication cache: the unverified
	// connection now logs in by the fast path, through the TLS upgrade made
	// below the driver.
	if mysql8 {
		if _, err := tlsConnect(t, remote, TLSPassword, remoteDial(srv)); err != nil {
			t.Errorf("require, warm cache: %v", err)
		}
	}

	// REQUIRE X509: the client certificate is the way in.
	x509u := with(func(p *config.Profile) {
		p.User, p.TLS, p.TLSCA, p.TLSServerName = "x509u", config.TLSVerifyFull, pki.ca, tlsServerName
	})
	if _, err := tlsConnect(t, x509u, TLSPassword, nil); err == nil {
		t.Error("REQUIRE X509 account logged in without a client certificate")
	}
	x509u.TLSCert, x509u.TLSKey = pki.clientCert, pki.clientKey
	if _, err := tlsConnect(t, x509u, TLSPassword, nil); err != nil {
		t.Errorf("REQUIRE X509 with the client certificate: %v", err)
	}
}

func startPostgresTLS(t *testing.T, version string, pki testPKI) Server {
	env := []string{"POSTGRES_PASSWORD=" + RootPassword, "POSTGRES_DB=app"}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%d user=postgres password=%s dbname=app sslmode=disable",
			host, port, RootPassword))
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return c.Ping(ctx)
	}
	return StartVariant(t, "tls", "postgres:"+version, 5432, env, nil, nil, ready, func(s Server) error {
		const home = "/var/lib/postgresql/"
		for name, data := range map[string][]byte{"ls-ca.pem": pki.caPEM, "ls-server.pem": pki.serverPEM, "ls-server.key": pki.serverKeyPEM} {
			if err := Exec(s, string(data), "sh", "-c", "cat > "+home+name+" && chown postgres "+home+name+" && chmod 600 "+home+name); err != nil {
				return err
			}
		}
		if err := Exec(s, "", "sh", "-c", `sed -i '1i hostssl all certuser all cert' "$PGDATA/pg_hba.conf"`); err != nil {
			return err
		}
		return Exec(s, `ALTER SYSTEM SET ssl_cert_file = '`+home+`ls-server.pem';
ALTER SYSTEM SET ssl_key_file = '`+home+`ls-server.key';
ALTER SYSTEM SET ssl_ca_file = '`+home+`ls-ca.pem';
ALTER SYSTEM SET ssl = on;
CREATE ROLE tlsu LOGIN PASSWORD '`+TLSPassword+`';
CREATE ROLE certuser LOGIN;
SELECT pg_reload_conf();
`, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app")
	})
}

func testPostgresTLS(t *testing.T, version string, pki testPKI) {
	srv := startPostgresTLS(t, version, pki)
	base := config.Profile{Engine: config.EnginePostgres, Host: srv.Host, Port: srv.Port, User: "tlsu", Database: "app"}
	with := func(f func(p *config.Profile)) config.Profile { p := base; f(&p); return p }
	probeLeaf(t, base)

	if _, err := tlsConnect(t, with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSVerifyFull, pki.ca }), TLSPassword, nil); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full on a name the certificate lacks: err = %v", err)
	}
	if _, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSCA, p.TLSServerName = config.TLSVerifyFull, pki.otherCA, tlsServerName
	}), TLSPassword, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full with another CA: err = %v", err)
	}
	// No tls_ca: the system roots do not hold the private CA.
	if _, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSServerName = config.TLSVerifyFull, tlsServerName
	}), TLSPassword, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("verify-full without tls_ca: err = %v", err)
	}
	s, err := tlsConnect(t, with(func(p *config.Profile) {
		p.TLS, p.TLSCA, p.TLSServerName = config.TLSVerifyFull, pki.ca, tlsServerName
	}), TLSPassword, nil)
	if err != nil {
		t.Fatalf("verify-full: %v", err)
	}
	noNotices(t, s)
	if _, err := tlsConnect(t, with(func(p *config.Profile) { p.TLS, p.TLSCA = config.TLSVerifyCA, pki.ca }), TLSPassword, nil); err != nil {
		t.Errorf("verify-ca: %v", err)
	}

	// pg_hba cert: the client certificate (CN certuser) is the way in.
	cert := with(func(p *config.Profile) {
		p.User, p.TLS, p.TLSCA, p.TLSServerName = "certuser", config.TLSVerifyFull, pki.ca, tlsServerName
	})
	if _, err := tlsConnect(t, cert, "", nil); err == nil {
		t.Error("cert account logged in without a client certificate")
	}
	cert.TLSCert, cert.TLSKey = pki.clientCert, pki.clientKey
	if _, err := tlsConnect(t, cert, "", nil); err != nil {
		t.Errorf("cert account with the client certificate: %v", err)
	}
}
