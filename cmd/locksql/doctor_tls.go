package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// expiryWarning is how long before its end a certificate is reported.
const expiryWarning = 30 * 24 * time.Hour

// tlsChecks checks the TLS files of a network profile (tls_ca, tls_cert,
// tls_key: readable, PEM, not expired, the key private) and, for a server
// reached without ssh, the certificate it presents: its chain against
// tls_ca or the system roots, its name, its expiry. The probe sends no
// secret. In a separated setup the files live in the console account's
// home: one this account cannot read is not checked.
func tlsChecks(d doctorEnv, p config.Profile, sys *sysconf.Config, name string) []check {
	var out []check
	add := func(state, title, detail, fix string) {
		out = append(out, check{state: state, title: name + ": " + title, detail: detail, fix: fix})
	}
	if p.Engine == config.EngineSQLite || strings.HasPrefix(p.Host, "/") {
		return nil
	}
	unreadable := func(err error) bool { return sys != nil && errors.Is(err, fs.ErrPermission) }
	now := time.Now()

	// roots is the pool the server certificate is verified against; nil
	// with caKnown false when tls_ca cannot be read from here.
	var roots *x509.CertPool
	caKnown := true
	if p.TLSCA != "" {
		certs, err := readCerts(d, p.TLSCA)
		switch {
		case unreadable(err):
			caKnown = false
		case err != nil:
			add(checkFail, "tls_ca", err.Error(), "point tls_ca to the PEM file of the server's CA")
			caKnown = false
		default:
			roots = x509.NewCertPool()
			for _, c := range certs {
				roots.AddCert(c)
			}
			state, detail := expiry(certs, now)
			add(state, "tls_ca", fmt.Sprintf("%s: %d certificate(s); %s", p.TLSCA, len(certs), detail), "renew the CA certificate")
		}
	}
	if p.TLSCert != "" {
		certs, err := readCerts(d, p.TLSCert)
		switch {
		case unreadable(err):
		case err != nil:
			add(checkFail, "tls_cert", err.Error(), "point tls_cert to the PEM file of the client certificate")
		default:
			state, detail := expiry(certs[:1], now)
			add(state, "tls_cert", p.TLSCert+": "+detail, "renew the client certificate")
		}
	}
	if p.TLSKey != "" {
		st, err := d.stat(p.TLSKey)
		switch {
		case unreadable(err):
		case err != nil:
			add(checkFail, "tls_key", p.TLSKey+": "+pathErr(err), "check tls_key")
		case st.Mode().Perm()&0o077 != 0:
			add(checkFail, "tls_key", fmt.Sprintf("%s is readable by others (mode %04o)", p.TLSKey, st.Mode().Perm()), "chmod 600 "+p.TLSKey)
		default:
			add(checkOK, "tls_key", p.TLSKey+" is private", "")
		}
	}

	if d.tlsProbe == nil || p.SSH != nil || config.TLSRank(p.TLS) <= config.TLSRank(config.TLSDisable) {
		return out // through a bastion: the console checks the chain when it connects
	}
	if p.TLS == config.TLSPrefer && config.IsLoopback(p.Host) {
		return out
	}
	const title = "server certificate"
	port := p.Port
	if port <= 0 {
		port = 3306
		if p.Engine == config.EnginePostgres {
			port = 5432
		}
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(port))
	chain, err := d.tlsProbe(p)
	if len(chain) == 0 {
		switch {
		case errors.Is(err, engine.ErrNoServerTLS) && config.TLSRank(p.TLS) >= config.TLSRank(config.TLSRequire):
			add(checkFail, title, addr+" does not offer TLS: the console will refuse to connect (tls = \""+p.TLS+"\")", "enable TLS on the server")
		case errors.Is(err, engine.ErrNoServerTLS):
			add(checkWarn, title, addr+" does not offer TLS: the connection is not encrypted", "enable TLS on the server")
		default:
			add(checkWarn, title, fmt.Sprintf("could not check %s from this account: %v", addr, err), "check that this machine reaches the server, or run locksql doctor as the console account")
		}
		return out
	}
	leaf := chain[0]
	state, detail := expiry(chain[:1], now)
	detail = fmt.Sprintf("%s (%s); %s", addr, leaf.Subject.CommonName, detail)
	fixExpiry := "renew the server certificate"
	if state == checkFail {
		add(state, title, detail, fixExpiry)
		return out
	}
	if !caKnown {
		add(state, title, detail+"; chain not checked: tls_ca is not readable from this account", fixExpiry)
		return out
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, chainErr := leaf.Verify(opts)
	host := p.Host
	if p.TLSServerName != "" {
		host = p.TLSServerName
	}
	nameErr := leaf.VerifyHostname(host)
	against := "the system roots"
	if p.TLSCA != "" {
		against = "tls_ca"
	}
	switch {
	case !config.TLSVerifiesChain(p.TLS, p.TLSCA):
		would := "it would not pass verify-full: "
		switch {
		case chainErr != nil:
			would += "its chain does not verify against " + against
		case nameErr != nil:
			would += "it does not name " + host
		default:
			would = "it would pass verify-full"
		}
		add(checkWarn, title, detail+"; not verified (tls = \""+p.TLS+"\"): "+would,
			"set tls = \"verify-full\" (and tls_ca if the server's CA is private)")
	case chainErr != nil:
		add(checkFail, title, detail+"; the chain does not verify against "+against+": the console will refuse to connect",
			"set tls_ca to the CA that signed the server certificate")
	case p.TLS == config.TLSVerifyFull && nameErr != nil:
		add(checkFail, title, detail+"; the certificate does not name "+host+": the console will refuse to connect",
			"set tls_server_name to a name the certificate carries, or tls = \"verify-ca\"")
	default:
		add(state, title, detail+"; verified against "+against, fixExpiry)
	}
	return out
}

// readCerts reads the PEM certificates of path.
func readCerts(d doctorEnv, path string) ([]*x509.Certificate, error) {
	data, err := d.readFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the path is already in the message
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return certs, nil
}

// pathErr is err without the path, which the detail already shows.
func pathErr(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// expiry reports the certificate of certs that ends first: expired is a
// failure, ending within expiryWarning a warning.
func expiry(certs []*x509.Certificate, now time.Time) (state, detail string) {
	first := certs[0]
	for _, c := range certs[1:] {
		if c.NotAfter.Before(first.NotAfter) {
			first = c
		}
	}
	end := first.NotAfter.UTC().Format("2006-01-02")
	left := first.NotAfter.Sub(now)
	switch {
	case left <= 0:
		return checkFail, "expired on " + end
	case now.Before(first.NotBefore):
		return checkFail, "not valid before " + first.NotBefore.UTC().Format("2006-01-02")
	case left < expiryWarning:
		return checkWarn, fmt.Sprintf("expires on %s, in %d days", end, int(left.Hours()/24))
	}
	return checkOK, "valid until " + end
}
