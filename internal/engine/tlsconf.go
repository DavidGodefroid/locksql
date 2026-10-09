package engine

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TLSConfig builds the client TLS configuration of a network profile's tls
// mode, as libpq's sslmode: nil for disable and for a Unix socket; prefer and
// require encrypt without verifying, except require with tls_ca, which is
// verify-ca as in libpq; verify-ca checks the chain against
// tls_ca (or the system roots); verify-full checks the chain and that the
// certificate names host. "" is prefer, the mode of policies approved before
// the setting existed.
func TLSConfig(p config.Profile) (*tls.Config, error) {
	mode := p.TLS
	if mode == "" {
		mode = config.TLSPrefer
	}
	if mode == config.TLSDisable || strings.HasPrefix(p.Host, "/") {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if mode == config.TLSRequire && p.TLSCA != "" {
		mode = config.TLSVerifyCA // as libpq: require with a root CA verifies the chain
	}
	switch mode {
	case config.TLSPrefer, config.TLSRequire:
		cfg.InsecureSkipVerify = true // encrypt, do not verify
		return cfg, nil
	case config.TLSVerifyCA, config.TLSVerifyFull:
	default:
		return nil, fmt.Errorf("unknown tls mode %q", mode)
	}
	roots, err := rootPool(p.TLSCA)
	if err != nil {
		return nil, err
	}
	cfg.RootCAs = roots
	if mode == config.TLSVerifyFull {
		cfg.ServerName = p.Host
		return cfg, nil
	}
	// verify-ca: the chain, not the name. crypto/tls has no such mode, so
	// skip its check and verify the chain here.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("tls: the server sent no certificate")
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	return cfg, nil
}

// rootPool is the PEM bundle at path, or the system roots when path is "".
func rootPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return x509.SystemCertPool()
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls_ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls_ca: %s holds no PEM certificate", path)
	}
	return pool, nil
}

// TLSVerifyHint is the way out of a connection refused because the server's
// certificate did not verify, as a private or self-signed one does since
// verify-full became the default of a remote host; "" for any other error.
func TLSVerifyHint(err error, mode string) string {
	var (
		verr *tls.CertificateVerificationError
		uerr x509.UnknownAuthorityError
		herr x509.HostnameError
		ierr x509.CertificateInvalidError
	)
	if !errors.As(err, &verr) && !errors.As(err, &uerr) && !errors.As(err, &herr) && !errors.As(err, &ierr) {
		return ""
	}
	return " (tls = \"" + mode + "\": set tls_ca to the server's CA, or tls = \"require\" to encrypt without verifying)"
}
