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
// certificate names host (or tls_server_name). "" is prefer, the mode of
// policies approved before the setting existed. tls_cert and tls_key, when
// set, are the client certificate presented to a server that asks for one.
func TLSConfig(p config.Profile) (*tls.Config, error) {
	mode := p.TLS
	if mode == "" {
		mode = config.TLSPrefer
	}
	if mode == config.TLSDisable || strings.HasPrefix(p.Host, "/") {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.TLSCert != "" || p.TLSKey != "" {
		cert, err := ClientCertificate(p.TLSCert, p.TLSKey)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
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
		if p.TLSServerName != "" {
			cfg.ServerName = p.TLSServerName
		}
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

// ClientCertificate loads the client certificate of tls_cert and its key
// from tls_key. The key must be readable by its owner only, as an ssh key.
// Errors name the files, never their content.
func ClientCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("tls_cert and tls_key go together: set both, or neither")
	}
	st, err := os.Stat(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls_key: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return tls.Certificate{}, fmt.Errorf("tls_key: %s is readable by others (mode %04o); chmod 600 it", keyFile, st.Mode().Perm())
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls_cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls_key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil {
		// crypto/tls says which half it could not use, never the key.
		return tls.Certificate{}, fmt.Errorf("tls_cert %s and tls_key %s: %w", certFile, keyFile, err)
	}
	return cert, nil
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
