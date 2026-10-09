package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// ErrHostKeyChanged is a bastion whose key differs from the one recorded in
// known_hosts: possibly an attacker in the middle. There is no override;
// the human edits known_hosts after checking the new key.
var ErrHostKeyChanged = errors.New("ssh: REMOTE HOST IDENTIFICATION HAS CHANGED")

// Confirm is asked whether to trust a host key seen for the first time.
type Confirm func(host, keyType, fingerprint string) bool

// KnownHostsPath is the console account's known_hosts.
func KnownHostsPath(home string) string { return filepath.Join(home, ".ssh", "known_hosts") }

func knownAddr(p config.SSHProfile) string {
	return knownhosts.Normalize(net.JoinHostPort(strings.ToLower(p.Host), strconv.Itoa(p.Port)))
}

// KnownHosts verifies host keys against the known_hosts file at path, as
// OpenSSH with StrictHostKeyChecking=ask: a recorded key must match, an
// unknown host is trusted only on confirm, and is then recorded.
func KnownHosts(path string, confirm Confirm) (ssh.HostKeyCallback, error) {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		host = strings.ToLower(host) // host names are case-insensitive, as in OpenSSH
		check, err := load(path)
		if err != nil {
			return err
		}
		err = check(host, remote, key)
		var ke *knownhosts.KeyError
		var re *knownhosts.RevokedError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &re):
			return fmt.Errorf("ssh: the host key of %s is revoked in %s", host, path)
		case errors.As(err, &ke) && len(ke.Want) > 0:
			return fmt.Errorf("%w: %s now presents %s, %s:%d records %s",
				ErrHostKeyChanged, host, ssh.FingerprintSHA256(key), ke.Want[0].Filename, ke.Want[0].Line,
				ssh.FingerprintSHA256(ke.Want[0].Key))
		case errors.As(err, &ke):
			if confirm == nil || !confirm(host, key.Type(), ssh.FingerprintSHA256(key)) {
				return fmt.Errorf("ssh: host key of %s not trusted", host)
			}
			return appendLine(path, knownhosts.Line([]string{knownhosts.Normalize(host)}, key))
		default:
			return err
		}
	}, nil
}

// load parses path; a missing file is an empty one.
func load(path string) (ssh.HostKeyCallback, error) {
	cb, err := knownhosts.New(path)
	if errors.Is(err, os.ErrNotExist) {
		return func(string, net.Addr, ssh.PublicKey) error {
			return &knownhosts.KeyError{}
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ssh: %s: %w", path, err)
	}
	return cb, nil
}

// HostKeyAlgorithms lists the host key algorithms to offer the bastion of p:
// those of the key types recorded for it in the known_hosts file at path, so
// that a bastion with several keys is not negotiated onto one that is not
// recorded (which would look like a changed key). With nothing recorded it
// lists the plain key algorithms, Ed25519 first and no certificates.
func HostKeyAlgorithms(path string, p config.SSHProfile) ([]string, error) {
	check, err := load(path)
	if err != nil {
		return nil, err
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	// The throwaway key never matches, so a recorded host answers with a
	// KeyError listing what is recorded. The remote address is a
	// documentation address that no entry should name.
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: p.Port}
	var ke *knownhosts.KeyError
	if err := check(net.JoinHostPort(strings.ToLower(p.Host), strconv.Itoa(p.Port)), remote, probe); !errors.As(err, &ke) {
		return nil, fmt.Errorf("ssh: %s: %w", path, err)
	}
	recorded := map[string]bool{}
	for _, w := range ke.Want {
		recorded[w.Key.Type()] = true
	}
	var algs []string
	for _, group := range hostKeyAlgorithmOrder {
		if recorded[group.keyType] {
			algs = append(algs, group.algorithms...)
		}
	}
	if len(algs) == 0 {
		for _, group := range hostKeyAlgorithmOrder {
			algs = append(algs, group.algorithms...)
		}
	}
	return algs, nil
}

// hostKeyAlgorithmOrder maps a key type to the algorithms that sign with it,
// in order of preference.
var hostKeyAlgorithmOrder = []struct {
	keyType    string
	algorithms []string
}{
	{ssh.KeyAlgoED25519, []string{ssh.KeyAlgoED25519}},
	{ssh.KeyAlgoSKED25519, []string{ssh.KeyAlgoSKED25519}},
	{ssh.KeyAlgoECDSA256, []string{ssh.KeyAlgoECDSA256}},
	{ssh.KeyAlgoECDSA384, []string{ssh.KeyAlgoECDSA384}},
	{ssh.KeyAlgoECDSA521, []string{ssh.KeyAlgoECDSA521}},
	{ssh.KeyAlgoSKECDSA256, []string{ssh.KeyAlgoSKECDSA256}},
	{ssh.KeyAlgoRSA, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
}

func appendLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer f.Close()
	// A hand-edited file may lack its final newline; do not glue to it.
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	return nil
}
