package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

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
	return knownhosts.Normalize(net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
}

// KnownHosts verifies host keys against the known_hosts file at path, as
// OpenSSH with StrictHostKeyChecking=ask: a recorded key must match, an
// unknown host is trusted only on confirm, and is then recorded.
func KnownHosts(path string, confirm Confirm) (ssh.HostKeyCallback, error) {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
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

func appendLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	return nil
}
