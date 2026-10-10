package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/secrets"
	"github.com/DavidGodefroid/locksql/internal/tunnel"
)

// hostKeyAnswerOK accepts "yes", or on a production profile the last 8
// characters of the fingerprint, as typing the profile name approves a
// production statement.
func hostKeyAnswerOK(production bool, fingerprint, answer string) bool {
	answer = strings.TrimSpace(answer)
	if production {
		return len(fingerprint) >= 8 && answer == fingerprint[len(fingerprint)-8:]
	}
	return answer == "yes"
}

// retryKeychainSSHSecret reports whether a failed Open should be retried
// with an asked secret: only when Open was handed the keychain secret
// (used) and the bastion refused it or it did not decrypt the key.
func retryKeychainSSHSecret(err error, used bool) bool {
	return used && errors.Is(err, tunnel.ErrAuth)
}

// openTunnel opens the SSH tunnel of p, asking for its secret by p.SSH's
// credentials mode and for any unknown host key. Open runs under ctx
// itself, with no deadline of the console's: it bounds its own network
// phases and lifts them while the human answers a prompt.
func (st *starter) openTunnel(ctx context.Context, p config.Profile) (*tunnel.Tunnel, error) {
	s := *p.SSH
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("console: ssh: %w", err)
	}
	khPath := tunnel.KnownHostsPath(home)
	// added is the fingerprint the human trusted; it is audited once Open
	// succeeded, as the known_hosts write follows confirm.
	var added string
	confirm := func(host, keyType, fp string) bool {
		st.io.Println(paint.Warn(fmt.Sprintf("The authenticity of %s can't be established.", safeText(host, false))))
		st.io.Println(fmt.Sprintf("%s key fingerprint is %s", safeText(keyType, false), fp))
		prompt := "Trust this key and add it to " + safeText(khPath, false) + "? [yes/N] "
		if p.Production {
			prompt = "Type the last 8 characters of the fingerprint to trust it: "
		}
		ans, ok := st.io.Ask(ctx, prompt, ApprovalTimeout)
		if !ok || !hostKeyAnswerOK(p.Production, fp, ans) {
			return false
		}
		added = fp
		return true
	}
	hk, err := tunnel.KnownHosts(khPath, confirm)
	if err != nil {
		return nil, fmt.Errorf("console: %s", secrets.Sanitize(err))
	}
	algs, err := tunnel.HostKeyAlgorithms(khPath, s)
	if err != nil {
		return nil, fmt.Errorf("console: %s", secrets.Sanitize(err))
	}

	keychainHost := "ssh:" + s.Host
	keychain := s.Credentials == config.CredentialsKeychain
	var fromKeychain, asked []byte
	if keychain {
		if v, legacy, err := secrets.KeychainGet(p.Name, keychainHost, s.Port, config.DefaultSSHPort); err == nil {
			fromKeychain = v
			if legacy == secrets.LegacyMoved {
				st.io.Println(migratedLine(p.Name, keychainHost, s.Port))
			}
		} else if legacy == secrets.LegacyRemoved {
			st.io.Println(removedLine(p.Name, keychainHost, s.Port))
		} else if !errors.Is(err, secrets.ErrNotFound) {
			st.io.Println("OS keychain unavailable, asking instead: " + secrets.Sanitize(err))
			keychain = false
		}
	}
	defer func() { secrets.Wipe(fromKeychain); secrets.Wipe(asked) }()
	// usedKeychain records that Open was handed the keychain secret, so that
	// only a failure with it retries by asking.
	usedKeychain := false
	secret := func(prompt string) ([]byte, error) {
		if fromKeychain != nil {
			usedKeychain = true
			return append([]byte(nil), fromKeychain...), nil
		}
		v, err := st.io.AskSecret(ctx, prompt)
		if err != nil {
			return nil, err
		}
		secrets.Wipe(asked)
		asked = append([]byte(nil), v...)
		return v, nil
	}
	o := tunnel.Options{Profile: s, Home: home, HostKey: hk, HostKeyAlgorithms: algs, Secret: secret,
		AgentSock: os.Getenv("SSH_AUTH_SOCK")}
	t, err := tunnel.Open(ctx, o)
	savePrompt := "Save the SSH secret in the OS keychain? [y/N] "
	if err != nil && retryKeychainSSHSecret(err, usedKeychain) {
		st.io.Println("connecting with the keychain SSH secret failed: " + secrets.Sanitize(err, fromKeychain))
		secrets.Wipe(fromKeychain)
		fromKeychain = nil
		savePrompt = "Replace the SSH secret stored in the OS keychain? [y/N] "
		t, err = tunnel.Open(ctx, o)
	}
	if err != nil {
		return nil, fmt.Errorf("console: %s", secrets.Sanitize(err, fromKeychain, asked))
	}
	if added != "" {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "hostkey-added", SSHHost: s.Host, SSHHostKey: added})
	}
	if keychain && asked != nil {
		st.offerSaveAs(ctx, keychainHost, s.Port, asked, savePrompt)
	}
	st.audit(audit.Record{Event: audit.EventLogin, Decision: "tunnel", SSHHost: s.Host, SSHHostKey: t.HostKey()})
	return t, nil
}

// tunneledSession is a database session reached through an SSH tunnel; it
// closes the tunnel with the session.
type tunneledSession struct {
	engine.Session
	closeTunnel     func() error
	bastion, dbHost string
}

func (s *tunneledSession) Close() error {
	err := s.Session.Close()
	if s.closeTunnel != nil {
		if terr := s.closeTunnel(); err == nil {
			err = terr
		}
	}
	return err
}

// Notices restates the session's transport notices for the two legs: the
// SSH leg is encrypted and verified; the bastion-to-database leg is only
// as safe as the database's own tls mode, unless the database runs on the
// bastion itself.
func (s *tunneledSession) Notices() []string {
	n, ok := s.Session.(engine.Noticer)
	if !ok || len(n.Notices()) == 0 || config.IsLoopback(s.dbHost) {
		return nil
	}
	return []string{fmt.Sprintf("encrypted by SSH to %s; NOT encrypted (or not verified) from the bastion to %s: %s",
		s.bastion, s.dbHost, strings.Join(n.Notices(), "; "))}
}
