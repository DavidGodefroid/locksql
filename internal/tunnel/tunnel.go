// Package tunnel opens the SSH connection to a profile's bastion and dials
// the database server through it. Connections are direct-tcpip channels
// handed to the driver: no local port is ever listened on, so no other
// account on this machine can use the tunnel.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/secrets"
)

// connectTimeout bounds each non-interactive phase of the connection; a
// variable so that tests can shorten it.
var connectTimeout = 15 * time.Second

const (
	defaultKeepalive = 30 * time.Second
	keepaliveMisses  = 3
)

// Options configure Open.
type Options struct {
	Profile config.SSHProfile
	// Home is the console account's home directory, for "~" in Profile.Key.
	Home string
	// HostKey verifies the bastion's key (see KnownHosts).
	HostKey ssh.HostKeyCallback
	// Secret returns a key passphrase or an SSH password; it is called only
	// when one is needed, and Open wipes what it returns.
	Secret func(prompt string) ([]byte, error)
	// AgentSock is the console's SSH_AUTH_SOCK, "" when unset.
	AgentSock string
	// Keepalive is the interval between keepalives; 0 means 30s.
	Keepalive time.Duration
}

// Tunnel is an open SSH connection to a bastion.
type Tunnel struct {
	client  *ssh.Client
	hostKey string
	done    chan struct{}
	once    sync.Once
}

// Open connects and authenticates to the bastion.
func Open(ctx context.Context, o Options) (*Tunnel, error) {
	p := o.Profile
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	// The handshake runs under connectTimeout (or the earlier ctx deadline),
	// except while a human answers a prompt: the host key confirmation or
	// the SSH password. A cancelled ctx closes the connection at any point.
	var nc net.Conn
	// handshaking guards the deadline: the host key callback also runs on
	// every later key re-exchange, when nc must keep no deadline.
	var handshaking atomic.Bool
	handshaking.Store(true)
	arm := func() {
		if !handshaking.Load() {
			return
		}
		dl := time.Now().Add(connectTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(dl) {
			dl = d
		}
		nc.SetDeadline(dl)
	}
	suspend := func() (resume func()) {
		if handshaking.Load() {
			nc.SetDeadline(time.Time{})
		}
		return arm
	}
	var fingerprint string
	verify := func(host string, remote net.Addr, key ssh.PublicKey) error {
		if handshaking.Load() {
			fingerprint = ssh.FingerprintSHA256(key)
		}
		if o.HostKey == nil {
			return errors.New("ssh: no host key verification configured")
		}
		defer suspend()()
		return o.HostKey(host, remote, key)
	}
	auth, cleanup, err := authMethod(o, suspend)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cfg := &ssh.ClientConfig{
		User: p.User, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: verify,
		ClientVersion: "SSH-2.0-locksql",
	}
	d := net.Dialer{Timeout: connectTimeout}
	nc, err = d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: connect to %s: %w", addr, err)
	}
	arm()
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	cc, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		stop()
		nc.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// The client reports a refused authentication only as text.
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("ssh: authentication to %s@%s failed (%s)", p.User, p.Host, p.Auth)
		}
		return nil, fmt.Errorf("ssh: %s: %w", addr, err)
	}
	handshaking.Store(false)
	if !stop() {
		// ctx was cancelled as the handshake ended: nc is closed.
		cc.Close()
		return nil, ctx.Err()
	}
	nc.SetDeadline(time.Time{})
	t := &Tunnel{client: ssh.NewClient(cc, chans, reqs), hostKey: fingerprint, done: make(chan struct{})}
	go func() { t.client.Wait(); t.closeDone() }()
	go t.keepalive(o.Keepalive)
	return t, nil
}

// authMethod builds the single method of p.Auth. suspend lifts the
// handshake deadline while the human types the SSH password; the function
// it returns restores it. cleanup releases what authMethod holds open (the
// agent connection).
func authMethod(o Options, suspend func() (resume func())) (ssh.AuthMethod, func(), error) {
	p := o.Profile
	nop := func() {}
	switch p.Auth {
	case config.SSHAuthKey:
		signer, err := loadKey(o)
		if err != nil {
			return nil, nop, err
		}
		return ssh.PublicKeys(signer), nop, nil
	case config.SSHAuthAgent:
		if o.AgentSock == "" {
			return nil, nop, errors.New("ssh: auth = \"agent\" but SSH_AUTH_SOCK is not set in the console's environment")
		}
		c, err := net.Dial("unix", o.AgentSock)
		if err != nil {
			return nil, nop, fmt.Errorf("ssh: agent at SSH_AUTH_SOCK: %w", err)
		}
		return ssh.PublicKeysCallback(agent.NewClient(c).Signers), func() { c.Close() }, nil
	case config.SSHAuthPassword:
		if o.Secret == nil {
			return nil, nop, errors.New("ssh: no way to ask for the SSH password")
		}
		return ssh.PasswordCallback(func() (string, error) {
			resume := suspend()
			pw, err := o.Secret(fmt.Sprintf("SSH password for %s@%s: ", p.User, p.Host))
			resume()
			if err != nil {
				return "", err
			}
			defer secrets.Wipe(pw)
			return string(pw), nil
		}), nop, nil
	}
	return nil, nop, fmt.Errorf("ssh: unknown auth %q", p.Auth)
}

// loadKey reads the private key, refusing a file others can read (as
// OpenSSH does), and asks for its passphrase when it is encrypted.
func loadKey(o Options) (ssh.Signer, error) {
	path := o.Profile.Key
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home := o.Home
		if home == "" {
			h, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("ssh.key: %w", err)
			}
			home = h
		}
		path = filepath.Join(home, rest)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ssh.key: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("ssh.key: %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ssh.key: %s is readable by others (mode %04o); chmod 600 it", path, st.Mode().Perm())
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ssh.key: %w", err)
	}
	defer secrets.Wipe(pem)
	signer, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		if err != nil {
			return nil, fmt.Errorf("ssh.key: %s: %w", path, err)
		}
		return signer, nil
	}
	if o.Secret == nil {
		return nil, fmt.Errorf("ssh.key: %s is encrypted and no passphrase can be asked", path)
	}
	pass, err := o.Secret("Passphrase for " + path + ": ")
	if err != nil {
		return nil, err
	}
	defer secrets.Wipe(pass)
	signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, pass)
	if err != nil {
		return nil, fmt.Errorf("ssh.key: %s: the passphrase is incorrect or the key is unreadable", path)
	}
	return signer, nil
}

// Dial opens a connection to addr from the bastion. Only TCP is forwarded.
func (t *Tunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("ssh: cannot forward %s connections", network)
	}
	select {
	case <-t.done:
		return nil, errors.New("ssh: the tunnel is closed")
	default:
	}
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := t.client.Dial("tcp", addr)
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("ssh: forward to %s: %w", addr, r.err)
		}
		return r.c, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// HostKey is the SHA256 fingerprint of the bastion's host key.
func (t *Tunnel) HostKey() string { return t.hostKey }

// Done is closed once the tunnel is gone.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Close closes the SSH connection and every forwarded connection.
func (t *Tunnel) Close() error {
	err := t.client.Close()
	t.closeDone()
	return err
}

func (t *Tunnel) closeDone() { t.once.Do(func() { close(t.done) }) }

// keepalive sends keepalive@openssh.com and closes the tunnel after
// keepaliveMisses unanswered ones, so that a dead bastion fails the
// database connections instead of hanging them.
func (t *Tunnel) keepalive(every time.Duration) {
	if every <= 0 {
		every = defaultKeepalive
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	misses := 0
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := t.client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		select {
		case err := <-reply:
			if err != nil {
				misses++
			} else {
				misses = 0
			}
		case <-time.After(every):
			misses++
		case <-t.done:
			return
		}
		if misses >= keepaliveMisses {
			t.Close()
			return
		}
	}
}
