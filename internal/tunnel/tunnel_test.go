package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func sshProfile(s *testServer, auth, key string) config.SSHProfile {
	host, port, _ := net.SplitHostPort(s.addr)
	p, _ := strconv.Atoi(port)
	return config.SSHProfile{Host: host, Port: p, User: "deploy", Auth: auth, Key: key, Credentials: config.CredentialsAsk}
}

// writeKey writes an ed25519 key, encrypted when passphrase is not empty,
// and returns its path and public key.
func writeKey(t *testing.T, dir, passphrase string, mode os.FileMode) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var blk *pem.Block
	var err error
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), mode); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return path, sp
}

func acceptKey(want ssh.PublicKey) *ssh.ServerConfig {
	return &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), want.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("no")
	}}
}

func roundTrip(t *testing.T, tun *Tunnel, target string) {
	t.Helper()
	c, err := tun.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestKeyAuth(t *testing.T) {
	home := t.TempDir()
	path, pub := writeKey(t, home, "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s),
		Secret: func(string) ([]byte, error) { t.Fatal("asked a secret for an unencrypted key"); return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	roundTrip(t, tun, echoServer(t))
	if !strings.HasPrefix(tun.HostKey(), "SHA256:") {
		t.Errorf("HostKey = %q", tun.HostKey())
	}
}

func TestEncryptedKeyAsksPassphrase(t *testing.T) {
	home := t.TempDir()
	path, pub := writeKey(t, home, "open sesame", 0o600)
	s := newTestServer(t, acceptKey(pub))
	var prompt string
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s),
		Secret: func(p string) ([]byte, error) { prompt = p; return []byte("open sesame"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	if !strings.Contains(prompt, "Passphrase for "+path) {
		t.Errorf("prompt = %q", prompt)
	}
	_, err = Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s),
		Secret: func(string) ([]byte, error) { return []byte("wrong"), nil }})
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("wrong passphrase: err = %v", err)
	}
}

func TestKeyFileTooOpen(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o644)
	s := newTestServer(t, acceptKey(pub))
	_, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s)})
	if err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("err = %v", err)
	}
}

func TestTildeKeyPath(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	_, pub := writeKey(t, filepath.Join(home, ".ssh"), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, "~/.ssh/id_ed25519"), Home: home, HostKey: trust(s)})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
}

func TestPasswordAuth(t *testing.T) {
	s := newTestServer(t, &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "hunter2" {
			return nil, nil
		}
		return nil, errors.New("no")
	}})
	secret := []byte("hunter2")
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthPassword, ""), HostKey: trust(s),
		Secret: func(p string) ([]byte, error) {
			if !strings.Contains(p, "SSH password for deploy@") {
				t.Errorf("prompt = %q", p)
			}
			return secret, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	if string(secret) == "hunter2" {
		t.Error("secret not wiped")
	}
}

func TestAgentAuth(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{PrivateKey: priv})
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()
	signers, _ := kr.Signers()
	s := newTestServer(t, acceptKey(signers[0].PublicKey()))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthAgent, ""), HostKey: trust(s), AgentSock: sock})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	_, err = Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthAgent, ""), HostKey: trust(s)})
	if err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("no agent: err = %v", err)
	}
}

func TestWrongHostKeyRefused(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	other := newTestServer(t, acceptKey(pub))
	_, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(other)})
	if err == nil {
		t.Error("connected with a host key that does not match")
	}
}

func TestDialRefusesUnix(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s)})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if _, err := tun.Dial(context.Background(), "unix", "/run/x.sock"); err == nil {
		t.Error("unix dial accepted")
	}
}

func TestKeepaliveClosesDeadTunnel(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s), Keepalive: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.dropReqs = true
	s.mu.Unlock()
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel still open after missed keepalives")
	}
	if _, err := tun.Dial(context.Background(), "tcp", echoServer(t)); err == nil {
		t.Error("dial on a closed tunnel succeeded")
	}
}

// shortHandshake lowers the handshake timeout for one test.
func shortHandshake(t *testing.T, d time.Duration) {
	t.Helper()
	old := connectTimeout
	connectTimeout = d
	t.Cleanup(func() { connectTimeout = old })
}

func TestSlowPasswordAnswerConnects(t *testing.T) {
	shortHandshake(t, 200*time.Millisecond)
	s := newTestServer(t, &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "hunter2" {
			return nil, nil
		}
		return nil, errors.New("no")
	}})
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthPassword, ""), HostKey: trust(s),
		Secret: func(string) ([]byte, error) { time.Sleep(600 * time.Millisecond); return []byte("hunter2"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	roundTrip(t, tun, echoServer(t))
}

func TestSlowHostKeyAnswerConnects(t *testing.T) {
	shortHandshake(t, 200*time.Millisecond)
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	check := trust(s)
	slow := func(host string, remote net.Addr, key ssh.PublicKey) error {
		time.Sleep(600 * time.Millisecond)
		return check(host, remote, key)
	}
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: slow})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	roundTrip(t, tun, echoServer(t))
}

func TestCancelStopsHandshake(t *testing.T) {
	// A server that accepts and never speaks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err = Open(ctx, Options{Profile: config.SSHProfile{Host: host, Port: p, User: "deploy", Auth: config.SSHAuthAgent},
		AgentSock: agentSock(t), HostKey: ssh.InsecureIgnoreHostKey()})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Open returned after %v", d)
	}
}

// agentSock serves an empty agent keyring and returns its socket path.
func agentSock(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	kr := agent.NewKeyring()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()
	return sock
}

func TestAuthFailuresAreErrAuth(t *testing.T) {
	s := newTestServer(t, &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, errors.New("no")
	}})
	_, err := Open(t.Context(), Options{Profile: sshProfile(s, config.SSHAuthPassword, ""), HostKey: trust(s),
		Secret: func(string) ([]byte, error) { return []byte("wrong"), nil }})
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "authentication to deploy@") {
		t.Errorf("refused password: err = %v", err)
	}

	path, pub := writeKey(t, t.TempDir(), "open sesame", 0o600)
	ks := newTestServer(t, acceptKey(pub))
	_, err = Open(t.Context(), Options{Profile: sshProfile(ks, config.SSHAuthKey, path), HostKey: trust(ks),
		Secret: func(string) ([]byte, error) { return []byte("wrong"), nil }})
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "passphrase is incorrect") {
		t.Errorf("wrong passphrase: err = %v", err)
	}

	cb, _ := KnownHosts(filepath.Join(t.TempDir(), "known_hosts"), func(string, string, string) bool { return false })
	_, err = Open(t.Context(), Options{Profile: sshProfile(ks, config.SSHAuthKey, path), HostKey: cb,
		Secret: func(string) ([]byte, error) { return []byte("open sesame"), nil }})
	if err == nil || errors.Is(err, ErrAuth) {
		t.Errorf("refused host key: err = %v", err)
	}
}

// The drivers bound their handshakes and reads with deadlines, which an
// SSH channel does not support on its own.
func TestDialedConnHonoursDeadlines(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s)})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	c, err := tun.Dial(context.Background(), "tcp", echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	var ne net.Error
	if _, err := c.Read(make([]byte, 1)); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read past the deadline = %v, want a timeout", err)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo after a timeout = %q, %v", buf, err)
	}
	tun.Close()
	if _, err := c.Read(buf); err == nil {
		t.Error("read on a closed tunnel succeeded")
	}
}

// targetServer accepts one TCP connection and hands it to serve.
func targetServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c)
	}()
	return ln.Addr().String()
}

func openKeyTunnel(t *testing.T) *Tunnel {
	t.Helper()
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	tun, err := Open(context.Background(), Options{Profile: sshProfile(s, config.SSHAuthKey, path), HostKey: trust(s)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close() })
	return tun
}

// Closing the driver's end closes the connection on the far side.
func TestDriverCloseReachesTheServer(t *testing.T) {
	tun := openKeyTunnel(t)
	closed := make(chan struct{})
	addr := targetServer(t, func(c net.Conn) {
		io.Copy(io.Discard, c)
		c.Close()
		close(closed)
	})
	c, err := tun.Dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	c.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the close")
	}
}

// A server that answers and then closes without reading must not leave a
// large driver Write blocked: the bridge closes both ends when either copy
// ends.
func TestRemoteCloseUnblocksDriverWrite(t *testing.T) {
	tun := openKeyTunnel(t)
	addr := targetServer(t, func(c net.Conn) {
		c.Write([]byte("bye"))
		c.Close()
	})
	c, err := tun.Dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := c.Write(make([]byte, 8<<20)) // never read: blocks until the bridge closes
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a write to a closed connection succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the driver's Write is still blocked after the server closed")
	}
}
