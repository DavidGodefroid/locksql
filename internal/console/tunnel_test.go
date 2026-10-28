package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/tunnel"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

func TestHostKeyAnswer(t *testing.T) {
	fp := "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	for _, c := range []struct {
		prod   bool
		answer string
		ok     bool
	}{
		{false, "yes", true}, {false, " yes ", true}, {false, "y", false}, {false, "YES", false}, {false, "", false},
		{true, "yes", false}, {true, "6789ABCDEFG"[3:], true}, {true, "89ABCDEF", false},
	} {
		if got := hostKeyAnswerOK(c.prod, fp, c.answer); got != c.ok {
			t.Errorf("prod=%v answer=%q: %v", c.prod, c.answer, got)
		}
	}
}

type noticeSession struct {
	engine.Session
	notices []string
	closed  bool
}

func (f *noticeSession) Notices() []string { return f.notices }
func (f *noticeSession) Close() error      { f.closed = true; return nil }

func TestTunneledSessionNotices(t *testing.T) {
	inner := &noticeSession{notices: []string{"the connection is NOT encrypted (tls = \"prefer\")"}}
	s := &tunneledSession{Session: inner, bastion: "bastion", dbHost: "db.internal"}
	got := strings.Join(s.Notices(), "\n")
	if !strings.Contains(got, "encrypted by SSH to bastion") || !strings.Contains(got, "from the bastion to db.internal") {
		t.Errorf("notices = %q", got)
	}
	s.dbHost = "127.0.0.1"
	if n := s.Notices(); len(n) != 0 {
		t.Errorf("database on the bastion: notices = %q", n)
	}
	inner.notices = nil
	s.dbHost = "db.internal"
	if n := s.Notices(); len(n) != 0 {
		t.Errorf("verified TLS: notices = %q", n)
	}
}

func TestTunneledSessionCloseClosesTunnel(t *testing.T) {
	inner := &noticeSession{}
	closed := false
	s := &tunneledSession{Session: inner, closeTunnel: func() error { closed = true; return nil }}
	s.Close()
	if !inner.closed || !closed {
		t.Errorf("session closed %v, tunnel closed %v", inner.closed, closed)
	}
}

func TestRetryKeychainSSHSecret(t *testing.T) {
	auth := fmt.Errorf("wrapped: %w", tunnel.ErrAuth)
	for _, c := range []struct {
		err  error
		used bool
		ok   bool
	}{
		{auth, true, true},
		{auth, false, false}, // the keychain secret was never handed to Open
		{errors.New("ssh: connect to bastion:22: connection refused"), true, false},
		{errors.New("ssh: bastion:22: knownhosts: key is unknown"), true, false},
		{tunnel.ErrHostKeyChanged, true, false},
		{context.Canceled, true, false},
	} {
		if got := retryKeychainSSHSecret(c.err, c.used); got != c.ok {
			t.Errorf("err=%v used=%v: %v", c.err, c.used, got)
		}
	}
}

func TestProxiedSessionNotices(t *testing.T) {
	inner := &noticeSession{notices: []string{"the connection is NOT encrypted (tls = \"prefer\")"}}
	s := &proxiedSession{Session: inner, program: "kubectl", dbHost: "db.internal"}
	got := strings.Join(s.Notices(), "\n")
	if !strings.Contains(got, "through proxy_command kubectl") || !strings.Contains(got, "to db.internal") || strings.Contains(got, "ssh tunnel") {
		t.Errorf("notices = %q", got)
	}
	// The database listens on loopback where the command runs.
	s.dbHost = "127.0.0.1"
	if n := s.Notices(); len(n) != 0 {
		t.Errorf("loopback database: notices = %q", n)
	}
}

func TestDescribePolicyShowsProxyCommand(t *testing.T) {
	p := uatProfile()
	p.ProxyCommand = []string{"docker", "exec", "-i", "my db", "nc", "127.0.0.1", "3306"}
	got := strings.Join(describePolicy(config.NewPolicy(p, nil, nil)), "\n")
	if !strings.Contains(got, `proxy_command: "docker" "exec" "-i" "my db" "nc" "127.0.0.1" "3306"`) {
		t.Errorf("policy:\n%s", got)
	}
}

func TestProxyStderrInConnectError(t *testing.T) {
	err := withProxyStderr(errors.New("handshake: EOF"), "Error: No such container: db")
	if !strings.Contains(err.Error(), "handshake: EOF") || !strings.Contains(err.Error(), "proxy_command stderr: Error: No such container: db") {
		t.Errorf("err = %v", err)
	}
	if e := errors.New("x"); withProxyStderr(e, "") != e {
		t.Error("an empty stderr changed the error")
	}
}
