package console

import (
	"strings"
	"testing"

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
