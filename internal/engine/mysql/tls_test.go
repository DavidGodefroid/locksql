package mysql

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TestRequireNeverFallsBack checks that a server offering no TLS is refused
// by every mode that demands encryption, instead of being dialled plain.
func TestRequireNeverFallsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ln: ln}
	go f.serve(t)
	defer func() { ln.Close(); f.done.Wait() }()
	port := ln.Addr().(*net.TCPAddr).Port

	for _, mode := range []string{config.TLSRequire, config.TLSVerifyCA, config.TLSVerifyFull} {
		p := config.Profile{Engine: config.EngineMySQL, Host: "127.0.0.1", Port: port, User: "u", TLS: mode}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := Engine{}.Connect(ctx, p, []byte("pw"), nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Errorf("%s: err = %v, want a TLS refusal", mode, err)
		}
	}
}

func TestNoticeOnlyWhenNotVerified(t *testing.T) {
	cases := []struct {
		mode  string
		plain bool
		want  string
	}{
		{config.TLSPrefer, true, "NOT encrypted"},
		{config.TLSDisable, true, "NOT encrypted"},
		{config.TLSPrefer, false, "not verified"},
		{config.TLSRequire, false, "not verified"},
		{config.TLSVerifyFull, false, ""},
	}
	for _, c := range cases {
		s := &session{tlsMode: c.mode, plain: c.plain, host: "db.example"}
		got := strings.Join(s.Notices(), "\n")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s plain=%v: notices = %q, want %q", c.mode, c.plain, got, c.want)
		}
	}
}
