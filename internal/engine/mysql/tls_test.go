package mysql

import (
	"bytes"
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
	go f.serve()
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

// TestNoAuthGuard checks that locksql leaves the authentication method to
// the driver and the server, on a remote host, in plain TCP (prefer falls
// back, disable) and in TLS whose certificate is not verified (prefer,
// require), which the driver negotiates itself: the clear-text password
// request is answered, and no locksql refusal stops it.
func TestNoAuthGuard(t *testing.T) {
	const secret = "S3cr3t-pa55word"
	for _, tc := range []struct {
		mode    string
		withTLS bool
	}{
		{config.TLSDisable, false},
		{config.TLSPrefer, false},
		{"", false},
		{config.TLSPrefer, true},
		{config.TLSRequire, true},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeServer{ln: ln}
		if tc.withTLS {
			cert := selfSigned(t)
			f.cert = &cert
		}
		go f.serve()
		p := config.Profile{Name: "t", Engine: config.EngineMySQL, Host: "db.example", Port: 3306, User: "u",
			TLS: tc.mode, Tier: config.TierRead, Limits: config.DefaultLimits(true)}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = Engine{}.Connect(ctx, p, []byte(secret), remoteDial(ln.Addr().String()))
		cancel()
		ln.Close()
		f.done.Wait()
		if err != nil && strings.Contains(err.Error(), "refused") {
			t.Errorf("tls=%q server TLS %v: locksql refused: %v", tc.mode, tc.withTLS, err)
		}
		f.mu.Lock()
		if !bytes.Contains(f.got.Bytes(), []byte(secret)) {
			t.Errorf("tls=%q server TLS %v: the clear-text password request was not answered (err %v)", tc.mode, tc.withTLS, err)
		}
		if f.tlsDone != tc.withTLS {
			t.Errorf("tls=%q server TLS %v: TLS negotiated = %v", tc.mode, tc.withTLS, f.tlsDone)
		}
		f.mu.Unlock()
	}
}
