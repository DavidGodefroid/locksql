package postgres

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TestClearTextPasswordRefusedUnverified: on a remote host under a tls mode
// that does not verify the certificate, a clear-text password request is
// refused before the password leaves, with the remedy named.
func TestClearTextPasswordRefusedUnverified(t *testing.T) {
	// require is not tried: the fake server speaks no TLS. passwordGuarded
	// covers it.
	for _, mode := range []string{config.TLSDisable, config.TLSPrefer, ""} {
		f := &fakeServer{clearText: true}
		p := config.Profile{Engine: config.EnginePostgres, Host: "db.internal", Port: 5432, User: "u", TLS: mode, Tier: config.TierRead}
		_, err := Engine{}.Connect(t.Context(), p, []byte("pw"), f.dial)
		if err == nil {
			t.Fatalf("tls=%q: connected", mode)
		}
		if f.passwordSeen.Load() {
			t.Errorf("tls=%q: the password was sent", mode)
		}
		for _, want := range []string{"clear text", "verify-full", "scram-sha-256"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("tls=%q: error %q lacks %q", mode, err, want)
			}
		}
		if strings.Contains(err.Error(), "pw") {
			t.Errorf("tls=%q: error quotes the password: %q", mode, err)
		}
	}
}

// TestClearTextPasswordAllowedLocal: a loopback host or a socket path does
// not cross the network: the request is answered.
func TestClearTextPasswordAllowedLocal(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "/var/run/postgresql"} {
		f := &fakeServer{clearText: true}
		p := config.Profile{Engine: config.EnginePostgres, Host: host, Port: 5432, User: "u", TLS: config.TLSDisable, Tier: config.TierRead}
		sess, err := Engine{}.Connect(t.Context(), p, []byte("pw"), f.dial)
		if err != nil {
			t.Fatalf("host %q: %v", host, err)
		}
		sess.Close()
		if !f.passwordSeen.Load() {
			t.Errorf("host %q: the password was not sent", host)
		}
	}
}

func TestPasswordGuarded(t *testing.T) {
	for _, tc := range []struct {
		host, tls, ca string
		want          bool
	}{
		{"db.internal", config.TLSDisable, "", true},
		{"db.internal", config.TLSPrefer, "", true},
		{"db.internal", "", "", true},
		{"db.internal", config.TLSRequire, "", true},
		{"db.internal", config.TLSRequire, "ca.pem", false},
		{"db.internal", config.TLSVerifyCA, "", false},
		{"db.internal", config.TLSVerifyFull, "", false},
		{"localhost", config.TLSDisable, "", false},
		{"::1", config.TLSDisable, "", false},
		{"/tmp", config.TLSDisable, "", false},
	} {
		p := config.Profile{Host: tc.host, TLS: tc.tls, TLSCA: tc.ca}
		if got := passwordGuarded(p); got != tc.want {
			t.Errorf("passwordGuarded(%q, tls=%q, ca=%q) = %v, want %v", tc.host, tc.tls, tc.ca, got, tc.want)
		}
	}
}
