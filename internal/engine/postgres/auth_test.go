package postgres

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TestClearTextPasswordAnswered: locksql leaves the authentication method
// to the driver and the server, whatever the host and the tls mode: a
// clear-text password request is answered, and a remote plaintext
// connection gets one notice instead of a refusal.
func TestClearTextPasswordAnswered(t *testing.T) {
	for _, tc := range []struct {
		host, tls string
		notice    bool
	}{
		{"db.internal", config.TLSDisable, true},
		{"db.internal", config.TLSPrefer, true}, // the fake server speaks no TLS: prefer falls back
		{"db.internal", "", true},
		{"localhost", config.TLSDisable, true},
		{"/var/run/postgresql", config.TLSDisable, false},
	} {
		f := &fakeServer{clearText: true}
		p := config.Profile{Engine: config.EnginePostgres, Host: tc.host, Port: 5432, User: "u", TLS: tc.tls, Tier: config.TierRead}
		sess, err := Engine{}.Connect(t.Context(), p, []byte("pw"), f.dial)
		if err != nil {
			t.Fatalf("host %q tls=%q: %v", tc.host, tc.tls, err)
		}
		n := sess.(*session).Notices()
		sess.Close()
		if !f.passwordSeen.Load() {
			t.Errorf("host %q tls=%q: the password was not sent", tc.host, tc.tls)
		}
		if got := len(n) == 1 && strings.Contains(n[0], "NOT encrypted"); got != tc.notice {
			t.Errorf("host %q tls=%q: notices = %q, want plaintext notice %v", tc.host, tc.tls, n, tc.notice)
		}
	}
}
