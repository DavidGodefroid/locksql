package engine

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestTransportNotices(t *testing.T) {
	cases := []struct {
		name      string
		tr        Transport
		want, not string
	}{
		{"plain", Transport{Mode: config.TLSPrefer, Host: "db.example", Plain: true}, "NOT encrypted (tls = \"prefer\"); set tls = \"verify-full\" or use an ssh tunnel", ""},
		{"plain default mode", Transport{Host: "db.example", Plain: true}, "tls = \"prefer\"", ""},
		{"plain tunnelled", Transport{Mode: config.TLSDisable, Host: "db.internal", Plain: true, Tunneled: true}, "NOT encrypted (tls = \"disable\")", "use an ssh tunnel"},
		{"prefer tls", Transport{Mode: config.TLSPrefer, Host: "db.example"}, "not verified (tls = \"prefer\")", ""},
		{"require", Transport{Mode: config.TLSRequire, Host: "db.example"}, "not verified (tls = \"require\")", ""},
		{"require with ca", Transport{Mode: config.TLSRequire, CA: "/ca.pem", Host: "db.example"}, "", ""},
		{"verify-full", Transport{Mode: config.TLSVerifyFull, Host: "db.example"}, "", ""},
		{"loopback", Transport{Mode: config.TLSPrefer, Host: "127.0.0.1"}, "", ""},
		{"socket", Transport{Mode: config.TLSPrefer, Host: "/run/m.sock"}, "", ""},
	}
	for _, c := range cases {
		got := strings.Join(c.tr.Notices(), "\n")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: notices = %q, want %q", c.name, got, c.want)
		}
		if c.not != "" && strings.Contains(got, c.not) {
			t.Errorf("%s: notices = %q, must not advise %q", c.name, got, c.not)
		}
	}
}
