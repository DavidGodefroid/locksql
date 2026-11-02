package engine

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestTransportNotices(t *testing.T) {
	cases := []struct {
		name string
		tr   Transport
		want string
	}{
		{"plain", Transport{Mode: config.TLSPrefer, Plain: true}, "NOT encrypted (tls = \"prefer\")"},
		{"plain default mode", Transport{Plain: true}, "tls = \"prefer\""},
		{"plain disable", Transport{Mode: config.TLSDisable, Plain: true}, "NOT encrypted (tls = \"disable\")"},
		// TLS, verified or not, gets no notice.
		{"prefer tls", Transport{Mode: config.TLSPrefer}, ""},
		{"require", Transport{Mode: config.TLSRequire}, ""},
		{"verify-full", Transport{Mode: config.TLSVerifyFull}, ""},
	}
	for _, c := range cases {
		n := c.tr.Notices()
		got := strings.Join(n, "\n")
		if c.want == "" && got != "" || c.want != "" && (len(n) != 1 || !strings.Contains(got, c.want)) {
			t.Errorf("%s: notices = %q, want one with %q", c.name, got, c.want)
		}
		if strings.Contains(got, "verify-full") {
			t.Errorf("%s: notices = %q, must not advise verify-full", c.name, got)
		}
	}
}
