package console

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// Policy text shown to the human never carries raw terminal escapes.
func TestPolicyTextIsEscaped(t *testing.T) {
	evil := "zz.zz.z\x1b[1F\x1b[2K\x1b[8m"
	lines := formatChanges([]config.Change{
		{Field: "pii.allow", New: evil, Loosens: true},
		{Field: "host", Old: "db", New: "db\x1b[2K", Loosens: true},
	})
	p := config.NewPolicy(uatProfile(), nil, []string{evil})
	p.Profile.Host = "db\u202e"
	lines = append(lines, describePolicy(p)...)
	for _, l := range lines {
		if strings.Contains(l, "\x1b[1F") || strings.Contains(l, "\x1b[2K") || strings.Contains(l, "\x1b[8m") || strings.Contains(l, "\u202e") {
			t.Errorf("raw escape in %q", l)
		}
	}
	h := newHarness(t, uatProfile())
	wantCode(t, h.call(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "a.b.c\x1b[2J\x1b[H"}), ipc.CodeInvalidParams)
	if strings.Contains(h.io.output(), "\x1b[2J") {
		t.Error("raw escape printed")
	}
}

// A plan's weight verdict is checked again, under the limits in force, when
// it runs.
func TestRunReassessesWeightAfterTightening(t *testing.T) {
	h := newHarness(t, uatProfile(), skip)
	h.sess.plan = engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{
		{Table: "users", Access: engine.AccessFull, EstRows: 150_000},
	}}}
	pr := h.plan(t, "SELECT id FROM users LIMIT 10", false)
	if pr.Verdict != "WARN" {
		t.Fatalf("verdict %s", pr.Verdict)
	}
	next := h.s.approved
	next.Profile.Limits.ExplainRowsWarn, next.Profile.Limits.ExplainRowsRefuse = 1000, 10000
	if err := h.s.adopt(next, "tightened"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeRefused)
	if h.sess.runCount() != 0 || h.io.promptCount() != 0 {
		t.Fatal("stale plan ran")
	}
}

// A mask rule a client adds while a loosening is pending survives :review.
func TestPIIAddWhilePending(t *testing.T) {
	h := newHarness(t, uatProfile())
	next := h.s.approved
	next.Profile.Limits.MaxRows *= 2
	h.s.pending = &next
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.users.phone"}, nil)
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if !h.s.rules.Matches("app", "users", "phone") {
		t.Fatalf("client mask rule lost: %+v", h.s.rules)
	}
	if strings.Contains(h.io.output(), "- pii.mask") {
		t.Error("review shows the client rule as removed")
	}
}

// An adopted change of the transport (tls, tls_ca, the ssh table) ends the
// session as a host change does: the open connection keeps the old one.
func TestAdoptTransportChangeEndsSession(t *testing.T) {
	bastion := &config.SSHProfile{Host: "bastion", Port: 22, User: "ops", Auth: config.SSHAuthAgent, Credentials: config.CredentialsAsk}
	cases := []struct {
		name   string
		start  func(p *config.Profile)
		change func(p *config.Profile)
		ends   bool
	}{
		{"host", nil, func(p *config.Profile) { p.Host = "other.example" }, true},
		{"tls", nil, func(p *config.Profile) { p.TLS = config.TLSRequire }, true},
		{"tls_ca", nil, func(p *config.Profile) { p.TLSCA = "/ca.pem" }, true},
		{"ssh added", nil, func(p *config.Profile) { p.SSH = bastion }, true},
		{"ssh removed", func(p *config.Profile) { p.SSH = bastion }, func(p *config.Profile) { p.SSH = nil }, true},
		{"ssh host", func(p *config.Profile) { p.SSH = bastion }, func(p *config.Profile) { s := *bastion; s.Host = "other"; p.SSH = &s }, true},
		{"ssh same", func(p *config.Profile) { p.SSH = bastion }, func(p *config.Profile) { s := *bastion; p.SSH = &s }, false},
		{"limits", nil, func(p *config.Profile) { p.Limits.MaxRows *= 2 }, false},
	}
	for _, c := range cases {
		prof := uatProfile()
		if c.start != nil {
			c.start(&prof)
		}
		h := newHarness(t, prof)
		next := h.s.approved
		c.change(&next.Profile)
		if err := h.s.adopt(next, "approved"); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, ended := h.s.Ended(); ended != c.ends {
			t.Errorf("%s: session ended = %v, want %v", c.name, ended, c.ends)
		}
	}
}
