package console

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The status answer, :status and :review, byte for byte (#96): moving the
// console Server onto lockkit's must not change what clients get or what
// the human sees. Run with -update and review the diff of testdata/screens
// to change them deliberately.
func TestGoldenStatusAndReview(t *testing.T) {
	transcript := func(h *harness) string {
		h.io.mu.Lock()
		defer h.io.mu.Unlock()
		var b strings.Builder
		for _, l := range h.io.transcript {
			b.WriteString(strconv.Quote(l) + "\n")
		}
		h.io.transcript = nil
		return b.String()
	}
	reset := func(h *harness) {
		h.io.mu.Lock()
		h.io.transcript = nil
		h.io.mu.Unlock()
	}
	audit := func(h *harness, from int) string {
		var b strings.Builder
		for _, r := range goldenRecords(t, h)[from:] {
			var parts []string
			for _, k := range []string{"event", "decision", "approval", "reason", "error"} {
				if v, ok := r[k]; ok {
					parts = append(parts, k+"="+strings.TrimSpace(strings.ReplaceAll(jsonText(v), "\n", " ")))
				}
			}
			b.WriteString(strings.Join(parts, " ") + "\n")
		}
		return b.String()
	}

	for _, tc := range []struct {
		name    string
		profile func() config.Profile
		opts    []hopt
		pending bool
	}{
		{name: "status-uat", profile: uatProfile},
		{name: "status-production", profile: prodProfile},
		{name: "status-auto-unmask", profile: uatProfile, opts: []hopt{skip, allowUnmask}},
		{name: "status-desktop-health-pending", profile: uatProfile, opts: []hopt{func(c *ServerConfig) {
			c.Boundary = "level 1: the agent's account can read this window"
			c.Health = &ipc.Health{Separated: true, Display: "wayland", Privileges: []string{"INSERT on app.users"}, ExplainOK: true}
		}}, pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.profile(), tc.opts...)
			if tc.pending {
				next := tc.profile()
				next.Limits.MaxRows = 5000
				h.s.pending = new(config.Policy)
				*h.s.pending = config.NewPolicy(next, []string{"app.users.email"}, nil)
			}
			resp := h.call(t, ipc.MethodStatus, nil)
			if resp.Error != nil {
				t.Fatal(resp.Error.Message)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, resp.Result, "", "  "); err != nil {
				t.Fatal(err)
			}
			reset(h)
			h.s.Command(context.Background(), ":status")
			compareGolden(t, tc.name, "== status answer\n"+pretty.String()+"\n== :status\n"+transcript(h))
		})
	}

	for _, tc := range []struct {
		name   string
		start  func() config.Profile
		opts   []hopt
		answer string
		change func(*config.Profile)
		// mask is the pending policy's mask rules (nil: unchanged).
		mask []string
		// none: no pending change.
		none bool
		// requests are change.request proposals from clients.
		requests []string
	}{
		{name: "review-applied", start: uatProfile, answer: "y", change: func(p *config.Profile) { p.Limits.MaxRows = 5000; p.Tier = config.TierWrite }},
		{name: "review-refused", start: uatProfile, answer: "n", change: func(p *config.Profile) { p.Limits.MaxRows = 5000 }},
		{name: "review-production-off", start: prodProfile, answer: "y", change: func(p *config.Profile) { p.Production = false }},
		// lockkit's FormatChanges, :review wording and adopt differ here:
		// "- " only for PII rules and detectors, the auto-mode warning, and
		// the wider connection-change check (tls, ssh, proxy_command).
		{name: "review-removals-auto-connection", answer: "y", mask: []string{},
			start: func() config.Profile {
				p := prodProfile()
				p.Detectors, p.TLSCA = []string{"email", "iban"}, "/etc/ca.pem"
				return p
			},
			opts:   []hopt{skip},
			change: func(p *config.Profile) { p.Detectors, p.TLSCA, p.Production = []string{"email"}, "", false }},
		{name: "review-nothing", start: uatProfile, none: true},
		{name: "review-requests", start: uatProfile, none: true, requests: []string{"allow unmask on app.users.note", "raise max_rows to \x1b[2J500"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := tc.start()
			h := newHarness(t, start, tc.opts...)
			if !tc.none {
				next := start
				tc.change(&next)
				mask := []string{"app.users.email"}
				if tc.mask != nil {
					mask = tc.mask
				}
				h.s.pending = new(config.Policy)
				*h.s.pending = config.NewPolicy(next, mask, nil)
			}
			h.s.requests = tc.requests
			recs := len(goldenRecords(t, h))
			reset(h)
			h.io.answers = []string{tc.answer}
			h.s.Command(context.Background(), ":review")
			compareGolden(t, tc.name, "== :review\n"+transcript(h)+"== audit\n"+audit(h, recs))
		})
	}

	// A tightening read from the files applies at once.
	t.Run("tightened", func(t *testing.T) {
		next := uatProfile()
		next.Limits.MaxRows = 50
		h := newHarness(t, uatProfile(), func(c *ServerConfig) {
			c.LoadPolicy = func() (config.Policy, error) { return config.NewPolicy(next, []string{"app.users.email"}, nil), nil }
		})
		recs := len(goldenRecords(t, h))
		reset(h)
		h.s.CheckPolicy()
		compareGolden(t, "tightened", "== poll\n"+transcript(h)+"== audit\n"+audit(h, recs))
	})
}

func jsonText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
