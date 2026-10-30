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
	}{
		{name: "status-uat", profile: uatProfile},
		{name: "status-production", profile: prodProfile},
		{name: "status-auto-unmask", profile: uatProfile, opts: []hopt{skip, allowUnmask}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.profile(), tc.opts...)
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
		answer string
		change func(*config.Profile)
	}{
		{name: "review-applied", answer: "y", change: func(p *config.Profile) { p.Limits.MaxRows = 5000; p.Tier = config.TierWrite }},
		{name: "review-refused", answer: "n", change: func(p *config.Profile) { p.Limits.MaxRows = 5000 }},
		{name: "review-production-off", answer: "y", change: func(p *config.Profile) { p.Production = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := uatProfile()
			if tc.name == "review-production-off" {
				start = prodProfile()
			}
			h := newHarness(t, start)
			next := start
			tc.change(&next)
			h.s.pending = new(config.Policy)
			*h.s.pending = config.NewPolicy(next, []string{"app.users.email"}, nil)
			recs := len(goldenRecords(t, h))
			reset(h)
			h.io.answers = []string{tc.answer}
			h.s.Command(context.Background(), ":review")
			compareGolden(t, tc.name, "== :review\n"+transcript(h)+"== audit\n"+audit(h, recs))
		})
	}
}

func jsonText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
