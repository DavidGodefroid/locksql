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
