package console

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

func runWarned(t *testing.T, h *harness, q string) string {
	t.Helper()
	before := len(h.io.out)
	pr := h.plan(t, q, false)
	h.io.answers = []string{"n"}
	h.approveRun(t, pr.PlanID)
	return strings.Join(h.io.out[before:], "\n")
}

func TestWarnClearValueFromAgent(t *testing.T) {
	h := newHarness(t, uatProfile()) // detectors: email
	out := runWarned(t, h, "SELECT id, email, note FROM users WHERE email = 'alice@example.com' LIMIT 5")
	if !strings.Contains(out, "the agent received this value in clear") {
		t.Errorf("no warning:\n%s", out)
	}
	if !strings.Contains(h.auditLog(t), `"warnings"`) {
		t.Error("warning not audited")
	}
}

func TestClearLiteralQuoting(t *testing.T) {
	h := newHarness(t, uatProfile())
	for _, q := range []string{
		`SELECT 1 FROM users WHERE email = "alice@example.com"`,
		`SELECT 1 FROM users WHERE email = N'alice@example.com'`,
		`SELECT 1 FROM users WHERE email = 'ali''ce@example.com'`,
	} {
		if !h.s.clearLiteral(q) {
			t.Errorf("clear value missed: %s", q)
		}
	}
}

// A refusal after the approval still carries the warnings in the audit,
// the k-anonymity warning included.
func TestWarnAuditedOnRefusalAfterApproval(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.count = countResult(int64(2))
	pr := h.plan(t, "SELECT id, email FROM users WHERE email = 'alice@example.com' LIMIT 1", false)
	h.io.answers = []string{"y"}
	// The engine labels the email column otherwise: the result cannot be
	// masked with certainty.
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	wantCode(t, h.approveRun(t, pr.PlanID), ipc.CodeRefused)
	recs := h.auditRecords(t)
	last := recs[len(recs)-1]
	if last["event"] != "refused" || !strings.Contains(fmt.Sprint(last["warnings"]), "k-anonymity") {
		t.Errorf("refusal audited without the warnings: %v", last)
	}
}
