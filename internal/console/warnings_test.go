package console

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// firstResult runs a query whose email cells get references r1.R.2.
func firstResult(t *testing.T, h *harness) {
	t.Helper()
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE id = 1 LIMIT 1", false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
}

func runWarned(t *testing.T, h *harness, q string) string {
	t.Helper()
	before := len(h.io.out)
	pr := h.plan(t, q, false)
	h.io.answers = []string{"n"}
	h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
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
	if strings.Contains(runWarned(t, h, "SELECT id, email, note FROM users WHERE email = '${email}' LIMIT 5"), "in clear") {
		t.Error("a placeholder taken for a clear value")
	}
}

func TestWarnProbeUniqueKey(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.indexes = []engine.IndexDesc{{Name: "PRIMARY", Columns: []string{"id"}, Primary: true}}
	firstResult(t, h)
	out := runWarned(t, h, "SELECT id, email, note FROM users WHERE id = 57 AND email = '${r1.1.2}' LIMIT 1")
	if !strings.Contains(out, "tests whether one row (users.id) has the same value as r1.1.2") {
		t.Errorf("no probe warning:\n%s", out)
	}
	// Without a unique key on the filtered column: no warning.
	h.sess.indexes = nil
	h2 := newHarness(t, uatProfile())
	firstResult(t, h2)
	if out := runWarned(t, h2, "SELECT id, email, note FROM users WHERE status = 'x' AND email = '${r1.1.2}' LIMIT 1"); strings.Contains(out, "tests whether") {
		t.Errorf("warned without a unique key:\n%s", out)
	}
}

func TestWarnProbeCountsOnly(t *testing.T) {
	h := newHarness(t, uatProfile())
	firstResult(t, h)
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "count"}}, Rows: [][]any{{int64(1)}}}
	out := runWarned(t, h, "SELECT count(*) FROM users WHERE email = '${r1.1.2}' LIMIT 1")
	if !strings.Contains(out, "holds only counts") {
		t.Errorf("no counts warning:\n%s", out)
	}
}

func TestWarnProbeScan(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{
		Columns: []engine.ResultColumn{{Label: "id"}, {Label: "email", OriginDB: "app", OriginTable: "users", OriginColumn: "email"}, {Label: "note"}},
		Rows:    [][]any{},
	}
	for i := 1; i <= 7; i++ {
		h.sess.result.Rows = append(h.sess.result.Rows, []any{int64(i), "u@example.com", ""})
	}
	firstResult(t, h) // r1.1.2 .. r1.7.2
	// One IN list counts once.
	if out := runWarned(t, h, "SELECT id, email, note FROM users WHERE email IN ('${r1.1.2}', '${r1.2.2}', '${r1.3.2}', '${r1.4.2}', '${r1.5.2}', '${r1.6.2}') LIMIT 9"); strings.Contains(out, "distinct cells") {
		t.Errorf("an IN list counted as a scan:\n%s", out)
	}
	var out string
	for i := 1; i <= 6; i++ {
		out = runWarned(t, h, "SELECT id, email, note FROM users WHERE email = '${r1."+string(rune('0'+i))+".2}' LIMIT 9")
	}
	if !strings.Contains(out, "compared 7 distinct cells of result r1") {
		t.Errorf("no scan warning after 7 uses (threshold 5):\n%s", out)
	}
}
