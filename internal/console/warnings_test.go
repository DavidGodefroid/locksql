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
	// A unique key on another column than the filtered one: no warning.
	h2 := newHarness(t, uatProfile())
	h2.sess.indexes = []engine.IndexDesc{{Name: "PRIMARY", Columns: []string{"id"}, Primary: true}}
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
	if !strings.Contains(out, "holds no plain column") {
		t.Errorf("no counts warning:\n%s", out)
	}
	// An expression over an aggregate is no plain column either.
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "n"}}, Rows: [][]any{{int64(1)}}}
	for _, q := range []string{
		"SELECT coalesce(max(id), 0) AS n FROM users WHERE email = '${r1.1.2}' LIMIT 1",
		"SELECT id + 0 AS n FROM users WHERE email = '${r1.1.2}' LIMIT 1",
	} {
		if out := runWarned(t, h, q); !strings.Contains(out, "holds no plain column") {
			t.Errorf("%s: no warning:\n%s", q, out)
		}
	}
}

// IN and BETWEEN on a unique key pin one row as = does.
func TestWarnProbeUniqueKeyInBetween(t *testing.T) {
	for _, w := range []string{"id IN (57)", "id BETWEEN 57 AND 57"} {
		h := newHarness(t, uatProfile())
		h.sess.indexes = []engine.IndexDesc{{Name: "PRIMARY", Columns: []string{"id"}, Primary: true}}
		firstResult(t, h)
		out := runWarned(t, h, "SELECT id, email, note FROM users WHERE "+w+" AND email = '${r1.1.2}' LIMIT 1")
		if !strings.Contains(out, "tests whether one row (users.id) has the same value as r1.1.2") {
			t.Errorf("%s: no probe warning:\n%s", w, out)
		}
	}
}

// The plain fetch of the rows behind references warns of nothing.
func TestNoWarningOnPlainInFetch(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.indexes = []engine.IndexDesc{{Name: "PRIMARY", Columns: []string{"id"}, Primary: true}}
	firstResult(t, h)
	out := runWarned(t, h, "SELECT id, email FROM users WHERE email IN ('${r1.1.2}') LIMIT 9")
	for _, w := range []string{"tests whether", "no plain column", "distinct ways", "in clear"} {
		if strings.Contains(out, w) {
			t.Errorf("plain IN fetch warned %q:\n%s", w, out)
		}
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
	if out := runWarned(t, h, "SELECT id, email, note FROM users WHERE email IN ('${r1.1.2}', '${r1.2.2}', '${r1.3.2}', '${r1.4.2}', '${r1.5.2}', '${r1.6.2}') LIMIT 9"); strings.Contains(out, "distinct ways") {
		t.Errorf("an IN list counted as a scan:\n%s", out)
	}
	var out string
	for i := 1; i <= 6; i++ {
		out = runWarned(t, h, "SELECT id, email, note FROM users WHERE email = '${r1."+string(rune('0'+i))+".2}' LIMIT 9")
	}
	if !strings.Contains(out, "filtered on cells of result r1 in 7 distinct ways") {
		t.Errorf("no scan warning after 7 uses (threshold 5):\n%s", out)
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
	if h.s.clearLiteral(`SELECT 1 FROM users WHERE email = '${email}'`) {
		t.Error("placeholder taken for a clear value")
	}
}

// A refusal after the approval still carries the warnings in the audit.
func TestWarnAuditedOnKAnonymityRefusal(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
	h.sess.count = countResult(int64(2))
	pr := h.plan(t, "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1", false)
	h.io.answers = []string{"y"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeRefused)
	log := h.auditLog(t)
	if !strings.Contains(log, `"refused"`) || !strings.Contains(log, `"warnings"`) {
		t.Errorf("refusal audited without the warnings:\n%s", log)
	}
}
