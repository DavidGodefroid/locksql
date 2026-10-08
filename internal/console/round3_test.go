package console

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// A write whose RETURNING list moves a PII column under another label is
// refused at plan time, before it can run, even under --skip-permissions;
// so is a read of the planner statistics.
func TestWriteReturningPIIRefusedBeforeRun(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p, skip)
	for _, q := range []string{
		"UPDATE users SET note = note WHERE id < 3 RETURNING upper(email)",
		"DELETE FROM users WHERE id = 1 RETURNING concat(email, '') AS x",
		"SELECT min_value FROM mysql.column_stats LIMIT 5",
	} {
		wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}), ipc.CodeRefused)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a refused statement ran")
	}
	// A plain RETURNING of the rule column is allowed: it is masked by name.
	h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1 RETURNING id, email", false)

	// A read resolves a nested * over a PII source to that source and masks
	// it, whatever label or origin the engine reports.
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "x"}}, Rows: [][]any{{"Alice"}}}
	pr := h.plan(t, "WITH c AS (SELECT email FROM users) SELECT (SELECT * FROM c LIMIT 1) AS x LIMIT 5", false)
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if got := rr.Rows[0][0]; got != "A***(5)" {
		t.Errorf("nested PII source not masked: %v", got)
	}
}
