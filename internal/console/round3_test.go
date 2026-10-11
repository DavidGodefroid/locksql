package console

import (
	"fmt"
	"strings"
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
	if got := rr.Rows[0][0]; !strings.HasPrefix(fmt.Sprint(got), "<redacted") {
		t.Errorf("nested PII source not masked: %v", got)
	}
}

// The RETURNING list of a write is masked in each column's mode, as the
// approval screen promises: a redact rule gives plain <redacted>, not the
// partial format. (The SQLite engine runs a write without reading its
// RETURNING rows; MariaDB and PostgreSQL return them, as the fake does.)
func TestWriteReturningHonoursMaskMode(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	h.sess.result = engine.Result{
		Columns: []engine.ResultColumn{
			{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"},
			{Label: "email", OriginDB: "app", OriginTable: "users", OriginColumn: "email"},
		},
		Rows: [][]any{{int64(1), "alice@example.com"}},
	}
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1 RETURNING id, email", false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if len(rr.Rows) != 1 || len(rr.Rows[0]) != 2 || rr.Rows[0][1] != "<redacted>" {
		t.Errorf("RETURNING rows = %v, want the email <redacted>", rr.Rows)
	}
}
