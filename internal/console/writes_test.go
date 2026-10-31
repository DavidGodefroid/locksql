package console

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The rows a write returns are resolved like a read's: a renamed rule
// column in a RETURNING list is masked by provenance whatever label or
// origin the engine reports, and never handed back as a cell reference.
func TestWriteReturningMaskedByProvenance(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	for _, c := range []struct {
		sql   string
		label string
	}{
		{"DELETE FROM users WHERE id = 1 RETURNING email AS x, id", "x"},
		{"INSERT INTO users (id, note) VALUES (9, 'a') RETURNING email AS e, id", "e"},
		{"REPLACE INTO users (id, note) VALUES (9, 'a') RETURNING users.email AS id, id AS email", "id"},
	} {
		h.sess.result = engine.Result{
			Columns: []engine.ResultColumn{{Label: c.label}, {Label: "id"}},
			Rows:    [][]any{{"alice@example.com", int64(1)}},
		}
		if strings.Contains(c.sql, "AS email") {
			h.sess.result.Columns[1].Label = "email"
		}
		pr := h.plan(t, c.sql, false)
		var rr ipc.RunResult
		h.okRun(t, pr.PlanID, &rr)
		if got := fmt.Sprint(rr.Rows[0][0]); got != "<redacted>" {
			t.Errorf("%s: %v, want <redacted> (no reference)", c.sql, got)
		}
	}
}

// What the write analysis cannot resolve, or that transforms a rule column
// on its way out, is refused before the write runs.
func TestWriteAnalysisRefusesBeforeRun(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	for _, q := range []string{
		"DELETE FROM users WHERE id = 1 RETURNING lower(email) AS x",
		"INSERT INTO users (id, note) VALUES (9, 'a') RETURNING (SELECT concat(email, '') FROM users LIMIT 1) AS e",
		"DELETE users FROM users JOIN orders o ON o.user_id = users.id RETURNING users.email",
		"INSERT INTO users (id, note) VALUES (9, 'a') RETURNING nosuchcol",
		"INSERT INTO orders (id, user_id, total) SELECT id, id, x FROM (SELECT id, email AS x FROM users) d",
		"INSERT INTO orders (id, user_id, total) SELECT id, id, myfunc(id) FROM users",
		"INSERT INTO users (id, email) SELECT id, 'v@x.example' FROM orders",
	} {
		wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}), ipc.CodeRefused)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a refused statement ran")
	}
	// INSERT ... SELECT without a rule column passes, and so does a write
	// the analysis does not need.
	h.plan(t, "INSERT INTO orders (id, user_id, total) SELECT id, id, note FROM users WHERE email = 'a@x.example'", false)
	h.plan(t, "UPDATE users SET note = myfunc(id) WHERE id = 1", false)
}

// A write whose engine returns no rows (SQLite runs it without reading its
// RETURNING list) is not dropped for a missing result.
func TestWriteReturningNoRows(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	h.sess.result = engine.Result{Affected: 1}
	pr := h.plan(t, "DELETE FROM users WHERE id = 1 RETURNING email", false)
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
}

// write_functions = "allowlist" (issue #60): a write may call allowlisted
// functions only, masked or not, and CALL is refused; the default keeps
// the denylist alone.
func TestWriteFunctionsAllowlist(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierAdmin
	p.WriteFunctions = config.WriteFunctionsAllowlist
	h := newHarness(t, p, allowUnmask)
	for _, q := range []string{
		"UPDATE users SET note = myfunc(id) WHERE id = 1",
		"INSERT INTO orders (id, user_id, total) VALUES (1, 1, shop.price(1))",
		"DELETE FROM users WHERE id = `lower`(1)",
		"UPDATE users u, orders o SET u.note = o.total WHERE o.user_id = u.id",
		"CALL refresh_totals()",
		"UPDATE users SET note = lower (note) WHERE id = 1",
		"UPDATE users SET note = users.nosuch WHERE id = 1",
	} {
		for _, unmask := range []bool{false, true} {
			wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q, Unmask: unmask}), ipc.CodeRefused)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a refused statement ran")
	}
	h.plan(t, "UPDATE users SET note = concat(lower(note), UUID()) WHERE id = abs(-1)", false)
	h.plan(t, "INSERT INTO users (id, note) VALUES (9, 'a') ON DUPLICATE KEY UPDATE note = VALUES(note)", false)
}

func TestWriteFunctionsDefaultDenylist(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierAdmin
	h := newHarness(t, p)
	h.plan(t, "UPDATE users SET note = myfunc(id) WHERE id = 1", false)
	h.plan(t, "CALL refresh_totals()", false)
}
