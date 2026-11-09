package console

import (
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/render"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

// pgWriteProfile is writeProfile on PostgreSQL.
func pgWriteProfile() config.Profile {
	p := writeProfile()
	p.Engine, p.Port = config.EnginePostgres, 5432
	return p
}

// An INSERT without a column list stores its values into the table's
// columns in their catalogue order: it is refused only when a value the
// agent chose lands in a column under a mask rule (#208).
func TestPositionalInsert(t *testing.T) {
	for _, p := range []config.Profile{writeProfile(), pgWriteProfile()} {
		h := newHarness(t, p)
		for _, q := range []string{
			"INSERT INTO orders VALUES (9999, 1, 1)",
			"INSERT INTO orders VALUES (9998, 1, 1), (9997, 2, 3)",
			"INSERT INTO users VALUES (1, NULL, 'n', 's')",
			"INSERT INTO users VALUES (1, DEFAULT, 'n', 's')",
			"INSERT INTO orders SELECT id + 100, user_id, total FROM orders WHERE id = 1",
			"INSERT INTO users SELECT id + 100, NULL, note, status FROM users WHERE id = 1",
		} {
			if r := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}); r.Error != nil {
				t.Errorf("%s: %s refused: %s", p.Engine, q, r.Error.Message)
			}
		}
		for q, code := range map[string]refusal.Code{
			"INSERT INTO users VALUES (1, 'victim@x.com', 'n', 's')":                         refusal.MaskedWrite,
			"INSERT INTO users SELECT id + 100, note, note, status FROM users WHERE id = 1":  refusal.MaskedWrite,
			"INSERT INTO users SELECT id + 100, email, note, status FROM users WHERE id = 1": refusal.MaskedWrite,
			"INSERT INTO orders VALUES (1, 2)":                                               refusal.InvalidSQL,
			"INSERT INTO missing VALUES (1, 2)":                                              refusal.UnknownName,
		} {
			r := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
			wantCode(t, r, ipc.CodeRefused)
			if r.Error.Data.Code != code {
				t.Errorf("%s: %s: %s %q, want %s", p.Engine, q, r.Error.Data.Code, r.Error.Message, code)
			}
		}
	}
}

// planTicket plans q and runs it, and returns the plan and the raw hub
// ticket.
func planTicket(t *testing.T, h *harness, hub *hubtest.Hub, q string) (ipc.PlanResult, string) {
	t.Helper()
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	return pr, string(hub.Ticket(tk))
}

// The ticket says personal data is touched only when the statement names a
// column under a mask rule, and names it; its literals are masked either
// way (#208).
func TestHubTicketTouched(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	_, raw := planTicket(t, h, hub, "UPDATE orders SET total = 12345 WHERE id = 67890")
	if strings.Contains(raw, render.TouchedColumn) || strings.Contains(raw, "masked columns") {
		t.Errorf("a write to no masked column touches personal data: %s", raw)
	}
	if strings.Contains(raw, "12345") || strings.Contains(raw, "67890") {
		t.Errorf("literal in clear: %s", raw)
	}
	_, raw = planTicket(t, h, hub, "UPDATE users SET email = NULL WHERE id = 67890")
	if !strings.Contains(raw, `"touched":["`+render.TouchedColumn+`"]`) || !strings.Contains(raw, "personal data: masked columns email") {
		t.Errorf("a write to a masked column, not touched: %s", raw)
	}
	if strings.Contains(raw, "67890") || strings.Contains(raw, touchedMark) {
		t.Errorf("literal or mark in the ticket: %s", raw)
	}
	// A detector still masks what it finds, without a masked column.
	_, raw = planTicket(t, h, hub, "UPDATE orders SET total = 0 WHERE id = 1 AND 'bob@example.org' <> ''")
	if strings.Contains(raw, "bob@example.org") || strings.Contains(raw, render.TouchedColumn) {
		t.Errorf("detected literal: %s", raw)
	}
}

// A write with no WHERE, or an always-true one, is a WARN, and its ticket
// says it changes the whole table (#208).
func TestWholeTableWriteWarns(t *testing.T) {
	for _, p := range []config.Profile{writeProfile(), pgWriteProfile()} {
		var hub *hubtest.Hub
		h := newHarness(t, p, withHub(t, &hub))
		h.sess.plan = engine.Plan{Root: engine.PlanNode{Detail: "UPDATE", EstRows: 1000, Children: []engine.PlanNode{
			{Table: "orders", Access: engine.AccessFull, EstRows: 1000},
		}}}
		for _, q := range []string{"UPDATE orders SET total = 0", "DELETE FROM orders WHERE true", "UPDATE orders SET total = 0 WHERE 1 = 1"} {
			pr, raw := planTicket(t, h, hub, q)
			if pr.Verdict != weight.Warn.String() || !slices.Contains(pr.Reasons, "no WHERE: the write changes every row of the table") {
				t.Errorf("%s: %s: verdict %s reasons %q", p.Engine, q, pr.Verdict, pr.Reasons)
			}
			if !strings.Contains(raw, "whole table: 1000 rows") || !strings.Contains(raw, "verdict WARN") {
				t.Errorf("%s: %s: ticket %s", p.Engine, q, raw)
			}
		}
		pr, raw := planTicket(t, h, hub, "UPDATE orders SET total = 0 WHERE id = 1")
		if pr.Verdict != weight.OK.String() || strings.Contains(raw, "whole table") {
			t.Errorf("%s: one-row update: verdict %s ticket %s", p.Engine, pr.Verdict, raw)
		}
	}
}

func TestWholeTableWrite(t *testing.T) {
	for q, want := range map[string]bool{
		"UPDATE orders SET amount = 0":                                       true,
		"update orders set amount = 0;":                                      true,
		"DELETE FROM orders":                                                 true,
		"DELETE FROM orders WHERE TRUE":                                      true,
		"DELETE FROM orders WHERE 1":                                         true,
		"UPDATE orders SET amount = 0 WHERE 1 = 1 RETURNING id":              true,
		"WITH s AS (SELECT id FROM t WHERE id = 1) UPDATE orders SET a = 1":  true,
		"UPDATE orders SET amount = (SELECT max(a) FROM t WHERE id = 1)":     true,
		"UPDATE orders SET amount = 0 WHERE id = 1":                          false,
		"UPDATE orders SET amount = 0 WHERE true AND id = 1":                 false,
		"UPDATE orders SET amount = 0 WHERE 1 = 2":                           false,
		"DELETE FROM orders ORDER BY id LIMIT 5":                             false,
		"INSERT INTO orders VALUES (1)":                                      false,
		"INSERT INTO orders (id) VALUES (1) ON DUPLICATE KEY UPDATE id = 2":  false,
		"WITH d AS (UPDATE t SET a = 1 RETURNING a) SELECT a FROM d LIMIT 1": false,
	} {
		if got := wholeTableWrite(sqlclass.Postgres, q); got != want {
			t.Errorf("wholeTableWrite(%q) = %v", q, got)
		}
	}
}

// A data-modifying CTE is refused at the plan, as its run would be (#208).
func TestNestedDMLRefusedAtPlan(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, pgWriteProfile(), withHub(t, &hub))
	for _, q := range []string{
		"WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING id) SELECT count(*) FROM d LIMIT 1",
		"WITH d AS (UPDATE orders SET total = 0 WHERE id = 1 RETURNING id) UPDATE orders SET total = 1 WHERE id = 2",
	} {
		r := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, r, ipc.CodeRefused)
		if r.Error.Data.Code != refusal.StatementKind || !strings.Contains(r.Error.Message, "not run in hub mode") {
			t.Errorf("%s: %s %q", q, r.Error.Data.Code, r.Error.Message)
		}
	}
	if hub.Pushed() != 0 {
		t.Fatalf("pushed %d", hub.Pushed())
	}
}
