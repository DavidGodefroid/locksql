package console

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/refusal"
)

// refusalCase is one refusal path of query.plan and what its answer must
// carry.
type refusalCase struct {
	name   string
	sql    string
	params func(*ipc.PlanParams)
	setup  func(*harness)
	code   refusal.Code
	// line, col and token, when line is set, are the expected span.
	line, col int
	token     string
}

// TestEveryPlanRefusalPathHasACode walks the refusal paths of query.plan:
// each answer carries its code, retry rule, hint and, when the check knows
// it, the place of the statement it points at.
func TestEveryPlanRefusalPathHasACode(t *testing.T) {
	writeTier := func(c *ServerConfig) {
		c.Policy.Profile.Tier = config.TierWrite
	}
	for _, tc := range []refusalCase{
		{name: "unmask off", sql: "SELECT email FROM users LIMIT 1", params: func(p *ipc.PlanParams) { p.Unmask = true }, code: refusal.UnmaskOff},
		{name: "no limit", sql: "SELECT id FROM users", code: refusal.NoLimit, line: 1, col: 21},
		{name: "limit too high", sql: "SELECT id FROM users LIMIT 100000", code: refusal.LimitTooHigh},
		{name: "two statements", sql: "SELECT id FROM users LIMIT 1; SELECT 2", code: refusal.MultiStatement, line: 1, col: 29, token: ";"},
		{name: "comment", sql: "SELECT id FROM users -- why\nLIMIT 1", code: refusal.ForbiddenToken, line: 1, col: 22, token: "--"},
		{name: "bind parameter", sql: "SELECT id FROM users WHERE id = ? LIMIT 1", code: refusal.ForbiddenToken, line: 1, col: 33, token: "?"},
		{name: "show", sql: "SHOW TABLES", code: refusal.StatementKind, line: 1, col: 1, token: "SHOW"},
		{name: "explain of a write", sql: "EXPLAIN DELETE FROM users", code: refusal.StatementKind, line: 1, col: 9},
		{name: "tier", sql: "DELETE FROM users WHERE id = 1", code: refusal.Tier},
		{name: "forbidden function", sql: "SELECT sleep(1) LIMIT 1", code: refusal.Forbidden, line: 1, col: 8, token: "sleep"},
		{name: "locking read", sql: "SELECT id FROM users LIMIT 1 FOR UPDATE", code: refusal.Forbidden, line: 1, col: 30, token: "FOR"},
		{name: "unsupported syntax", sql: "SELECT id FROM users WHERE ! (id = 1) LIMIT 1", code: refusal.UnsupportedSyntax, line: 1, col: 28, token: "!"},
		{name: "unknown column", sql: "SELECT nope FROM users LIMIT 1", code: refusal.UnknownName, line: 1, col: 8, token: "nope"},
		{name: "unknown table", sql: "SELECT id FROM nope LIMIT 1", code: refusal.UnknownName, line: 1, col: 16, token: "nope"},
		{name: "function outside the allowlist", sql: "SELECT frobnicate(id) FROM users LIMIT 1", code: refusal.Function, line: 1, col: 8, token: "frobnicate"},
		{name: "system schema", sql: "SELECT table_name FROM information_schema.tables LIMIT 1", code: refusal.SystemObject},
		{name: "masked filter", sql: "SELECT id FROM users WHERE email LIKE 'a%' LIMIT 1", code: refusal.MaskedFilter, line: 1, col: 28, token: "LIKE"},
		{name: "masked expression", sql: "SELECT lower(email) FROM users LIMIT 1", code: refusal.MaskedExpression, line: 1, col: 8, token: "lower"},
		{name: "masked order", sql: "SELECT id\nFROM users\nORDER BY email\nLIMIT 1", code: refusal.MaskedOrder, line: 3, col: 10, token: "email"},
		{name: "masked set operation", sql: "SELECT email FROM users UNION SELECT 'x' LIMIT 5", code: refusal.MaskedSetOp},
		{name: "size", sql: "SELECT repeat(note, 100000) FROM users LIMIT 1", code: refusal.Size},
		{name: "weight", sql: "SELECT id FROM users WHERE id = 1 LIMIT 1", setup: func(h *harness) { h.sess.plan = heavyPlan() }, code: refusal.Cost},
		{name: "explain failed", sql: "SELECT id FROM users WHERE id = 1 LIMIT 1", setup: func(h *harness) { h.sess.explainErr = errors.New("syntax error near 'secret'") }, code: refusal.Engine},
		{name: "unknown database", sql: "SELECT id FROM users LIMIT 1", params: func(p *ipc.PlanParams) { p.DB = "nope" }, code: refusal.UnknownName},
		{name: "database not served", sql: "SELECT id FROM users LIMIT 1", params: func(p *ipc.PlanParams) { p.DB = "nope" },
			setup: func(h *harness) { h.s.profile.Database = "app" }, code: refusal.DatabaseNotServed},
		{name: "leading blanks and EXPLAIN", sql: " \n  EXPLAIN SELECT nope FROM users LIMIT 1", code: refusal.UnknownName, line: 2, col: 18, token: "nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, uatProfile())
			checkRefusal(t, h, tc)
		})
	}
	for _, tc := range []refusalCase{
		{name: "placeholder in a write", sql: "UPDATE users SET note = 'x' WHERE email = '${e}'", code: refusal.Placeholder},
		{name: "write into a masked column", sql: "UPDATE users SET email = 'x' WHERE id = 1", code: refusal.MaskedWrite, line: 1, col: 18, token: "email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, uatProfile(), writeTier)
			checkRefusal(t, h, tc)
		})
	}
}

func checkRefusal(t *testing.T, h *harness, tc refusalCase) {
	t.Helper()
	if tc.setup != nil {
		tc.setup(h)
	}
	p := ipc.PlanParams{DB: "app", SQL: tc.sql}
	if tc.params != nil {
		tc.params(&p)
	}
	resp := h.call(t, ipc.MethodQueryPlan, p)
	wantCode(t, resp, ipc.CodeRefused)
	d := resp.Error.Data
	if d.Code != tc.code {
		t.Fatalf("code %s, want %s (%q)", d.Code, tc.code, resp.Error.Message)
	}
	if tc.line == 0 {
		return
	}
	if d.Span == nil || d.Span.Line != tc.line || d.Span.Col != tc.col || d.Span.Token != tc.token {
		t.Errorf("span %+v, want %d:%d %q (%q)", d.Span, tc.line, tc.col, tc.token, resp.Error.Message)
	}
}

// The refusal record of the audit log carries the code and the span.
func TestRefusalAuditCarriesTheCode(t *testing.T) {
	h := newHarness(t, uatProfile())
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT nope FROM users LIMIT 1"}), ipc.CodeRefused)
	recs := h.auditRecords(t)
	last := recs[len(recs)-1]
	if last["event"] != "refused" || last["code"] != "E_UNKNOWN_NAME" {
		t.Fatalf("record %v", last)
	}
	span, _ := last["span"].(map[string]any)
	if span["line"] != float64(1) || span["col"] != float64(8) || span["token"] != "nope" {
		t.Errorf("span %v", last["span"])
	}
	if !strings.Contains(h.io.output(), "refused [E_UNKNOWN_NAME]") {
		t.Errorf("the console does not show the code:\n%s", h.io.output())
	}
}

// A refusal's structured form never holds a literal of the statement, nor
// the database's text: only the message, written by locksql, may name
// what the agent wrote.
func TestRefusalDataHoldsNoLiteral(t *testing.T) {
	for _, q := range []string{
		"SELECT id FROM users WHERE email LIKE 'zz-secret%' LIMIT 1",
		"SELECT id FROM users WHERE ! ('zz-secret' = id) LIMIT 1",
		"SELECT id FROM users WHERE id = 'zz-secret' LIMIT 1 FOR UPDATE",
		"SELECT 'zz-secret', email FROM users ORDER BY email LIMIT 1",
		"SELECT id FROM users WHERE note = 'zz-secret' LIMIT 'zz-secret'",
		"SELECT id FROM users WHERE note = 'zz-secret'",
	} {
		h := newHarness(t, uatProfile())
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		b, _ := json.Marshal(resp.Error.Data)
		if strings.Contains(string(b), "zz-secret") {
			t.Errorf("%s: %s", q, b)
		}
	}
	// The database's text stays on the console.
	h := newHarness(t, uatProfile())
	h.sess.explainErr = errors.New("near 'zz-secret'")
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM users WHERE id = 1 LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if b, _ := json.Marshal(resp.Error); strings.Contains(string(b), "zz-secret") {
		t.Errorf("engine text reaches the client: %s", b)
	}
}

// Run-time refusals carry their code too: a weight refusal under a PII
// filter tells the agent nothing beyond its code (no span, no reason, the
// code's default hint).
func TestRunRefusalsCarryACode(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.plan = heavyPlan()
	pr := h.plan(t, "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1", false)
	h.io.answers = []string{""}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeRefused)
	want := refusal.Info{Code: refusal.Cost, Retry: refusal.Cost.Retry(), Hint: refusal.Cost.Hint()}
	if d := resp.Error.Data; *d != want {
		t.Errorf("hidden weight refusal: %+v, want %+v", d, want)
	}
	recs := h.auditRecords(t)
	if last := recs[len(recs)-1]; last["event"] != "refused" || last["code"] != "E_COST" {
		t.Errorf("record %v", last)
	}
}

// A refusal over a referenced cell carries nothing of its value.
func TestRefusalOverAReferenceHoldsNoValue(t *testing.T) {
	h := newHarness(t, uatProfile())
	const v = `zz-secret\value@example.com`
	h.sess.result.Rows[0][1] = v
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE id = 1 LIMIT 1", false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM users WHERE email = '${r1.1.2}' LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if resp.Error.Data.Code != refusal.Placeholder {
		t.Errorf("code %s (%q)", resp.Error.Data.Code, resp.Error.Message)
	}
	b, _ := json.Marshal(resp.Error)
	if strings.Contains(string(b), "zz-secret") {
		t.Errorf("the typed value reaches the client: %s", b)
	}
	if log := h.auditLog(t); strings.Contains(log, "zz-secret") {
		t.Errorf("the typed value reaches the audit log:\n%s", log)
	}
}

// A statement refused for carrying credentials leaves no secret in the
// audit log: its literals are redacted from the record.
func TestCredentialRefusalKeepsTheSecretOutOfTheAudit(t *testing.T) {
	for _, q := range []string{
		"SET PASSWORD = 'hunter2-secret'",
		"SET PASSWORD FOR bob = PASSWORD('hunter2-secret')",
		"CREATE USER bob IDENTIFIED BY 'hunter2-secret'",
		"ALTER USER bob IDENTIFIED WITH mysql_native_password AS 'hunter2-secret'",
		"GRANT ALL ON *.* TO bob IDENTIFIED BY 'hunter2-secret'",
	} {
		h := newHarness(t, uatProfile())
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error.Data.Code != refusal.Forbidden {
			t.Errorf("%s: code %s (%q)", q, resp.Error.Data.Code, resp.Error.Message)
		}
		log := h.auditLog(t)
		if strings.Contains(log, "hunter2") {
			t.Errorf("%s: the audit log holds the secret:\n%s", q, log)
		}
		if !strings.Contains(log, `"event":"refused"`) || !strings.Contains(log, "<redacted>") {
			t.Errorf("%s: refusal not audited with a redacted statement:\n%s", q, log)
		}
		if strings.Contains(h.io.output(), "hunter2") {
			t.Errorf("%s: the console shows the secret", q)
		}
	}
}
