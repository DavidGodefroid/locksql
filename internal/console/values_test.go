package console

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

const typedQ = "SELECT id, email, note FROM users WHERE email = '${email}' LIMIT 5"

func TestTypedValueAskedOnceThenReused(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	if len(pr.Values) != 0 {
		t.Errorf("values before any prompt: %v", pr.Values)
	}
	h.io.secrets = []string{"alice@example.com"}
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if !slices.ContainsFunc(h.io.prompts, func(p string) bool { return strings.Contains(p, "${email}") && strings.Contains(p, "app.users.email") }) {
		t.Errorf("prompts %q", h.io.prompts)
	}
	if last := h.sess.runs[len(h.sess.runs)-1]; !strings.Contains(last, "email = 'alice@example.com'") {
		t.Errorf("ran %q", last)
	}
	if strings.Contains(rr.Text, "alice@") {
		t.Error("the value came back to the agent")
	}

	// Second statement with the same name: no value prompt.
	pr = h.plan(t, typedQ, false)
	if !slices.Equal(pr.Values, []string{"email"}) {
		t.Errorf("values %v", pr.Values)
	}
	before := len(h.io.prompts)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if got := h.io.prompts[before:]; len(got) != 1 || !strings.Contains(got[0], "Approve") {
		t.Errorf("prompts on reuse %q", got)
	}
	if !strings.Contains(h.io.output(), "${email} = value typed at") {
		t.Errorf("reuse not shown:\n%s", h.io.output())
	}
}

func TestTypedValueRetype(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	pr = h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"bob@example.com"}, []string{"r", "y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if last := h.sess.runs[len(h.sess.runs)-1]; !strings.Contains(last, "'bob@example.com'") {
		t.Errorf("ran %q", last)
	}
}

func TestTypedValueCancelled(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.io.secrets = nil // AskSecret fails: Ctrl-C or timeout
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeDenied)
	if h.sess.runCount() != 0 {
		t.Errorf("ran %q", h.sess.runs)
	}
	if pr = h.plan(t, typedQ, false); len(pr.Values) != 0 {
		t.Errorf("a cancelled name became known: %v", pr.Values)
	}
	if log := h.auditLog(t); !strings.Contains(log, `"event":"denied"`) || !strings.Contains(log, `"decision":"no value"`) {
		t.Errorf("audit log:\n%s", log)
	}
}

func TestTypedValueClientGone(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantCode(t, h.callCtx(t, ctx, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeDenied)
	if h.sess.runCount() != 0 {
		t.Errorf("ran %q", h.sess.runs)
	}
	if log := h.auditLog(t); !strings.Contains(log, `"decision":"abandoned"`) {
		t.Errorf("audit log:\n%s", log)
	}
}

func TestTypedValueUnsafeAudited(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.io.secrets = []string{`a\b`}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeDenied)
	if log := h.auditLog(t); !strings.Contains(log, `"decision":"unsafe value"`) || strings.Contains(log, `a\\b`) {
		t.Errorf("audit log:\n%s", log)
	}
}

// On a production profile named r, typing the name approves: it is not
// taken for a retype.
func TestRetypeNotTheApprovalAnswer(t *testing.T) {
	p := prodProfile()
	p.Name = "r"
	h := newHarness(t, p)
	pr := h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"r"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	pr = h.plan(t, typedQ, false)
	h.io.answers = []string{"r"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.sess.runCount() != 2 {
		t.Errorf("runs %q", h.sess.runs)
	}
	if strings.Contains(h.io.prompts[len(h.io.prompts)-1], "retype") {
		t.Errorf("prompt %q", h.io.prompts[len(h.io.prompts)-1])
	}
}

// A database error echoing the value SQL-quoted, or cut short, leaves no
// trace of it in the audit log, the console or the client answer.
func TestTypedValueQuotedOrCutEcho(t *testing.T) {
	for _, v := range []string{"o'brien@example.com", "o'zz-secret-77"} {
		h := newHarness(t, uatProfile())
		pr := h.plan(t, typedQ, false)
		q := strings.ReplaceAll(v, "'", "''")
		h.sess.runErr = errors.New("error 1064 (42000): You have an error in your SQL syntax; check the manual near '" + q + "' LIMIT 5' at line 1 and " + q)
		h.io.secrets, h.io.answers = []string{v}, []string{"y"}
		resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		if resp.Error == nil {
			t.Fatal("want an error")
		}
		for where, text := range map[string]string{"client": resp.Error.Message, "audit": h.auditLog(t), "console": h.io.output()} {
			if tail := v[strings.IndexByte(v, '\'')+1:]; strings.Contains(text, tail) {
				t.Errorf("%s holds %q:\n%s", where, v, text)
			}
		}
	}

	long := "averyveryverylongsecretvalue-0123456789"
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.sess.runErr = errors.New("error 1406 (22001): Data too long near " + long[:10])
	h.io.secrets, h.io.answers = []string{long}, []string{"y"}
	h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if log := h.auditLog(t); strings.Contains(log, long[:10]) {
		t.Errorf("audit log holds the cut value:\n%s", log)
	}
}

func TestTypedValueQuoting(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"o'brien@example.com"}, []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if last := h.sess.runs[len(h.sess.runs)-1]; !strings.Contains(last, "'o''brien@example.com'") {
		t.Errorf("ran %q", last)
	}
	pr = h.plan(t, strings.Replace(typedQ, "${email}", "${other}", 1), false)
	h.io.secrets = []string{`a\b`}
	runs := h.sess.runCount()
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeDenied)
	if h.sess.runCount() != runs {
		t.Errorf("ran %q", h.sess.runs[runs:])
	}
	if pr = h.plan(t, strings.Replace(typedQ, "${email}", "${other}", 1), false); slices.Contains(pr.Values, "other") {
		t.Errorf("a refused value became known: %v", pr.Values)
	}
}

func TestSkipPermissionsStillAsksValues(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.SkipPermissions = true })
	pr := h.plan(t, typedQ, false)
	h.io.secrets = []string{"alice@example.com"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.io.promptCount() != 1 {
		t.Errorf("prompts %q", h.io.prompts)
	}
	if h.sess.runCount() == 0 || !strings.Contains(h.sess.runs[len(h.sess.runs)-1], "email = 'alice@example.com'") {
		t.Errorf("ran %q", h.sess.runs)
	}
}

func TestTypedValueNeverLeaves(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}, {Label: "email"}, {Label: "note"}}, Rows: [][]any{}}
	pr := h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	pr = h.plan(t, typedQ, false)
	if strings.Contains(pr.SQL, "alice@") || pr.SQL != typedQ {
		t.Errorf("plan answer %q", pr.SQL)
	}
	if strings.Contains(h.auditLog(t), "alice@example.com") {
		t.Error("the typed value reached the audit log")
	}
}

// A database error quoting the typed value, quoted or not, reaches neither
// the client, nor the audit log, nor the console's error text.
func TestTypedValueNotInErrors(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, typedQ, false)
	h.sess.runErr = errors.New("conversion failed near zz-secret-77 and 'zz-secret-77'")
	h.io.secrets, h.io.answers = []string{"zz-secret-77"}, []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if resp.Error == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(resp.Error.Message, "zz-secret") {
		t.Errorf("client error %q", resp.Error.Message)
	}
	if strings.Contains(h.auditLog(t), "zz-secret") {
		t.Errorf("audit log:\n%s", h.auditLog(t))
	}
	if out := h.io.output(); strings.Contains(out, "failed: conversion failed near zz-secret") {
		t.Errorf("console error text:\n%s", out)
	}
}

// The k-anonymity counts of a mixed IN list never run the raw placeholder:
// the statement's own count runs with the typed value.
func TestTypedValueInKCheck(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.count = &engine.Result{Columns: []engine.ResultColumn{{Label: "n"}}, Rows: [][]any{{int64(100)}}}
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE email IN ('${a}', 'x') LIMIT 5", false)
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	var counts []string
	for _, r := range h.sess.runs {
		if strings.Contains(r, "${a}") {
			t.Errorf("ran a raw placeholder: %q", r)
		}
		if strings.Contains(r, "COUNT(*)") {
			counts = append(counts, r)
		}
	}
	// The subject count covers the literal the agent wrote; the statement's
	// own count runs with the typed value.
	if len(counts) != 2 || !strings.HasSuffix(counts[0], "= 'x'") || !strings.Contains(counts[1], "'alice@example.com'") {
		t.Errorf("k-checks %q (runs %q)", counts, h.sess.runs)
	}
}

func TestPlaceholderColumns(t *testing.T) {
	pl := &plan{an: &sqlast.Analysis{Values: []sqlast.ValueUse{
		{Kind: sqlast.ValueTyped, Name: "x", Column: sqlast.Source{DB: "app", Table: "users", Column: "email"}},
		{Kind: sqlast.ValueTyped, Name: "x", Column: sqlast.Source{DB: "app", Table: "users", Column: "alt_email"}},
		{Kind: sqlast.ValueTyped, Name: "x", Column: sqlast.Source{DB: "app", Table: "users", Column: "email"}},
		{Kind: sqlast.ValueTyped, Name: "v", Column: sqlast.Source{Column: "email", View: true}},
		{Kind: sqlast.ValueTyped, Name: "z"},
	}}}
	for name, want := range map[string]string{"x": "app.users.email, app.users.alt_email", "v": "email", "z": "?"} {
		if got := placeholderColumns(pl, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// A placeholder in a write is refused at plan time: it would run as the
// literal text '${...}', and no value is ever prompted for.
func TestPlaceholderInWriteRefused(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p, skip)
	for _, q := range []string{
		"UPDATE users SET email = '${email}' WHERE id = 7",
		"UPDATE users SET note = 'x' WHERE email = '${r1.1.2}'",
		"DELETE FROM users WHERE email = '${email}'",
		"INSERT INTO users (id, email) VALUES (9, '${email}')",
		"INSERT INTO users (id, email) VALUES (9, \"${email}\")",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error != nil && !strings.Contains(resp.Error.Message, "only allowed in read statements") {
			t.Errorf("%s: refusal %q", q, resp.Error.Message)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
	// A plain string that merely holds "${" further in is not a placeholder.
	h.plan(t, "UPDATE users SET note = 'cost: ${x}' WHERE id = 1", false)
}

// An approved statement whose run-time analysis fails is still audited,
// with its warnings, and without the typed value.
func TestRunTimeAnalysisFailureAudited(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE email = '${email}' AND note = 'bob@example.com' LIMIT 5", false)
	h.sess.colsErr = errors.New("catalog read failed for alice@example.com")
	h.s.catalogCache = nil
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if resp.Error == nil {
		t.Fatal("the run succeeded")
	}
	if strings.Contains(resp.Error.Message, "alice@") {
		t.Errorf("the value reached the client: %q", resp.Error.Message)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
	log := h.auditLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, `"approved"`) || !strings.Contains(last, `"error"`) || !strings.Contains(last, `"warnings"`) {
		t.Errorf("no audit record of the failed run: %s", last)
	}
	if strings.Contains(log, "alice@") {
		t.Error("the value reached the audit log")
	}
}

// While mask rules exist, a write cannot plant a value the agent chose into
// a masked column: read back, it would come as a reference to a known
// value, usable as a lookup without the k-anonymity check.
func TestWritePlantingRefused(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p, skip)
	for _, q := range []string{
		"UPDATE users SET email = 'victim@x.com' WHERE id = 1",
		"INSERT INTO users (id, email) VALUES (99, 'victim@x.com')",
		"UPDATE users SET email = note WHERE id = 1",
		"UPDATE users SET email = CONCAT('vic', 'tim@x.com') WHERE id = 1",
		"INSERT INTO users (id, email) SELECT 99, note FROM users WHERE id = 1",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error != nil && (!strings.Contains(resp.Error.Message, "cannot receive values the agent chose") || strings.Contains(resp.Error.Message, "victim")) {
			t.Errorf("%s: refusal %q", q, resp.Error.Message)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
	// NULL into a masked column, and any value into another column, pass.
	h.sess.result = engine.Result{}
	h.plan(t, "UPDATE users SET email = NULL WHERE id = 1", false)
	h.plan(t, "UPDATE users SET note = 'victim@x.com' WHERE id = 1", false)
	h.plan(t, "INSERT INTO users (id, note) VALUES (99, 'x')", false)
}
