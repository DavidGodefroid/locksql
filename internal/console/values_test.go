package console

import (
	"errors"
	"slices"
	"strings"
	"testing"

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

// The k-anonymity count of a mixed IN list runs with the typed value, never
// with the raw placeholder.
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
	if len(counts) == 0 || !strings.Contains(counts[0], "'alice@example.com'") {
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
