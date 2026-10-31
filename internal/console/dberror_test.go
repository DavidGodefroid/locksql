package console

import (
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// dbDetail is an engine error that quotes a value, as a database's message
// may: it must never reach the client.
const dbDetail = "Unknown error near carol@example.net"

// wantGeneric fails unless resp is the generic failure of what, with none
// of the database's text.
func wantGeneric(t *testing.T, resp ipc.Response, what string) {
	t.Helper()
	if resp.Error == nil {
		t.Fatal("the request succeeded")
	}
	m := resp.Error.Message
	if resp.Error.Code != ipc.CodeInternal || strings.Contains(m, "carol") || strings.Contains(m, "Unknown error") ||
		m != what+" failed: "+genericDBFailure {
		t.Errorf("client error %d %q", resp.Error.Code, m)
	}
}

// wantConsoleDetail fails unless the console shows the database's text;
// masked, the quoted value is redacted there too.
func wantConsoleDetail(t *testing.T, h *harness, masked bool) {
	t.Helper()
	out := h.io.output()
	if !strings.Contains(out, "Unknown error") {
		t.Errorf("the console does not show the failure:\n%s", out)
	}
	if masked == strings.Contains(out, "carol@example.net") {
		t.Errorf("console (masked %v):\n%s", masked, out)
	}
}

// A catalog request the database fails answers a generic failure: the
// database's text stays on the console and in the audit log, redacted.
func TestCatalogFailureIsGeneric(t *testing.T) {
	noMask := uatProfile()
	noMask.Detectors = nil
	for _, c := range []struct {
		name    string
		profile config.Profile
		masked  bool
	}{{"masked", uatProfile(), true}, {"unmasked", noMask, false}} {
		for _, m := range []struct {
			method string
			params any
			set    func(*fakeSession)
		}{
			{ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, func(f *fakeSession) { f.tablesErr = errors.New(dbDetail) }},
			{ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: "app", Table: "users"}, func(f *fakeSession) { f.describeErr = errors.New(dbDetail) }},
		} {
			t.Run(c.name+"/"+m.method, func(t *testing.T) {
				h := newHarness(t, c.profile)
				m.set(h.sess)
				wantGeneric(t, h.call(t, m.method, m.params), m.method)
				wantConsoleDetail(t, h, c.masked)
				log := h.auditLog(t)
				if strings.Count(log, `"event":"catalog"`) != 1 || !strings.Contains(log, "Unknown error") || c.masked && strings.Contains(log, "carol@") {
					t.Errorf("audit log:\n%s", log)
				}
			})
		}
	}
}

// The checks before a run (the object state of a guarded plan, the
// function lookup of the k-anonymity counts) answer a generic failure when
// the database fails them; the console shows the detail, and the audit of
// the k-anonymity check holds it redacted.
func TestRunCheckFailureIsGeneric(t *testing.T) {
	t.Run("object state", func(t *testing.T) {
		h := newHarness(t, uatProfile())
		guarded(h)
		pr := h.plan(t, selectUsers, false)
		h.sess.objectsErr = errors.New(dbDetail)
		wantGeneric(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "plan")
		wantConsoleDetail(t, h, true)
	})
	t.Run("k-anonymity check", func(t *testing.T) {
		ss := &shadowSession{}
		h := newHarness(t, uatProfile(), withShadows(ss))
		h.sess.count = countResult(int64(2))
		pr := h.plan(t, "SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", false)
		ss.err = errors.New(dbDetail)
		runs := h.sess.runCount()
		wantGeneric(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "k-anonymity check")
		wantConsoleDetail(t, h, true)
		if h.sess.runCount() != runs {
			t.Error("a statement ran")
		}
		log := h.auditLog(t)
		if !strings.Contains(log, "Unknown error") || strings.Contains(log, "carol@") {
			t.Errorf("audit log:\n%s", log)
		}
	})
}
