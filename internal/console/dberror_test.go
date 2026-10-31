package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// dbDetail is an engine error that quotes a value, as a database's message
// may: it must never reach the client.
const dbDetail = "Unknown error near carol@example.net"

// noMask drops the harness's mask rule: with no detector either, the
// session masks nothing.
func noMask(p config.Profile) hopt {
	return func(c *ServerConfig) { c.Policy = config.NewPolicy(p, nil, nil) }
}

func noMaskProfile() config.Profile {
	p := uatProfile()
	p.Detectors = nil
	return p
}

var maskModes = []struct {
	name   string
	masked bool
}{{"masked", true}, {"unmasked", false}}

// modeHarness is a harness on uatProfile, masking or not.
func modeHarness(t *testing.T, masked bool, opts ...hopt) *harness {
	t.Helper()
	if masked {
		return newHarness(t, uatProfile(), opts...)
	}
	p := noMaskProfile()
	h := newHarness(t, p, append([]hopt{noMask(p)}, opts...)...)
	if h.s.masking() {
		t.Fatal("the unmasked harness masks")
	}
	return h
}

// wantGeneric fails unless resp is the generic failure of what, with none
// of the database's text.
func wantGeneric(t *testing.T, resp ipc.Response, what string) {
	t.Helper()
	wantClient(t, resp, what+" failed: "+genericDBFailure)
}

// wantClient fails unless resp is the error msg, with none of the
// database's text.
func wantClient(t *testing.T, resp ipc.Response, msg string) {
	t.Helper()
	if resp.Error == nil {
		t.Fatal("the request succeeded")
	}
	m := resp.Error.Message
	if resp.Error.Code != ipc.CodeInternal || m != msg ||
		strings.Contains(m, "carol") || strings.Contains(m, "Unknown error") || strings.Contains(m, "abc123") {
		t.Errorf("client error %d %q, want %q", resp.Error.Code, m, msg)
	}
}

// wantConsole fails unless the console shows detail; shown, when not
// empty, must be there, and hidden must not.
func wantConsole(t *testing.T, h *harness, detail, shown, hidden string) {
	t.Helper()
	out := h.io.output()
	if !strings.Contains(out, detail) || shown != "" && !strings.Contains(out, shown) || hidden != "" && strings.Contains(out, hidden) {
		t.Errorf("console (want %q, %q shown, %q hidden):\n%s", detail, shown, hidden, out)
	}
}

// wantConsoleDetail is wantConsole for dbDetail: masked, the quoted value
// is redacted on the console too.
func wantConsoleDetail(t *testing.T, h *harness, masked bool) {
	t.Helper()
	if masked {
		wantConsole(t, h, "Unknown error", "", "carol@example.net")
	} else {
		wantConsole(t, h, "Unknown error", "carol@example.net", "")
	}
}

// A catalog request the database fails answers a generic failure: the
// database's text stays on the console and in the audit log, redacted
// when the session masks.
func TestCatalogFailureIsGeneric(t *testing.T) {
	for _, c := range maskModes {
		for _, m := range []struct {
			method string
			params any
			set    func(*fakeSession, error)
		}{
			{ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, func(f *fakeSession, err error) { f.tablesErr = err }},
			{ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: "app", Table: "users"}, func(f *fakeSession, err error) { f.describeErr = err }},
		} {
			t.Run(c.name+"/"+m.method, func(t *testing.T) {
				h := modeHarness(t, c.masked)
				m.set(h.sess, errors.New(dbDetail))
				wantGeneric(t, h.call(t, m.method, m.params), m.method)
				wantConsoleDetail(t, h, c.masked)
				log := h.auditLog(t)
				if strings.Count(log, `"event":"catalog"`) != 1 || !strings.Contains(log, "Unknown error") || c.masked == strings.Contains(log, "carol@") {
					t.Errorf("audit log:\n%s", log)
				}
			})
			// A quoted value no detector recognises: masked, the quote
			// heuristic redacts it (it is not in the request).
			t.Run(c.name+"/"+m.method+"/quoted", func(t *testing.T) {
				h := modeHarness(t, c.masked)
				m.set(h.sess, errors.New(`invalid input syntax for type integer: "abc123"`))
				wantGeneric(t, h.call(t, m.method, m.params), m.method)
				log := h.auditLog(t)
				// The console and the audit log show the detail; masked, the
				// value is redacted from both.
				if c.masked {
					wantConsole(t, h, "invalid input syntax for type integer", "redacted", "abc123")
				} else {
					wantConsole(t, h, "invalid input syntax for type integer", `"abc123"`, "")
				}
				if !strings.Contains(log, "invalid input syntax") || c.masked && strings.Contains(log, "abc123") {
					t.Errorf("audit log:\n%s", log)
				}
			})
		}
	}
}

// The checks before a run (the object state of a guarded plan, the
// function lookup of the k-anonymity counts) answer a generic failure when
// the database fails them; the console shows the detail, and the audit of
// the k-anonymity check holds it, redacted when the session masks.
func TestRunCheckFailureIsGeneric(t *testing.T) {
	for _, c := range maskModes {
		t.Run(c.name+"/object state", func(t *testing.T) {
			h := modeHarness(t, c.masked)
			guarded(h)
			pr := h.plan(t, selectUsers, false)
			h.sess.objectsErr = errors.New(dbDetail)
			wantGeneric(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "plan")
			wantConsoleDetail(t, h, c.masked)
		})
		t.Run(c.name+"/k-anonymity check", func(t *testing.T) {
			ss := &shadowSession{}
			h := modeHarness(t, c.masked, withShadows(ss))
			h.sess.count = countResult(int64(2))
			pr := h.plan(t, "SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", false)
			ss.err = errors.New(dbDetail)
			runs := h.sess.runCount()
			wantGeneric(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "k-anonymity check")
			wantConsoleDetail(t, h, c.masked)
			if h.sess.runCount() != runs {
				t.Error("a statement ran")
			}
			log := h.auditLog(t)
			if !strings.Contains(log, "Unknown error") || c.masked == strings.Contains(log, "carol@") {
				t.Errorf("audit log:\n%s", log)
			}
		})
		t.Run(c.name+"/function lookup before the run", func(t *testing.T) {
			ss := &shadowSession{err: errors.New(dbDetail)}
			h, resp := failLastLookup(t, c.masked, ss)
			wantGeneric(t, resp, "plan")
			wantConsoleDetail(t, h, c.masked)
			log := h.auditLog(t)
			if !strings.Contains(log, `"decision":"failed"`) || !strings.Contains(log, "Unknown error") || c.masked == strings.Contains(log, "carol@") {
				t.Errorf("audit log:\n%s", log)
			}
		})
	}
}

// shadowQuery is a read with no k-anonymity count: its one lookup of
// operators at the run is the last one (runApproved).
const shadowQuery = "SELECT id, email, note FROM users WHERE id = 1 LIMIT 1"

// failLastLookup runs shadowQuery through its ticket with ss failing the
// last lookup, the one runApproved makes just before the statement; the
// number of lookups is learnt from a run that succeeds.
func failLastLookup(t *testing.T, masked bool, ss *shadowSession) (*harness, ipc.Response) {
	t.Helper()
	ok := &shadowSession{}
	h := modeHarness(t, masked, withShadows(ok))
	h.okRun(t, h.plan(t, shadowQuery, false).PlanID, nil)
	if ok.lookups == 0 {
		t.Fatal("no function lookup")
	}
	ss.failAt = ok.lookups
	h = modeHarness(t, masked, withShadows(ss))
	resp := h.approveRun(t, h.plan(t, shadowQuery, false).PlanID)
	if h.sess.runCount() != 0 {
		t.Error("the statement ran")
	}
	return h, resp
}

// A check cut by the statement timeout says so: the agent can tell it from
// a failure of the database.
func TestRunCheckTimeout(t *testing.T) {
	timedOut := fmt.Errorf("canceling statement near carol@example.net: %w", context.DeadlineExceeded)
	t.Run("k-anonymity function lookup", func(t *testing.T) {
		ss := &shadowSession{}
		h := newHarness(t, uatProfile(), withShadows(ss))
		pr := h.plan(t, "SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", false)
		ss.err = timedOut
		wantClient(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "k-anonymity check timed out (limits.statement_timeout)")
		wantConsole(t, h, "timed out", "canceling statement", "carol@example.net")
	})
	t.Run("k-anonymity count", func(t *testing.T) {
		h := newHarness(t, uatProfile())
		pr := h.plan(t, "SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", false)
		h.sess.runErr = timedOut
		wantClient(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "k-anonymity check timed out (limits.statement_timeout)")
		wantConsole(t, h, "timed out", "canceling statement", "carol@example.net")
	})
	t.Run("function lookup before the run", func(t *testing.T) {
		h, resp := failLastLookup(t, true, &shadowSession{err: timedOut})
		wantClient(t, resp, "plan timed out (limits.statement_timeout)")
		wantConsole(t, h, "timed out", "canceling statement", "carol@example.net")
	})
}

// A privilege audit the database fails reaches the agent (status health,
// doctor) as a fixed finding; the console alone shows the detail.
func TestPrivilegeAuditFailureIsGeneric(t *testing.T) {
	io := &fakeIO{answers: []string{"continue"}}
	st := &starter{io: io, profile: uatProfile()}
	if err := st.privileges(context.Background(), &fakeSession{extraErr: errors.New(dbDetail)}); err != nil {
		t.Fatal(err)
	}
	if len(st.privWarns) != 1 || st.privWarns[0] != privAuditFailed {
		t.Errorf("findings %q", st.privWarns)
	}
	if !strings.Contains(io.output(), "Unknown error") {
		t.Errorf("console:\n%s", io.output())
	}
	// On production the audit refuses the start, without the detail.
	p := prodProfile()
	st = &starter{io: &fakeIO{}, profile: p}
	err := st.privileges(context.Background(), &fakeSession{extraErr: errors.New(dbDetail)})
	if err == nil || strings.Contains(err.Error(), "carol") || len(st.privWarns) != 1 || st.privWarns[0] != privAuditFailed {
		t.Errorf("production: %v, findings %q", err, st.privWarns)
	}
}
