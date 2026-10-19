package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

func fingerOpt(io IO, v fingerprint.Verifier) hopt {
	return func(c *ServerConfig) {
		c.Approver = newFingerprintApprover(io, v, "left-index-finger", time.Second)
	}
}

func recordsOf(t *testing.T, h *harness, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range h.auditRecords(t) {
		if r["event"] == event {
			out = append(out, r)
		}
	}
	return out
}

// A server built with a fingerprint approver audits an approval with the
// desktop mode and denies a typed yes that no finger confirms.
func TestServerApprovalUsesApprover(t *testing.T) {
	v := &fingerprint.Fake{Results: []error{nil, fingerprint.ErrNoMatch}}
	io := &fakeIO{}
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.IO = io }, fingerOpt(io, v))
	h.io = io
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}); r.Error != nil {
		t.Fatalf("first run: %s", r.Error.Message)
	}
	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if r.Error == nil || !strings.Contains(r.Error.Message, "no fingerprint") {
		t.Fatalf("second run should be denied: %+v", r)
	}
	approved := recordsOf(t, h, string(audit.EventApproved))
	if len(approved) != 1 || approved[0]["approval"] != "desktop+fingerprint" {
		t.Fatalf("approved records: %v", approved)
	}
	denied := recordsOf(t, h, string(audit.EventDenied))
	if len(denied) != 1 || denied[0]["reason"] != "no fingerprint" || !strings.Contains(errText(denied[0]), "no match") {
		t.Fatalf("denied records: %v", denied)
	}
	if n := h.sess.runCount(); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
}

func TestServerThreeNoMatchesEndTheConsole(t *testing.T) {
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, fingerprint.ErrNoMatch}}
	io := &fakeIO{}
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.IO = io }, fingerOpt(io, v))
	h.io = io
	for i := 0; i < 3; i++ {
		pr := h.plan(t, selectUsers, false)
		h.io.answers = []string{"y"}
		h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	}
	reason, ended := h.s.Ended()
	if !ended || !strings.Contains(reason, "fingerprint") {
		t.Fatalf("ended = %v %q", ended, reason)
	}
}

func TestStartPolicyUsesApprover(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{answers: []string{"y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrTimeout}}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p, approver: newFingerprintApprover(io, v, "left-index-finger", time.Second)}
	_, _, err = st.startPolicy(context.Background(), state, config.ApprovedKey(t.TempDir(), "uat"), config.NewPolicy(p, nil, nil))
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("err = %v", err)
	}
	if v.Calls != 1 {
		t.Fatalf("calls = %d", v.Calls)
	}
}

// With no approver configured the typed one applies, and the audit says so.
func TestDefaultApproverAuditsSession(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	approved := recordsOf(t, h, string(audit.EventApproved))
	if len(approved) != 1 || approved[0]["approval"] != "session" {
		t.Fatalf("approved records: %v", approved)
	}
}

func errText(rec map[string]any) string {
	s, _ := rec["error"].(string)
	return s
}

// A policy refused for want of a finger says so in the audit record.
func TestStartPolicyNoFingerIsAudited(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{answers: []string{"y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch}}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p, approver: newFingerprintApprover(io, v, "left-index-finger", time.Second)}
	if _, _, err = st.startPolicy(context.Background(), state, config.ApprovedKey(t.TempDir(), "uat"), config.NewPolicy(p, nil, nil)); err == nil {
		t.Fatal("policy approved without a finger")
	}
	h := &harness{state: state}
	recs := recordsOf(t, h, string(audit.EventPolicy))
	if len(recs) != 1 || recs[0]["decision"] != "refused" || recs[0]["reason"] != "no fingerprint" || !strings.Contains(errText(recs[0]), "no match") {
		t.Fatalf("policy records: %v", recs)
	}
}
