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

// The hub decides the requests; the console's own decisions stay at the
// terminal, with the approver of its level: :unmask asks the finger, and
// a typed yes that no finger confirms leaves it off.
func TestConsoleDecisionsUseApprover(t *testing.T) {
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, nil}}
	io := &fakeIO{}
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.IO = io; c.Fingerprint = true }, fingerOpt(io, v))
	h.io = io
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if h.s.allowUnmask() || v.Calls != 1 {
		t.Fatalf("unmask = %v without a finger, calls %d", h.s.allowUnmask(), v.Calls)
	}
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.allowUnmask() || v.Calls != 2 {
		t.Fatalf("unmask = %v with a finger, calls %d", h.s.allowUnmask(), v.Calls)
	}
	// A request goes to the hub: no prompt, no finger.
	prompts := h.io.promptCount()
	pr := h.plan(t, selectUsers, false)
	pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if h.io.promptCount() != prompts || v.Calls != 2 {
		t.Fatalf("a request asked here: prompts %q, finger calls %d", h.io.prompts, v.Calls)
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
