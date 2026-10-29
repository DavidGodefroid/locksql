package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// An approval that cannot be audited runs nothing (fail closed); three
// failed writes in a row end the session (lockkit#5).
func TestApprovalAuditFailureRefuses(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	h := newHarness(t, uatProfile())
	logPath := filepath.Join(h.state, "locksql", "audit.log")
	if err := os.Chmod(logPath, 0o400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(logPath, 0o600)

	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if r.Error == nil || r.Error.Code != ipc.CodeInternal || !strings.Contains(r.Error.Message, "could not record the approval") {
		t.Fatalf("unrecorded approval ran: %s %+v", r.Result, r.Error)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("the statement ran")
	}
	out := h.io.output()
	if !strings.Contains(out, "audit log write failed") || !strings.Contains(out, "refused: the approval could not be recorded") {
		t.Fatalf("the human was not told:\n%s", out)
	}

	// Auto mode too.
	h.s.auto = true
	pr = h.plan(t, selectUsers, false)
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("unrecorded auto approval ran: %+v", r.Error)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("the statement ran in auto mode")
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended after two failures")
	}
	pr = h.plan(t, selectUsers, false)
	_ = h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if reason, ended := h.s.Ended(); !ended || reason != "the audit log cannot be written" {
		t.Fatalf("session not ended after repeated failures: %q %v", reason, ended)
	}
}
