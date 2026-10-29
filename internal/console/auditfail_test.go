package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
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

// readOnlyLog makes the harness's audit log unwritable for the test.
func readOnlyLog(t *testing.T, state string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	path := filepath.Join(state, "locksql", "audit.log")
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}

// A widening the human decides at the console takes effect only once it
// is recorded (locksql#102): auto mode, clear results, unmask.
func TestWideningAuditFailureKeepsSwitchesOff(t *testing.T) {
	h := newHarness(t, uatProfile())
	readOnlyLog(t, h.state)

	h.s.toggleMode()
	if h.s.auto {
		t.Error("auto mode on without a record")
	}
	h.s.toggleResults()
	if h.s.showResults {
		t.Error("clear results shown without a record")
	}
	h.io.answers = []string{"y"}
	h.s.toggleUnmask(context.Background())
	if h.s.allowUnmask {
		t.Error("unmask allowed without a record")
	}
	if !strings.Contains(h.io.output(), "not recorded in the audit log") {
		t.Fatalf("the human was not told:\n%s", h.io.output())
	}
}

// A loosened policy is neither saved nor applied when its record fails.
func TestAdoptAppliedAuditFailure(t *testing.T) {
	h := newHarness(t, uatProfile())
	readOnlyLog(t, h.state)
	next := h.s.approved
	next.Profile.Limits.MaxRows = h.s.approved.Profile.Limits.MaxRows + 100
	if err := h.s.adopt(next, "applied"); err == nil {
		t.Fatal("loosening adopted without a record")
	}
	if h.s.approved.Profile.Limits.MaxRows == next.Profile.Limits.MaxRows {
		t.Error("loosening applied without a record")
	}
	if _, err := config.LoadApproved(h.state, h.s.cfg.ApprovedKey); err == nil {
		t.Error("loosening saved without a record")
	}
}

// At start, a policy the human approves is not saved when its record
// fails, and the console does not start.
func TestStartPolicyAuditFailure(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyLog(t, state)
	io := &fakeIO{answers: []string{"y"}}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p}
	key := config.ApprovedKey(t.TempDir(), p.Name)
	if _, _, err := st.startPolicy(context.Background(), state, key, config.NewPolicy(p, nil, nil)); err == nil {
		t.Fatal("first-start policy approved without a record")
	}
	if _, err := config.LoadApproved(state, key); err == nil {
		t.Error("policy saved without a record")
	}
}

// Declining to mask a quasi-identifier widens the PII rules: nothing is
// saved without its record.
func TestPIIAllowAuditFailure(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	rulesPath := filepath.Join(root, pii.RulesFile)
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyLog(t, state)
	io := &fakeIO{answers: []string{"n"}}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p}
	sess := &columnsSession{cols: []engine.ColumnInfo{{DB: "app", Table: "users", Column: "gender", Type: "varchar"}}}
	key := config.ApprovedKey(root, p.Name)
	if _, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, config.NewPolicy(p, nil, nil)); err == nil {
		t.Fatal("allow rule kept without a record")
	}
	if _, err := os.Stat(rulesPath); err == nil {
		t.Error("rules file written without a record")
	}
	if _, err := config.LoadApproved(state, key); err == nil {
		t.Error("policy saved without a record")
	}
}

// A trusted SSH host key that cannot be recorded is not trusted, so it is
// never written to known_hosts.
func TestHostKeyAuditFailure(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	st := &starter{io: &fakeIO{}, log: log, profile: uatProfile()}
	if !st.recordHostKey("bastion.example.com", "SHA256:abc") {
		t.Fatal("recorded key refused")
	}
	readOnlyLog(t, state)
	if st.recordHostKey("bastion.example.com", "SHA256:def") {
		t.Fatal("host key trusted without a record")
	}
}
