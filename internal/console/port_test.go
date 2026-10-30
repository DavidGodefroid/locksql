package console

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kipc "github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// Behaviour that comes from lockkit's console since #96, pinned here.

// A change request beyond the 20 queued is refused (it no longer drops the
// oldest one).
func TestChangeRequestOverflowRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	for i := range 20 {
		h.ok(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "raise max_rows " + string(rune('a'+i))}, nil)
	}
	wantCode(t, h.call(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "one too many"}), ipc.CodeInvalidRequest)
	wantCode(t, h.call(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: ""}), ipc.CodeInvalidParams)
}

// A request naming a hub ticket on a console without its hub is answered
// withdrawn before locksql sees it, whatever the method.
func TestTicketWithoutHubWithdrawn(t *testing.T) {
	h := newHarness(t, uatProfile())
	for _, m := range []string{ipc.MethodQueryRun, ipc.MethodQueryPlan, ipc.MethodCatalogList} {
		wantCode(t, h.call(t, m, map[string]any{"ticket": "t-1"}), kipc.CodeWithdrawn)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("ran")
	}
}

// A tightening that cannot be saved still applies (the looser policy
// stayed in force before, which failed open), audited as unsaved.
func TestUnsavedTighteningApplies(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	h := newHarness(t, uatProfile())
	dir := filepath.Join(h.state, "locksql", "approved")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	next := h.s.approved
	next.Profile.Limits.MaxRows = h.s.approved.Profile.Limits.MaxRows / 2
	if err := h.s.adopt(next, "tightened"); err != nil {
		t.Fatal(err)
	}
	if h.s.approved.Profile.Limits.MaxRows != next.Profile.Limits.MaxRows {
		t.Fatal("unsaved tightening not in force")
	}
	if !strings.Contains(h.auditLog(t), `"decision":"unsaved"`) || !strings.Contains(h.io.output(), "could not be saved") {
		t.Fatalf("not audited or told:\n%s", h.io.output())
	}
}

// When the profile becomes production, a privilege audit that fails (not
// only one that finds grants) ends the session.
func TestBecomingProductionPrivilegeAuditError(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.extraErr = os.ErrPermission
	prod := uatProfile()
	prod.Production = true
	if err := h.s.adopt(config.NewPolicy(prod, []string{"app.users.email"}, nil), "tightened"); err != nil {
		t.Fatal(err)
	}
	if reason, ended := h.s.Ended(); !ended || reason != "privilege audit failed after the profile became production" {
		t.Fatalf("ended %v %q", ended, reason)
	}
	if !strings.Contains(h.io.output(), "privileges beyond tier read: the session ends") {
		t.Fatalf("not told:\n%s", h.io.output())
	}
}

// The hub goroutine's audit failures end the session through the request
// loop's tick (Serve's loop), not only a direct Tick.
func TestHubAuditFailuresEndTheSession(t *testing.T) {
	h := newHarness(t, uatProfile())
	readOnlyLog(t, h.state)
	for range maxAuditFails {
		h.s.auditHubRequest(kaudit.Base{Event: "reveal", Decision: "ok"})
	}
	h.s.loop().Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "the audit log cannot be written" {
		t.Fatalf("ended %v %q", ended, reason)
	}
}

// The fingerprint the hub goroutine checks tickets against follows the
// policy in force: a tightening moves it, a refused tightening and a
// loosening whose save failed leave it on the policy in force.
func TestLiveFingerprintFollowsThePolicy(t *testing.T) {
	h := newHarness(t, uatProfile())
	inForce := func() string {
		fp, err := ticket.HashOf(h.s.approved)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	fp0 := h.s.live.Load().fp
	if fp0 != inForce() {
		t.Fatal("start fingerprint")
	}
	next := h.s.approved
	next.Profile.Limits.MaxRows /= 2
	if err := h.s.adopt(next, "tightened"); err != nil {
		t.Fatal(err)
	}
	if fp := h.s.live.Load().fp; fp == fp0 || fp != inForce() {
		t.Fatal("tightening not published")
	}
	fp1 := inForce()
	// A loosening whose save fails is rolled back (a read-only directory:
	// not on Windows, nor as root).
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		dir := filepath.Join(h.state, "locksql", "approved")
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		looser := h.s.approved
		looser.Profile.Limits.MaxRows *= 4
		if err := h.s.adopt(looser, "applied"); err == nil {
			t.Fatal("a loosening adopted although its save failed")
		}
		if h.s.live.Load().fp != fp1 || inForce() != fp1 {
			t.Fatal("unsaved loosening published to the hub")
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A tightening locksql cannot compile ends the session; the hub stays
	// on the policy in force.
	bad := h.s.approved
	bad.Profile.Detectors = append(append([]string(nil), bad.Profile.Detectors...), "no-such-detector")
	_ = h.s.adopt(bad, "tightened")
	if _, ended := h.s.Ended(); !ended {
		t.Fatal("refused tightening: the session goes on")
	}
	if h.s.live.Load().fp != fp1 || inForce() != fp1 {
		t.Fatal("refused tightening published to the hub")
	}
}

// The hub goroutine reads the snapshot and writes its records while the
// request goroutine changes the policy (go test -race).
func TestHubGoroutineAlongsidePolicyChanges(t *testing.T) {
	h := newHarness(t, uatProfile())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			h.s.auditHubRequest(kaudit.Base{Event: "renew", Decision: "ok"})
			_ = h.s.live.Load().fp
		}
	}()
	for i := range 20 {
		next := h.s.approved
		next.Profile.Limits.MaxRows = 100 - i
		if err := h.s.adopt(next, "tightened"); err != nil {
			t.Fatal(err)
		}
		h.s.Tick()
	}
	<-done
}
