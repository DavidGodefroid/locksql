package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	kipc "github.com/DavidGodefroid/lockkit/ipc"
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
	if os.Getuid() == 0 {
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
