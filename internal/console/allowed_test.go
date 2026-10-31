//go:build unix

package console

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// allowedIsolation is a console container's: the console account (900),
// the clients group holding 1000 only, and allowed_uids honoured as
// lockkit's real ClientAllowed honours them.
func allowedIsolation(sys *sysconf.Config) isolationEnv {
	env := fakeIsolation(sys, sysconf.DisplayTTY)
	env.clientAllowed = func(sys *sysconf.Config, uid int) bool {
		return uid == 1000 || slices.Contains(sys.AllowedUIDs, uid)
	}
	return env
}

// --allowed-uids adds to the image's allowed_uids, as the build argument
// does, and to nothing else: the setup read is not changed in place.
func TestAllowUIDsExtendsTheSetup(t *testing.T) {
	sys := separated()
	sys.AllowedUIDs = []int{4242}
	got, err := allowUIDs(allowedIsolation(sys), []int{4243, 4242}).loadSys()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AllowedUIDs, []int{4242, 4243}) {
		t.Fatalf("AllowedUIDs = %v, want [4242 4243]", got.AllowedUIDs)
	}
	if !slices.Equal(sys.AllowedUIDs, []int{4242}) {
		t.Fatalf("the image's list changed: %v", sys.AllowedUIDs)
	}
	if same := allowUIDs(allowedIsolation(sys), nil); same.loadSys == nil {
		t.Fatal("no uids: loadSys lost")
	}
	if WithAllowedUIDs(nil, []int{1}) != nil || WithAllowedUIDs(sys, nil) != sys {
		t.Fatal("WithAllowedUIDs changed a nil setup or an empty list")
	}
	if _, err := allowUIDs(allowedIsolation(nil), []int{4242}).loadSys(); err == nil || !strings.Contains(err.Error(), "separated setup") {
		t.Fatalf("no separated setup: %v, want an error", err)
	}
}

// The isolation checks see the uids: the peer is served, another uid is
// not, and the console's own uid is refused (the separation would be void).
func TestAllowUIDsIsolation(t *testing.T) {
	iso, err := checkIsolation(&fakeIO{}, allowUIDs(allowedIsolation(separated()), []int{4242}))
	if err != nil {
		t.Fatalf("--allowed-uids 4242: %v", err)
	}
	served := iso.peerCheck()
	for uid, want := range map[int]bool{4242: true, 1000: true, 900: true, 4243: false, 0: false} {
		if served(ipc.Cred{UID: uid}) != want {
			t.Errorf("peer uid %d served = %v, want %v", uid, !want, want)
		}
	}
	iso, err = checkIsolation(&fakeIO{}, allowedIsolation(separated()))
	if err != nil || iso.peerCheck()(ipc.Cred{UID: 4242}) {
		t.Fatalf("without --allowed-uids, uid 4242 is served (%v)", err)
	}
	if _, err := checkIsolation(&fakeIO{}, allowUIDs(allowedIsolation(separated()), []int{900})); err == nil || !strings.Contains(err.Error(), "may also connect as a client") {
		t.Fatalf("--allowed-uids 900 (the console): %v, want a refusal", err)
	}
	// A terminal of an allowed uid is the agent's: refused.
	env := allowUIDs(allowedIsolation(separated()), []int{4242})
	env.terminalOwner = func() (int, bool) { return 4242, true }
	if _, err := checkIsolation(&fakeIO{}, env); err == nil || !strings.Contains(err.Error(), "terminal belongs to uid 4242") {
		t.Fatalf("terminal of an allowed uid: %v, want a refusal", err)
	}
}

// Run prints the allowed uids before anything else, and its isolation
// checks see them: the console's own uid is refused before any prompt.
func TestRunAllowedUIDs(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return allowedIsolation(separated()) }
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{}
	err := Run(context.Background(), Options{Hub: runHub(t), Profile: "uat", IO: io, StateDir: t.TempDir(), Cwd: root, AllowedUIDs: []int{4242, 900}})
	if err == nil || !strings.Contains(err.Error(), "may also connect as a client") {
		t.Fatalf("err = %v, want the console's uid refused", err)
	}
	if len(io.out) == 0 || io.out[0] != "allowed uids besides locksql-clients (--allowed-uids): 4242,900" {
		t.Fatalf("first lines: %q", io.out)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted before refusing: %q", io.prompts)
	}
}
