//go:build unix

package console

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

func fakeIsolation(sys *sysconf.Config, display string) isolationEnv {
	return isolationEnv{
		loadSys:        func() (*sysconf.Config, error) { return sys, nil },
		display:        func() sysconf.Display { return sysconf.Display{Kind: display, Detail: display} },
		uid:            func() int { return 900 },
		userName:       func() (string, error) { return "locksql", nil },
		loginUID:       func() (int, bool) { return 900, true },
		terminalOwner:  func() (int, bool) { return 900, true },
		clientAllowed:  func(_ *sysconf.Config, uid int) bool { return uid == 1000 },
		clientGID:      func(*sysconf.Config) (int, error) { return 950, nil },
		accountExists:  func(uid int) bool { return uid == 0 || uid == 900 || uid == 1000 || uid == 1500 },
		relay:          func() string { return "" },
		machinectlUIDs: func() ([]int, bool) { return nil, true },
	}
}

// A uid removed from the client group loses access at its next connection,
// not at the next console start.
func TestPeerCheckLooksUpMembershipPerConnection(t *testing.T) {
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	member := true
	lookups := 0
	env.clientAllowed = func(_ *sysconf.Config, uid int) bool {
		lookups++
		return uid == 1000 && member
	}
	iso, err := checkIsolation(&fakeIO{}, env, uatProfile())
	if err != nil {
		t.Fatal(err)
	}
	lookups = 0
	check := iso.peerCheck()
	if !check(ipc.Cred{UID: 1000}) {
		t.Fatal("member refused")
	}
	member = false
	if check(ipc.Cred{UID: 1000}) {
		t.Error("a uid removed from the group still connects")
	}
	if lookups != 2 {
		t.Errorf("%d membership lookups for two connections, want 2", lookups)
	}
	if !check(ipc.Cred{UID: 900}) {
		t.Error("the console's own uid refused")
	}
	if lookups != 2 {
		t.Error("the console's own uid is looked up in the group")
	}
}

func separated() *sysconf.Config {
	return &sysconf.Config{ServiceUser: "locksql", ClientGroup: "locksql-clients", SocketDir: "/run/locksql", X11: sysconf.X11Warn}
}

// skipWithTestHook skips a same-user refusal test in a locksql_testhook
// build, where the console accepts same-user mode.
func skipWithTestHook(t *testing.T) {
	t.Helper()
	if allowSameUserForTests {
		t.Skip("built with the locksql_testhook tag")
	}
}

func TestIsolationSameUserRefused(t *testing.T) {
	skipWithTestHook(t)
	io := &fakeIO{}
	_, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayWayland), uatProfile())
	if err == nil {
		t.Fatal("same-user mode accepted")
	}
	for _, want := range []string{"separate account", "sudo locksql install", "locksql doctor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestIsolationSameUserRefusedBeforeX11(t *testing.T) {
	skipWithTestHook(t)
	io := &fakeIO{}
	_, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayX11), uatProfile())
	if err == nil || !strings.Contains(err.Error(), "separate account") {
		t.Fatalf("want the same-user refusal, got %v", err)
	}
	if strings.Contains(io.output(), "X11") {
		t.Errorf("X11 warning before the same-user refusal:\n%s", io.output())
	}
}

// TestRunSameUserRefusedFirst pins spec §8 "Console refuses to start without
// a separated setup": no prompt, no approved policy, no audit file.
func TestRunSameUserRefusedFirst(t *testing.T) {
	skipWithTestHook(t)
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	state := t.TempDir()
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return fakeIsolation(nil, sysconf.DisplayWayland) }
	t.Cleanup(func() { newIsolationEnv = old })

	io := &fakeIO{answers: []string{"y", "y", "y"}}
	err := Run(context.Background(), Options{Profile: "uat", Cwd: root, IO: io, StateDir: state})
	if err == nil || err.Error() != sameUserRefusal {
		t.Fatalf("want the same-user refusal, got %v", err)
	}
	if len(io.prompts) > 0 {
		t.Errorf("prompted before refusing: %q", io.prompts)
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 0 {
		t.Errorf("state written before refusing: %v", entries)
	}
}

func TestIsolationX11(t *testing.T) {
	io := &fakeIO{}
	if _, err := checkIsolation(io, fakeIsolation(separated(), sysconf.DisplayX11), uatProfile()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(io.output(), "X11") {
		t.Errorf("no X11 warning:\n%s", io.output())
	}
	prod := uatProfile()
	prod.Production = true
	if _, err := checkIsolation(&fakeIO{}, fakeIsolation(separated(), sysconf.DisplayX11), prod); err == nil {
		t.Error("X11 accepted on a production profile")
	}
	sys := separated()
	sys.X11 = sysconf.X11Refuse
	if _, err := checkIsolation(&fakeIO{}, fakeIsolation(sys, sysconf.DisplayX11), uatProfile()); err == nil {
		t.Error("X11 accepted with x11 = refuse")
	}
}

func TestIsolationSeparated(t *testing.T) {
	iso, err := checkIsolation(&fakeIO{}, fakeIsolation(separated(), sysconf.DisplayWayland), uatProfile())
	if err != nil {
		t.Fatal(err)
	}
	if iso.gid != 950 {
		t.Errorf("gid = %d", iso.gid)
	}
	check := iso.peerCheck()
	for uid, want := range map[int]bool{900: true, 1000: true, 1001: false, 0: false} {
		if got := check(ipc.Cred{UID: uid}); got != want {
			t.Errorf("peer uid %d: %v, want %v", uid, got, want)
		}
	}

	cases := map[string]func(*isolationEnv){
		"wrong account":        func(e *isolationEnv) { e.userName = func() (string, error) { return "david", nil } },
		"console in the group": func(e *isolationEnv) { e.clientAllowed = func(*sysconf.Config, int) bool { return true } },
		"started through sudo": func(e *isolationEnv) { e.loginUID = func() (int, bool) { return 1000, true } },
		"someone else's tty":   func(e *isolationEnv) { e.terminalOwner = func() (int, bool) { return 1000, true } },
		"unknown login uid":    func(e *isolationEnv) { e.loginUID = func() (int, bool) { return 4242, true } },
		"unknown tty owner":    func(e *isolationEnv) { e.terminalOwner = func() (int, bool) { return 4242, true } },
	}
	for name, mutate := range cases {
		env := fakeIsolation(separated(), sysconf.DisplayWayland)
		mutate(&env)
		if _, err := checkIsolation(&fakeIO{}, env, uatProfile()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The approval screen names the process by its executable when the kernel
// lets the console read it, else by its self-reported name, labelled.
func TestProcessText(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc only")
	}
	own := processText(os.Getpid())
	if !strings.HasPrefix(own, "exe /") {
		t.Errorf("own process: %q", own)
	}
	if got := processText(1 << 30); got != "" {
		t.Errorf("unknown pid: %q", got)
	}
	if who := peerText(withPeer(context.Background(), ipc.Cred{UID: os.Getuid(), PID: os.Getpid()})); !strings.Contains(who, "pid "+strconv.Itoa(os.Getpid())+" · exe /") {
		t.Errorf("peerText: %q", who)
	}
}

// An account outside the client group (an administrator who handed the
// console off with sudo or su, while the agents run under an account of
// their own) may start the console from its session and terminal: the
// agent's account can read neither.
func TestIsolationAcceptsNonClientSession(t *testing.T) {
	env := fakeIsolation(separated(), sysconf.DisplayTTY)
	env.loginUID = func() (int, bool) { return 1500, true }
	env.terminalOwner = func() (int, bool) { return 1500, true }
	io := &fakeIO{}
	if _, err := checkIsolation(io, env, uatProfile()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(io.out, "\n"), "login session of uid 1500, an account outside the client group") {
		t.Errorf("not reported: %q", io.out)
	}
}

// A session opened through a relay names the console account in loginuid
// and as the terminal owner, but the keystrokes come from the terminal of
// whoever ran the relay.
func TestIsolationRelays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		relay  string
		uids   []int
		listed bool
		want   string // "" accepted, else part of the refusal
	}{
		{"desktop session", "", nil, true, ""},
		{"machinectl from the agent's account", sysconf.RelayMachinectl, []int{1000}, true, "uid 1000, which may reach the console"},
		{"machinectl from an administrator", sysconf.RelayMachinectl, []int{1500}, true, ""},
		{"machinectl, one of two callers is the agent", sysconf.RelayMachinectl, []int{1500, 1000}, true, "uid 1000"},
		{"machinectl, caller not found", sysconf.RelayMachinectl, nil, true, "cannot tell which account"},
		{"machinectl, /proc not listed", sysconf.RelayMachinectl, nil, false, "cannot tell which account"},
		{"machinectl from a uid with no account", sysconf.RelayMachinectl, []int{4242}, true, "uid 4242"},
		{"ssh from this machine", sysconf.RelaySSHLoopback, nil, true, "ssh from this machine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := fakeIsolation(separated(), sysconf.DisplayWayland)
			env.relay = func() string { return tc.relay }
			env.machinectlUIDs = func() ([]int, bool) { return tc.uids, tc.listed }
			_, err := checkIsolation(&fakeIO{}, env, uatProfile())
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
