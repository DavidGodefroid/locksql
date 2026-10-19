//go:build unix

package console

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/lockkit/sysconf"
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
		desktopEnv:     func() bool { return false },
		displaySet:     func() bool { return false },
		parentChain: func() ([]sysconf.Proc, error) {
			return []sysconf.Proc{{PID: 2, UID: 900, Comm: "foot"}, {PID: 1, UID: 0, Comm: "systemd"}}, nil
		},
		newVerifier: func(string) (fingerprint.Verifier, error) { return &fingerprint.Fake{EnrolledN: 1}, nil },
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
	iso, err := checkIsolation(&fakeIO{}, env)
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
	_, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayWayland))
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
	_, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayX11))
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

// The isolation refusal comes before the policy review: no prompt, no
// approved-policy file.
func TestRunIsolationBeforePolicy(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := fakeIsolation(separated(), sysconf.DisplayWayland)
		env.loginUID = func() (int, bool) { return 1000, true }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	state := t.TempDir()
	err := Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: state, Cwd: root})
	if err == nil || !strings.Contains(err.Error(), "login session of uid 1000") {
		t.Fatalf("err = %v", err)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted before the isolation check: %q", io.prompts)
	}
	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Fatalf("state written: %v", entries)
	}
}

func TestIsolationX11(t *testing.T) {
	io := &fakeIO{}
	if _, err := checkIsolation(io, fakeIsolation(separated(), sysconf.DisplayX11)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(io.output(), "X11") {
		t.Errorf("no X11 warning:\n%s", io.output())
	}
	iso, err := checkIsolation(&fakeIO{}, fakeIsolation(separated(), sysconf.DisplayX11))
	if err != nil {
		t.Fatal(err)
	}
	prod := uatProfile()
	prod.Production = true
	if err := iso.refuseX11IfProduction(prod); err == nil {
		t.Error("X11 accepted on a production profile")
	}
	if err := iso.refuseX11IfProduction(uatProfile()); err != nil {
		t.Errorf("X11 refused outside production: %v", err)
	}
	sys := separated()
	sys.X11 = sysconf.X11Refuse
	if _, err := checkIsolation(&fakeIO{}, fakeIsolation(sys, sysconf.DisplayX11)); err == nil {
		t.Error("X11 accepted with x11 = refuse")
	}
}

func TestIsolationSeparated(t *testing.T) {
	io := &fakeIO{}
	iso, err := checkIsolation(io, fakeIsolation(separated(), sysconf.DisplayWayland))
	if err != nil {
		t.Fatal(err)
	}
	if iso.desktop || iso.verifier != nil {
		t.Errorf("session shape marked desktop: %+v", iso)
	}
	if !containsLine(io, "session mode: boundary: kernel") {
		t.Errorf("out = %q", io.out)
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
		if _, err := checkIsolation(&fakeIO{}, env); err == nil {
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
	if _, err := checkIsolation(io, env); err != nil {
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
			_, err := checkIsolation(&fakeIO{}, env)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func desktopEnvFake(t *testing.T) isolationEnv {
	t.Helper()
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	env.desktopEnv = func() bool { return true }
	env.loginUID = func() (int, bool) { return 1000, true } // the agent's desktop session
	env.terminalOwner = func() (int, bool) { return 900, true }
	return env
}

func TestIsolationDesktopAccepted(t *testing.T) {
	io := &fakeIO{}
	iso, err := checkIsolation(io, desktopEnvFake(t))
	if err != nil {
		t.Fatal(err)
	}
	if !iso.desktop || iso.verifier == nil {
		t.Fatalf("iso = %+v", iso)
	}
	if !containsLine(io, "desktop mode, level 2: approvals by fingerprint (fprintd), boundary: your desktop session") || iso.Level() != 2 {
		t.Fatalf("out = %q", io.out)
	}
	if iso.gid != 950 || !iso.peerCheck()(ipc.Cred{UID: 1000}) {
		t.Errorf("gid = %d or the agent refused", iso.gid)
	}
}

func TestIsolationDesktopRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*isolationEnv)
		want string
	}{
		{"DISPLAY set", func(e *isolationEnv) { e.displaySet = func() bool { return true } }, "console: desktop mode needs a Wayland socket and no DISPLAY"},
		{"X11", func(e *isolationEnv) {
			e.display = func() sysconf.Display { return sysconf.Display{Kind: sysconf.DisplayX11} }
		}, "no DISPLAY"},
		{"text console", func(e *isolationEnv) {
			e.display = func() sysconf.Display { return sysconf.Display{Kind: sysconf.DisplayTTY} }
		}, "no DISPLAY"},
		{"terminal of the agent", func(e *isolationEnv) { e.terminalOwner = func() (int, bool) { return 1000, true } }, `console: desktop mode: the terminal must belong to "locksql"`},
		{"terminal unknown", func(e *isolationEnv) { e.terminalOwner = func() (int, bool) { return 0, false } }, "terminal must belong"},
		{"login uid not a client", func(e *isolationEnv) { e.loginUID = func() (int, bool) { return 1500, true } }, "console: desktop mode: started outside an allowed desktop session"},
		{"login uid unknown", func(e *isolationEnv) { e.loginUID = func() (int, bool) { return 0, false } }, "outside an allowed desktop session"},
		{"no emulator", func(e *isolationEnv) {
			e.parentChain = func() ([]sysconf.Proc, error) { return []sysconf.Proc{{PID: 2, UID: 900, Comm: "bash"}}, nil }
		}, `console: desktop mode: no terminal emulator of "locksql" above this process`},
		{"emulator of the agent", func(e *isolationEnv) {
			e.parentChain = func() ([]sysconf.Proc, error) { return []sysconf.Proc{{PID: 2, UID: 1000, Comm: "foot"}}, nil }
		}, "no terminal emulator"},
		{"parent chain unreadable", func(e *isolationEnv) {
			e.parentChain = func() ([]sysconf.Proc, error) { return nil, os.ErrPermission }
		}, "cannot read the parent processes"},
		{"relay", func(e *isolationEnv) { e.relay = func() string { return sysconf.RelayMachinectl } }, "machinectl"},
		{"reader error with wrong uid", func(e *isolationEnv) {
			e.newVerifier = func(string) (fingerprint.Verifier, error) {
				return nil, fmt.Errorf("%w: fprintd runs as uid 1000, expected 0", fingerprint.ErrWrongOwner)
			}
		}, "console: desktop mode: fingerprint reader refused"},
		{"other reader error", func(e *isolationEnv) {
			e.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, errors.New("boom") }
		}, "console: desktop mode: fingerprint reader refused"},
		{"other Enrolled error", func(e *isolationEnv) {
			e.newVerifier = func(string) (fingerprint.Verifier, error) {
				return &fingerprint.Fake{EnrolledErr: errors.New("boom")}, nil
			}
		}, "console: desktop mode: fingerprint reader refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := desktopEnvFake(t)
			c.mut(&env)
			io := &fakeIO{}
			iso, err := checkIsolation(io, env)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if iso != nil {
				t.Errorf("iso returned with a refusal: %+v", iso)
			}
			if containsLine(io, "desktop mode, level") {
				t.Errorf("accepted line printed: %q", io.out)
			}
		})
	}
}

// The checks run in order: the first failing one names the refusal.
func TestIsolationDesktopRefusalOrder(t *testing.T) {
	env := desktopEnvFake(t)
	verifierBuilt := false
	env.newVerifier = func(string) (fingerprint.Verifier, error) {
		verifierBuilt = true
		return &fingerprint.Fake{EnrolledN: 1}, nil
	}
	env.displaySet = func() bool { return true }
	env.terminalOwner = func() (int, bool) { return 1000, true }
	env.loginUID = func() (int, bool) { return 1500, true }
	env.parentChain = func() ([]sysconf.Proc, error) { return nil, nil }
	env.relay = func() string { return sysconf.RelaySSHLoopback }
	want := []string{"no DISPLAY", "terminal must belong", "outside an allowed desktop session", "no terminal emulator", "ssh from this machine"}
	fix := []func(){
		func() { env.displaySet = func() bool { return false } },
		func() { env.terminalOwner = func() (int, bool) { return 900, true } },
		func() { env.loginUID = func() (int, bool) { return 1000, true } },
		func() {
			env.parentChain = func() ([]sysconf.Proc, error) {
				return []sysconf.Proc{{PID: 3, UID: 900, Comm: "gnome-terminal-server"}}, nil
			}
		},
		func() { env.relay = func() string { return "" } },
	}
	for i, w := range want {
		_, err := checkIsolation(&fakeIO{}, env)
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Fatalf("step %d: err = %v, want %q", i, err, w)
		}
		if verifierBuilt {
			t.Fatalf("step %d: fprintd reached before the session checks", i)
		}
		fix[i]()
	}
	if _, err := checkIsolation(&fakeIO{}, env); err != nil {
		t.Fatal(err)
	}
}

// A verifier the desktop shape opened and then does not keep (level 1, or
// a refusal) is closed.
func TestIsolationDesktopClosesDroppedVerifier(t *testing.T) {
	for name, err := range map[string]error{"not enrolled": fingerprint.ErrNotEnrolled, "other": errors.New("boom")} {
		env := desktopEnvFake(t)
		v := &closingVerifier{Fake: fingerprint.Fake{EnrolledErr: err}}
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return v, nil }
		_, _ = checkIsolation(&fakeIO{}, env)
		if !v.closed {
			t.Errorf("%s: verifier not closed", name)
		}
	}
}

type closingVerifier struct {
	fingerprint.Fake
	closed bool
}

func (c *closingVerifier) Close() error { c.closed = true; return nil }

// Without LOCKSQL_DESKTOP, a console started with sudo from the agent's
// session is refused as before.
func TestIsolationSessionShapeStillRefusesAgentLogin(t *testing.T) {
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	env.loginUID = func() (int, bool) { return 1000, true } // sudo from the agent, no LOCKSQL_DESKTOP
	_, err := checkIsolation(&fakeIO{}, env)
	if err == nil || !strings.Contains(err.Error(), "login session of uid 1000") {
		t.Fatalf("err = %v", err)
	}
}

// /proc shows gnome-terminal-server truncated to 15 bytes; it still counts
// as the console account's emulator, and a longer or shorter name does not.
func TestIsolationDesktopTruncatedEmulator(t *testing.T) {
	for comm, ok := range map[string]bool{"gnome-terminal-": true, "gnome-terminal": false, "gnome-terminal-x": false, "foot": true} {
		env := desktopEnvFake(t)
		env.parentChain = func() ([]sysconf.Proc, error) {
			return []sysconf.Proc{{PID: 3, UID: 900, Comm: comm}}, nil
		}
		_, err := checkIsolation(&fakeIO{}, env)
		if ok && err != nil || !ok && err == nil {
			t.Errorf("comm %q: err = %v, want accepted %v", comm, err, ok)
		}
	}
}

// fprintd that does not answer counts as no reader: level 1.
func TestIsolationDesktopEnrolledTimeout(t *testing.T) {
	old := enrolledTimeout
	enrolledTimeout = 20 * time.Millisecond
	t.Cleanup(func() { enrolledTimeout = old })
	env := desktopEnvFake(t)
	env.newVerifier = func(string) (fingerprint.Verifier, error) { return &hangingEnrolled{}, nil }
	io := &fakeIO{}
	iso, err := checkIsolation(io, env)
	if err != nil {
		t.Fatal(err)
	}
	if iso.Level() != 1 || iso.verifier != nil {
		t.Fatalf("iso = %+v", iso)
	}
}

// Without a usable reader the desktop shape is level 1: typed approvals,
// the red boundary line, the reason named; never a refusal.
func TestIsolationDesktopLevel1(t *testing.T) {
	cases := []struct {
		name string
		v    func(string) (fingerprint.Verifier, error)
		why  string
	}{
		{"fprintd unavailable", func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }, "no reader"},
		{"unavailable wrapped", func(string) (fingerprint.Verifier, error) {
			return nil, fmt.Errorf("%w: no fingerprint reader: x", fingerprint.ErrUnavailable)
		}, "no reader"},
		{"not enrolled", func(string) (fingerprint.Verifier, error) {
			return &fingerprint.Fake{EnrolledErr: fingerprint.ErrNotEnrolled}, nil
		}, "no fingerprint enrolled for locksql: run sudo locksql enroll"},
		{"enrolled count zero", func(string) (fingerprint.Verifier, error) { return &fingerprint.Fake{}, nil }, "no fingerprint enrolled"},
		{"reader lost", func(string) (fingerprint.Verifier, error) {
			return &fingerprint.Fake{EnrolledErr: fingerprint.ErrUnavailable}, nil
		}, "no reader"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := desktopEnvFake(t)
			env.newVerifier = c.v
			io := &fakeIO{}
			iso, err := checkIsolation(io, env)
			if err != nil {
				t.Fatal(err)
			}
			if !iso.desktop || iso.verifier != nil || iso.Level() != 1 {
				t.Fatalf("iso = %+v", iso)
			}
			if !containsLine(io, red+"desktop mode, level 1: boundary: your desktop — the agent can read this window and type into it"+reset) {
				t.Errorf("no red level 1 line: %q", io.out)
			}
			if !containsLine(io, c.why) {
				t.Errorf("reason %q missing: %q", c.why, io.out)
			}
			if iso.gid != 950 || !iso.peerCheck()(ipc.Cred{UID: 1000}) {
				t.Errorf("gid = %d or the agent refused", iso.gid)
			}
		})
	}
}

type hangingEnrolled struct{ fingerprint.Fake }

func (*hangingEnrolled) Enrolled(ctx context.Context) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// writeProductionConfig writes a project whose profile "prod" is
// production when production is true.
func writeProductionConfig(t *testing.T, root string, production bool) {
	t.Helper()
	body := "[profiles.prod]\nengine = \"mariadb\"\nhost = \"db.example.com\"\nuser = \"alice\"\ntls = \"verify-full\"\nproduction = " + strconv.FormatBool(production) + "\n"
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func approvedFiles(t *testing.T, state string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(state, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// On X11 (x11 = warn) a production profile is refused before its policy
// review: no X client can answer it, no approval is written.
func TestRunProductionX11RefusedBeforePolicy(t *testing.T) {
	root := t.TempDir()
	writeProductionConfig(t, root, true)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return fakeIsolation(separated(), sysconf.DisplayX11) }
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "prod"}}
	state := t.TempDir()
	err := Run(context.Background(), Options{Profile: "prod", IO: io, StateDir: state, Cwd: root})
	if err == nil || !strings.Contains(err.Error(), "production profile in an X11 session") {
		t.Fatalf("err = %v", err)
	}
	if len(io.prompts) != 0 {
		t.Errorf("prompted: %q", io.prompts)
	}
	if f := approvedFiles(t, state); len(f) != 0 {
		t.Errorf("approval written: %v", f)
	}
}

// A profile turned non-production in the file is still refused on X11
// while its approved policy is production: the review would loosen it.
func TestRunProductionX11RefusedOnApprovedPolicy(t *testing.T) {
	root := t.TempDir()
	writeProductionConfig(t, root, true)
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	key := config.ApprovedKey(cfg.ProjectRoot, "prod")
	if err := config.SaveApproved(state, key, config.NewPolicy(cfg.Profiles["prod"], nil, nil)); err != nil {
		t.Fatal(err)
	}
	before := approvedFiles(t, state)
	b0, _ := os.ReadFile(before[0])
	writeProductionConfig(t, root, false)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv { return fakeIsolation(separated(), sysconf.DisplayX11) }
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "y"}}
	err = Run(context.Background(), Options{Profile: "prod", IO: io, StateDir: state, Cwd: root})
	if err == nil || !strings.Contains(err.Error(), "production profile in an X11 session") {
		t.Fatalf("err = %v", err)
	}
	if len(io.prompts) != 0 {
		t.Errorf("prompted: %q", io.prompts)
	}
	if b1, _ := os.ReadFile(before[0]); string(b1) != string(b0) {
		t.Error("approved policy rewritten")
	}
}

// In desktop mode a typed "y" alone never applies a policy: Run asks for
// the finger, and a non-matching one refuses.
func TestRunDesktopPolicyNeedsFinger(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	v := &fingerprint.Fake{EnrolledN: 1, Results: []error{fingerprint.ErrNoMatch}}
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return v, nil }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	state := t.TempDir()
	err := Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: state, Cwd: root})
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("err = %v", err)
	}
	if v.Calls != 1 {
		t.Errorf("Verify calls = %d, want 1", v.Calls)
	}
	if f := approvedFiles(t, state); len(f) != 0 {
		t.Errorf("approval written: %v", f)
	}
}

func runDesktop(t *testing.T, v func(string) (fingerprint.Verifier, error), o Options) (*fakeIO, string, error) {
	t.Helper()
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = v
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"n", "n", "n"}}
	state := t.TempDir()
	o.Profile, o.IO, o.StateDir, o.Cwd = "uat", io, state, root
	return io, state, Run(context.Background(), o)
}

// Level 2 refuses the start-up widening flags before any prompt.
func TestRunLevel2RefusesWideningFlags(t *testing.T) {
	for name, o := range map[string]Options{"auto": {Auto: true}, "unmask": {AllowUnmask: true}, "results": {ShowResults: true}} {
		t.Run(name, func(t *testing.T) {
			v := &fingerprint.Fake{EnrolledN: 1}
			io, state, err := runDesktop(t, func(string) (fingerprint.Verifier, error) { return v, nil }, o)
			if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "level 2 does not accept --auto, --allow-unmask or --show-results") {
				t.Fatalf("err = %v", err)
			}
			if len(io.prompts) != 0 || v.Calls != 0 {
				t.Errorf("prompts %q, finger calls %d", io.prompts, v.Calls)
			}
			if f := approvedFiles(t, state); len(f) != 0 {
				t.Errorf("approval written: %v", f)
			}
		})
	}
}

// Level 1 takes the same flags, and approves by typed answer alone: no
// finger is ever asked.
func TestRunLevel1AcceptsFlagsAndTypes(t *testing.T) {
	io, _, err := runDesktop(t, func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable },
		Options{Auto: true, AllowUnmask: true, ShowResults: true})
	if err == nil || strings.Contains(err.Error(), "level 2") {
		t.Fatalf("err = %v", err)
	}
	if !containsLine(io, "desktop mode, level 1") || len(io.prompts) == 0 {
		t.Errorf("out %q prompts %q", io.out, io.prompts)
	}
}

// Level-1 approvals are audited apart from the session shape: the human
// typed them in a window the agent can type into.
func TestRunLevel1AuditsDesktopTyped(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	io := &fakeIO{answers: []string{"y"}}
	state := t.TempDir()
	_ = Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: state, Cwd: root})
	var log strings.Builder
	_ = filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "audit.log") {
			b, _ := os.ReadFile(p)
			log.Write(b)
		}
		return nil
	})
	if !strings.Contains(log.String(), `"event":"policy"`) || !strings.Contains(log.String(), `"approval":"desktop+typed"`) {
		t.Fatalf("audit log:\n%s", log.String())
	}
}
