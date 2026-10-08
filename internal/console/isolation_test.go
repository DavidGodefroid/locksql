package console

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

func fakeIsolation(sys *sysconf.Config, display string) isolationEnv {
	return isolationEnv{
		loadSys:       func() (*sysconf.Config, error) { return sys, nil },
		display:       func() sysconf.Display { return sysconf.Display{Kind: display, Detail: display} },
		uid:           func() int { return 900 },
		userName:      func() (string, error) { return "locksql", nil },
		loginUID:      func() (int, bool) { return 900, true },
		terminalOwner: func() (int, bool) { return 900, true },
		clientAllowed: func(_ *sysconf.Config, uid int) bool { return uid == 1000 },
		clientGID:     func(*sysconf.Config) (int, error) { return 950, nil },
		tiocsti:       func() (bool, bool) { return true, true },
	}
}

func separated() *sysconf.Config {
	return &sysconf.Config{ServiceUser: "locksql", ClientGroup: "locksql-clients", SocketDir: "/run/locksql", X11: sysconf.X11Warn}
}

func TestIsolationSameUser(t *testing.T) {
	io := &fakeIO{}
	iso, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayWayland), uatProfile())
	if err != nil {
		t.Fatal(err)
	}
	out := io.output()
	if !strings.Contains(out, "same-user mode") || !strings.Contains(out, "TIOCSTI") {
		t.Errorf("same-user warnings missing:\n%s", out)
	}
	if iso.peerCheck() != nil {
		t.Error("same-user mode must keep the default peer check")
	}
}

func TestIsolationX11(t *testing.T) {
	io := &fakeIO{}
	if _, err := checkIsolation(io, fakeIsolation(nil, sysconf.DisplayX11), uatProfile()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(io.output(), "X11") {
		t.Errorf("no X11 warning:\n%s", io.output())
	}
	prod := uatProfile()
	prod.Production = true
	if _, err := checkIsolation(&fakeIO{}, fakeIsolation(nil, sysconf.DisplayX11), prod); err == nil {
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
	}
	for name, mutate := range cases {
		env := fakeIsolation(separated(), sysconf.DisplayWayland)
		mutate(&env)
		if _, err := checkIsolation(&fakeIO{}, env, uatProfile()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
