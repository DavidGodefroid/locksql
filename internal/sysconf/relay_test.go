package sysconf

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fakeProc points procRoot and sessionsRoot at temporary directories.
func fakeProc(t *testing.T) (proc, sessions string) {
	t.Helper()
	proc, sessions = t.TempDir(), t.TempDir()
	oldP, oldS := procRoot, sessionsRoot
	procRoot, sessionsRoot = proc, sessions
	t.Cleanup(func() { procRoot, sessionsRoot = oldP, oldS })
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return proc, sessions
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRelay(t *testing.T) {
	for _, tc := range []struct {
		name, cgroup, session, want string
	}{
		{"desktop", "0::/user.slice/user-900.slice/session-2.scope\n", "REMOTE=0\nTYPE=wayland\nSERVICE=gdm-password\n", ""},
		{"machinectl shell", "0::/system.slice/system-container\\x2dshell.slice/container-shell@3.service\n", "REMOTE=0\nSERVICE=login\n", RelayMachinectl},
		{"ssh from 127.0.0.1", "0::/user.slice/user-900.slice/session-7.scope\n", "REMOTE=1\nREMOTE_HOST=127.0.0.1\nSERVICE=sshd\n", RelaySSHLoopback},
		{"ssh from ::1", "0::/user.slice/session-7.scope\n", "REMOTE=1\nREMOTE_HOST=::1\n", RelaySSHLoopback},
		{"ssh from localhost", "0::/user.slice/session-7.scope\n", "REMOTE=1\nREMOTE_HOST=localhost\n", RelaySSHLoopback},
		{"ssh from another machine", "0::/user.slice/session-7.scope\n", "REMOTE=1\nREMOTE_HOST=192.0.2.7\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proc, sessions := fakeProc(t)
			write(t, filepath.Join(proc, "self", "cgroup"), tc.cgroup)
			write(t, filepath.Join(proc, "self", "sessionid"), "7")
			write(t, filepath.Join(sessions, "7"), tc.session)
			if got := SessionRelay(); got != tc.want {
				t.Errorf("SessionRelay() = %q, want %q", got, tc.want)
			}
		})
	}
	// No session, or a session id that is not a plain number.
	proc, sessions := fakeProc(t)
	write(t, filepath.Join(sessions, "x"), "REMOTE=1\nREMOTE_HOST=127.0.0.1\n")
	for _, sid := range []string{"4294967295", "../x", ""} {
		write(t, filepath.Join(proc, "self", "sessionid"), sid)
		if got := SessionRelay(); got != "" {
			t.Errorf("sessionid %q: %q", sid, got)
		}
	}
}

func TestMachinectlShellUIDs(t *testing.T) {
	proc, _ := fakeProc(t)
	pid := func(n, cmdline, uid string) {
		write(t, filepath.Join(proc, n, "cmdline"), cmdline)
		write(t, filepath.Join(proc, n, "status"), "Name:\tx\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
	}
	pid("10", "machinectl\x00shell\x00locksql@\x00", "1000")
	pid("11", "/usr/bin/machinectl\x00-q\x00login\x00", "1500")
	pid("12", "machinectl\x00list\x00", "1600")             // not a shell
	pid("13", "bash\x00-c\x00machinectl shell\x00", "1700") // not machinectl
	uids, ok := MachinectlShellUIDs()
	slices.Sort(uids)
	if !ok || !slices.Equal(uids, []int{1000, 1500}) {
		t.Errorf("uids %v, %v", uids, ok)
	}
}
