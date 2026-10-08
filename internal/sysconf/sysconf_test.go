package sysconf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func withFile(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "system.toml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := Path
	Path = p
	t.Cleanup(func() { Path = old })
}

func TestLoadAbsent(t *testing.T) {
	old := Path
	Path = filepath.Join(t.TempDir(), "none.toml")
	defer func() { Path = old }()
	c, err := Load()
	if c != nil || err != nil {
		t.Fatalf("Load = %v, %v", c, err)
	}
}

func TestLoadRefusesFileNotOwnedByRoot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a non-root Unix account")
	}
	withFile(t, "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("Load = %v", err)
	}
}

func TestLoadDefaultsAndValidation(t *testing.T) {
	SkipOwnerCheck = true
	defer func() { SkipOwnerCheck = false }()
	withFile(t, "allowed_uids = [1000]\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServiceUser != DefaultServiceUser || c.ClientGroup != DefaultClientGroup || c.SocketDir != DefaultSocketDir() || c.X11 != X11Warn {
		t.Errorf("defaults: %+v", c)
	}
	if !c.ClientAllowed(1000) {
		t.Error("allowed uid refused")
	}
	for _, bad := range []string{"x11 = \"maybe\"\n", "socket_dir = \"run\"\n", "unknown = 1\n"} {
		withFile(t, bad)
		if _, err := Load(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDetectDisplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux display detection")
	}
	defer func() { getenv = os.Getenv }()
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"XDG_SESSION_TYPE": "wayland", "WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, DisplayWayland},
		{map[string]string{"XDG_SESSION_TYPE": "x11", "DISPLAY": ":0"}, DisplayX11},
		{map[string]string{"DISPLAY": ":0"}, DisplayX11},
		{map[string]string{"XDG_SESSION_TYPE": "wayland", "DISPLAY": ":1"}, DisplayX11},
		{map[string]string{"XDG_SESSION_TYPE": "tty"}, DisplayTTY},
		{map[string]string{}, DisplayTTY},
	}
	for _, c := range cases {
		getenv = func(k string) string { return c.env[k] }
		if got := DetectDisplay(); got.Kind != c.want {
			t.Errorf("%v: %s, want %s", c.env, got.Kind, c.want)
		}
	}
}

func TestProcReaders(t *testing.T) {
	dir := t.TempDir()
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()
	for path, v := range map[string]string{
		"self/loginuid":                "4294967295\n",
		"sys/dev/tty/legacy_tiocsti":   "0\n",
		"sys/kernel/yama/ptrace_scope": "1\n",
	} {
		p := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if uid, ok := LoginUID(); !ok || uid != -1 {
		t.Errorf("LoginUID = %d %v", uid, ok)
	}
	if on, ok := LegacyTIOCSTI(); !ok || on {
		t.Errorf("LegacyTIOCSTI = %v %v", on, ok)
	}
	if s, ok := PtraceScope(); !ok || s != 1 {
		t.Errorf("PtraceScope = %d %v", s, ok)
	}
}
