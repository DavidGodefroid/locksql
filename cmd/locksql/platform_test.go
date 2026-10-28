package main

import (
	"bytes"
	"strings"
	"testing"
)

// On Windows every command but version and help refuses and names Docker.
func TestWindowsRefusesCommands(t *testing.T) {
	saved := hostOS
	hostOS = "windows"
	t.Cleanup(func() { hostOS = saved })
	for _, args := range [][]string{nil, {"console"}, {"mcp"}, {"status"}, {"install"}, {"update"}, {"doctor"}, {"init"}, {"plan", "SELECT 1"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitFail {
			t.Errorf("%v: exit %d, want %d", args, code, exitFail)
		}
		if !strings.Contains(errOut.String(), "docs/docker.md") || out.Len() != 0 {
			t.Errorf("%v: stdout %q stderr %q", args, out.String(), errOut.String())
		}
	}
	for _, args := range [][]string{{"version"}, {"help"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitOK {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// The host install, its update and its setup are refused: locksql runs in
// Docker, and the launcher on the host updates itself.
func TestHostModeCommandsRefused(t *testing.T) {
	for _, args := range [][]string{{"install"}, {"install", "--yes"}, {"setup"}, {"update"}, {"update", "--yes"}} {
		var out, errOut bytes.Buffer
		e := env{stdout: &out, stderr: &errOut, cwd: t.TempDir()}
		if code := runEnv(e, args); code != exitFail {
			t.Errorf("%v: exit %d, want %d", args, code, exitFail)
		}
		if !strings.Contains(errOut.String(), "runs in Docker") || !strings.Contains(errOut.String(), "docs/docker.md") || out.Len() != 0 {
			t.Errorf("%v: stdout %q stderr %q", args, out.String(), errOut.String())
		}
	}
}

// Bare locksql prints the help, in a terminal too: there is no host setup
// left to lead to.
func TestBareLocksqlPrintsUsageInTerminal(t *testing.T) {
	var out, errOut bytes.Buffer
	e := env{stdout: &out, stderr: &errOut, cwd: t.TempDir(), tty: true}
	if code := runEnv(e, nil); code != exitUsage || !strings.Contains(errOut.String(), "usage") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

// The help names no host install: setup and install are gone, update is
// the launcher's.
func TestHelpHasNoHostInstall(t *testing.T) {
	for _, gone := range []string{"\n  setup ", "\n  install ", "\n  locksql ", "/usr/local/bin/locksql", "separated setup"} {
		if strings.Contains(usageText, gone) {
			t.Errorf("help still names %q:\n%s", gone, usageText)
		}
	}
}
