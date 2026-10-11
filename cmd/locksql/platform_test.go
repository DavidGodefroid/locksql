package main

import (
	"bytes"
	"strings"
	"testing"
)

// On Windows every command but version and help refuses and names WSL2.
func TestWindowsRefusesCommands(t *testing.T) {
	saved := hostOS
	hostOS = "windows"
	t.Cleanup(func() { hostOS = saved })
	for _, args := range [][]string{nil, {"console"}, {"mcp"}, {"status"}, {"install"}, {"doctor"}, {"init"}, {"plan", "SELECT 1"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitFail {
			t.Errorf("%v: exit %d, want %d", args, code, exitFail)
		}
		if !strings.Contains(errOut.String(), "WSL2") || out.Len() != 0 {
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
