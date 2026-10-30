//go:build integration && linux

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A console started on a non-production profile in an X11 session (only
// warned) ends its session when the policy in force becomes production:
// the start-up refusal of X11 on production is applied again (#93).
func TestBecomingProductionInX11EndsSession(t *testing.T) {
	srv := startPostgresVariant(t, "17", "prodx11")
	if _, err := buildLocksql(); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := func(prod bool) {
		t.Helper()
		c := fmt.Sprintf("[profiles.uat]\nengine = \"postgres\"\nhost = \"127.0.0.1\"\nport = %d\nuser = \"ro\"\ndatabase = \"app\"\n", srv.Port)
		if prod {
			c += "production = true\n"
		}
		if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	conf(false)
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_RUNTIME_DIR=" + runDir,
		"XDG_SESSION_TYPE=x11", "DISPLAY=:99",
	}
	c := startConsole(t, project, env, "--profile", "uat")
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	c.expect("Password for ro@127.0.0.1: ")
	c.send(ROPassword + "\n")
	deadline := time.Now().Add(60 * time.Second)
	for {
		o := c.output()
		if strings.Contains(o[c.mark:], "Accept all [a]") {
			c.expect("Accept all [a], review [r], skip [s]: ")
			c.send("a\n")
		}
		if strings.Contains(o[c.mark:], "Listening…") {
			c.expect("Listening…")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the console never listened")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(c.output(), "X11") {
		t.Fatal("no X11 warning at start")
	}
	conf(true) // a tightening: applied at once
	c.expect("the profile is now production")
	c.expect("refused after the profile became production")
	_ = c.wait()
}
