//go:build unix

package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// At start the console shows the auto rules in force; connect = deny
// never connects; loosening a production profile's auto rules is reviewed
// and takes the typed profile name.
func TestRunAutoRulesAtStart(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	write := func(auto string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
			t.Fatal(err)
		}
		body := "[profiles.prod]\nengine = \"mariadb\"\nhost = \"db.prod.example.com\"\nuser = \"alice\"\nproduction = true\n" + auto
		if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	run := func(answers ...string) (*fakeIO, error) {
		t.Helper()
		io := &fakeIO{answers: answers}
		// Ends at the password prompt, which gets no answer.
		err := Run(context.Background(), Options{Hub: runHub(t), Profile: "prod", IO: io, StateDir: state, Cwd: root})
		return io, err
	}
	asked := func(io *fakeIO, prompt string) bool {
		for _, p := range io.prompts {
			if strings.Contains(p, prompt) {
				return true
			}
		}
		return false
	}
	const name = `Type the profile name "prod"`

	write("[profiles.prod.auto]\nddl = \"deny\"\n")
	io, _ := run("y", "prod")
	if !strings.Contains(io.output(), "auto mode (lox run): connect ask · read auto · write ask · ddl deny · unmask ask") {
		t.Fatalf("the rules in force are not shown:\n%s", io.output())
	}
	if !asked(io, "Password for alice@db.prod.example.com") {
		t.Fatalf("did not reach the password: %q", io.prompts)
	}

	// Loosening to full-auto: reviewed, the name typed again.
	write("auto = \"full-auto\"\n")
	io, _ = run("y", "nope")
	if !asked(io, "Apply these changes") || !asked(io, name) || asked(io, "Password for") {
		t.Fatalf("loosening with a wrong name, prompts: %q", io.prompts)
	}
	if !strings.Contains(io.output(), "auto.ddl: deny → auto  (loosens)") {
		t.Errorf("the loosening is not listed:\n%s", io.output())
	}
	io, _ = run("prod")
	if !asked(io, "Password for") || !strings.Contains(io.output(), "(full-auto)") {
		t.Fatalf("after the typed name: prompts %q\n%s", io.prompts, io.output())
	}

	// connect = deny (a tightening): applied at once, never connected.
	write("[profiles.prod.auto]\nconnect = \"deny\"\n")
	io, err := run()
	if err == nil || !strings.Contains(err.Error(), "auto.connect = deny") || asked(io, "Password for") {
		t.Fatalf("connect = deny: %v, prompts %q", err, io.prompts)
	}
	b, rerr := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if rerr != nil || !strings.Contains(string(b), `"auto_rule":"auto.connect = deny"`) {
		t.Fatalf("audit (%v):\n%s", rerr, b)
	}
}
