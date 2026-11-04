//go:build unix

package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/config"
)

const prodConfig = `[profiles.prod]
engine = "mariadb"
host = "db.prod.example.com"
user = "alice"
production = true

[profiles.prod.limits]
max_rows = %d
`

// The production profile name is typed when a policy is approved, not at
// every start: a restart of an approved, unchanged production profile goes
// straight to the credentials (#178).
func TestRunProductionNameOnlyOnApproval(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	write := func(maxRows int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(prodConfig, "%d", itoa(maxRows), 1)
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
	const name = `Type the profile name "prod" to continue: `
	run := func(answers ...string) *fakeIO {
		t.Helper()
		io := &fakeIO{answers: answers}
		// Ends at the password prompt, which gets no answer.
		_ = Run(context.Background(), Options{Hub: runHub(t), Profile: "prod", IO: io, StateDir: state, Cwd: root})
		return io
	}
	asked := func(io *fakeIO, prompt string) bool {
		for _, p := range io.prompts {
			if strings.Contains(p, prompt) {
				return true
			}
		}
		return false
	}
	reachedPassword := func(t *testing.T, io *fakeIO) {
		t.Helper()
		if !asked(io, "Password for alice@db.prod.example.com") {
			t.Fatalf("the start did not reach the password:\n%s", strings.Join(io.transcript, "\n"))
		}
	}

	write(100)
	// First approval: the review, then the name.
	io := run("y", "nope")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("first start prompts: %q", io.prompts)
	}
	if asked(io, "Password for") {
		t.Fatal("a wrong name went on to the credentials")
	}
	// The name was not confirmed: the approved policy alone does not skip it.
	io = run("prod")
	if asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("after a wrong name, prompts: %q", io.prompts)
	}
	reachedPassword(t, io)

	// Plain restart: no name, the banner still shows.
	io = run()
	if asked(io, name) {
		t.Fatalf("restart of an unchanged approved profile asked the name: %q", io.prompts)
	}
	if !strings.Contains(io.output(), "PRODUCTION profile prod") {
		t.Errorf("no production banner:\n%s", io.output())
	}
	reachedPassword(t, io)

	// A tightening applies without a review, and without the name.
	write(50)
	io = run()
	if asked(io, "Apply these changes") || asked(io, name) {
		t.Fatalf("tightening prompts: %q", io.prompts)
	}
	reachedPassword(t, io)

	// A loosening is reviewed, and the name is asked again.
	write(500)
	io = run("y", "prod")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("loosening prompts: %q", io.prompts)
	}
	reachedPassword(t, io)
	io = run()
	if asked(io, name) {
		t.Fatalf("restart after the reviewed loosening asked the name: %q", io.prompts)
	}

	// A refused loosening keeps the approved policy, already confirmed.
	write(900)
	io = run("n")
	if !asked(io, "Apply these changes") || asked(io, name) {
		t.Fatalf("refused loosening prompts: %q", io.prompts)
	}
	reachedPassword(t, io)

	// Deleting the approval brings back the first-start review, and the
	// name with it, even for the very policy confirmed before.
	write(500)
	path, err := os.ReadDir(filepath.Join(state, "locksql", "approved"))
	if err != nil {
		t.Fatal(err)
	}
	key := config.ApprovedKey(root, "prod")
	for _, e := range path {
		if e.Name() == key+".json" {
			if err := os.Remove(filepath.Join(state, "locksql", "approved", e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	io = run("y", "prod")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("re-approval prompts: %q", io.prompts)
	}
	reachedPassword(t, io)
}
