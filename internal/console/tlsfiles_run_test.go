//go:build unix

package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// A tls_ca under "~/" that is absent from the console account's home stops
// the start right after the policy review: before the production name, the
// passphrase or the password is asked for (#194).
func TestRunMissingTLSFileBeforeSecrets(t *testing.T) {
	root, state, home := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `[profiles.prod]
engine = "postgres"
host = "db.prod.example.com"
user = "alice"
production = true
tls = "verify-full"
tls_ca = "~/.ssh/db-ca.pem"
`
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
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
		err := Run(context.Background(), Options{Hub: runHub(t), Profile: "prod", IO: io, StateDir: state, Cwd: root})
		return io, err
	}

	io, err := run("y", "prod")
	want := "tls_ca: " + filepath.Join(home, ".ssh", "db-ca.pem") + " not found in the console's home (" + home + ")"
	if err == nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), want) {
		t.Fatalf("missing tls_ca: err = %v, want %q", err, want)
	}
	prompts := strings.Join(io.prompts, "\n")
	if !strings.Contains(prompts, "Apply these changes") {
		t.Fatalf("the policy review was not shown first: %q", io.prompts)
	}
	if strings.Contains(prompts, "Type the profile name") || strings.Contains(prompts, "Password for") {
		t.Fatalf("a question followed the policy review before the missing tls_ca was reported: %q", io.prompts)
	}

	// Once copied there, the start goes on to the name and the password.
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "db-ca.pem"), []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	io, _ = run("prod")
	if !strings.Contains(strings.Join(io.prompts, "\n"), "Password for alice@db.prod.example.com") {
		t.Fatalf("with tls_ca present, the start did not reach the password: %q", io.prompts)
	}
}
