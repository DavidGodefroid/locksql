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
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// At the first start after the upgrade, the legacy pii.toml becomes the
// default set once, with a notice; a profile approved before keeps it
// without a new approval, and its approval then names the set.
func TestRunMigratesLegacyRules(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	legacy := filepath.Join(root, ".locksql", "pii.toml")
	if err := os.WriteFile(legacy, []byte("[[mask]]\ncolumn = \"app.users.email\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	key := config.ApprovedKey(root, "uat")
	if err := config.SaveApproved(state, key, config.NewPolicy(cfg.Profiles["uat"], []string{"app.users.email"}, nil)); err != nil {
		t.Fatal(err)
	}
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })

	run := func() *fakeIO {
		io := &fakeIO{}
		// Ends at the password prompt, which gets no answer.
		_ = Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: state, Cwd: root})
		return io
	}
	io := run()
	if !strings.Contains(io.output(), "moved to the set \"default\"") {
		t.Fatalf("no migration notice:\n%s", io.output())
	}
	for _, p := range io.prompts {
		if strings.Contains(p, "Apply these changes") {
			t.Fatalf("migration asked for approval:\n%s", io.output())
		}
	}
	ap, err := config.LoadApproved(state, key)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Profile.PIIRules != pii.DefaultSet {
		t.Fatalf("approved set = %q", ap.Profile.PIIRules)
	}
	if !strings.Contains(io.output(), `PII rules "default"`) {
		t.Errorf("profile line does not name the set:\n%s", io.output())
	}

	// Once only.
	if io := run(); strings.Contains(io.output(), "moved to the set") {
		t.Fatalf("notice again:\n%s", io.output())
	}
}
