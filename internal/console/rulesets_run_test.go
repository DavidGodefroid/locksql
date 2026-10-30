//go:build unix

package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// With PIIDir (lock up: the profile's directory is a read-only copy), the
// console seeds its own rule sets from the profile once, reads them from
// PIIDir, and says when the profile's set has drifted from its copy.
func TestRunPIIDir(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	dir := filepath.Join(root, ".locksql")
	theirs := filepath.Join(dir, pii.SetsDir, "uat.toml")
	if err := os.MkdirAll(filepath.Dir(theirs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(theirs, []byte("[[mask]]\ncolumn = \"app.users.email\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	key := config.ApprovedKey(root, "uat")
	approved := config.NewPolicy(cfg.Profiles["uat"], []string{"app.users.email"}, nil)
	approved.Profile.PIIRules = "uat"
	if err := config.SaveApproved(state, key, approved); err != nil {
		t.Fatal(err)
	}
	// Read-only, as lock up's copy.
	for _, d := range []string{filepath.Dir(theirs), dir} {
		if err := os.Chmod(d, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(d, 0o755) })
	}
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	piiDir := filepath.Join(t.TempDir(), "pii-home")
	run := func(d string) (*fakeIO, error) {
		io := &fakeIO{}
		// Ends at the password prompt, which gets no answer.
		err := Run(context.Background(), Options{Profile: "uat", IO: io, StateDir: state, Cwd: root, PIIDir: d})
		return io, err
	}
	io, _ := run(piiDir)
	mine := filepath.Join(piiDir, pii.SetsDir, "uat.toml")
	if !strings.Contains(io.output(), "uat.toml copied from the profile") {
		t.Fatalf("no seed notice:\n%s", io.output())
	}
	if b, err := os.ReadFile(mine); err != nil || string(b) != "[[mask]]\ncolumn = \"app.users.email\"\n" {
		t.Fatalf("the console's set: %q, %v", b, err)
	}
	for _, p := range io.prompts {
		if strings.Contains(p, "Apply these changes") {
			t.Fatalf("the seeded set is not the one approved:\n%s", io.output())
		}
	}
	if strings.Contains(io.output(), "differs") {
		t.Fatalf("drift notice on identical sets:\n%s", io.output())
	}

	// The console's copy is in force: a rule it added stays, even though
	// the profile's set lacks it, and the drift is told.
	var r pii.Rules
	for _, pat := range []string{"app.users.email", "app.users.phone"} {
		if err := r.Add(pat); err != nil {
			t.Fatal(err)
		}
	}
	if err := pii.SaveRulesFile(mine, r); err != nil {
		t.Fatal(err)
	}
	approved = config.NewPolicy(approved.Profile, r.Mask, nil)
	if err := config.SaveApproved(state, key, approved); err != nil {
		t.Fatal(err)
	}
	io, _ = run(piiDir)
	if !strings.Contains(io.output(), "differs from this console's") || strings.Contains(io.output(), "copied from the profile") {
		t.Fatalf("no drift notice, or a second seed:\n%s", io.output())
	}
	for _, p := range io.prompts {
		if strings.Contains(p, "Apply these changes") {
			t.Fatalf("the profile's set was read instead of the console's:\n%s", io.output())
		}
	}

	// A mask rule added to the profile's set (a tightening lock up
	// reviewed) reaches the console's copy; an allow rule does not.
	for _, d := range []string{filepath.Dir(theirs), dir} {
		os.Chmod(d, 0o755)
	}
	if err := os.WriteFile(theirs, []byte("[[mask]]\ncolumn = \"app.users.email\"\n\n[[mask]]\ncolumn = \"app.users.iban\"\n\n[[allow]]\ncolumn = \"app.users.phone\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	io, _ = run(piiDir)
	if !strings.Contains(io.output(), "1 mask rules of the profile") || !strings.Contains(io.output(), "differs from this console's") {
		t.Fatalf("no merge or drift notice:\n%s", io.output())
	}
	got, err := pii.LoadRulesFile(mine)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Mask, []string{"app.users.email", "app.users.iban", "app.users.phone"}) && !slices.Equal(got.Mask, []string{"app.users.email", "app.users.phone", "app.users.iban"}) || len(got.Allow) != 0 {
		t.Fatalf("the console's set: %+v", got)
	}
	for _, p := range io.prompts {
		if strings.Contains(p, "Apply these changes") {
			t.Fatalf("a merged tightening asked for approval:\n%s", io.output())
		}
	}

	if _, err := run("relative/dir"); !errors.Is(err, ErrConfig) {
		t.Fatalf("relative PIIDir: %v", err)
	}
}
