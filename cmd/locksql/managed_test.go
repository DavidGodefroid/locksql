//go:build lockfamily_managed_test

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// The output and exit codes of `locksql managed show|check` and doctor's
// managed line are a contract (lox runs managed check before it starts the
// lock): kept by the goldens of testdata/managed.

var updateManaged = flag.Bool("update-managed", false, "rewrite the goldens of testdata/managed")

const managedBody = `version = 1
organisation = "Acme"

[locksql.bounds]
tier = "write"
tls = "verify-full"
credentials = ["vault", "ask"]
hosts = ["*.example.internal"]
auto = { ddl = "deny" }
detectors = ["fr_nir"]
limits = { max_rows = 500, max_session = "2h" }

[[locksql.bounds.pii_mask]]
column = "app.users.email"

[locksql.defaults]
limits = { max_rows = 100, max_session = "2h" }

[locksql.profiles.prod-erp]
engine = "postgres"
host = "erp.example.internal"
tls = "verify-full"
production = true
auto = { ddl = "deny" }
`

const managedProject = `[profiles.dev]
engine = "postgres"
host = "db.example.internal"
tls = "verify-full"
auto = { ddl = "deny" }
`

// withManaged places body as the machine's managed file ("" for none) and
// returns its directory.
func withManaged(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, managed.FileName)
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	return dir
}

// managedRun runs locksql in a project holding cfg, and renders the
// outcome as its golden holds it.
func managedRun(t *testing.T, dir, cfg string, args ...string) string {
	t.Helper()
	newMachine(t)
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runEnv(env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, cwd: project}, args)
	s := fmt.Sprintf("exit %d\n== stdout\n%s== stderr\n%s", code, out.String(), errb.String())
	return strings.ReplaceAll(s, dir, "<dir>")
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "managed", name+".golden")
	if *updateManaged {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-managed)", err)
	}
	if got != string(want) {
		t.Fatalf("%s:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestManagedGoldens(t *testing.T) {
	violation := strings.Replace(managedProject, "tls = \"verify-full\"\n", "tier = \"ddl\"\ntls = \"require\"\n", 1)
	for _, tc := range []struct {
		name, body, cfg string
		args            []string
	}{
		{"show-none", "", managedProject, []string{"managed", "show"}},
		{"show-file", managedBody, managedProject, []string{"managed", "show"}},
		{"show-refused", "version = 2\n", managedProject, []string{"managed", "show"}},
		{"check-none", "", managedProject, []string{"managed", "check"}},
		{"check-ok", managedBody, managedProject, []string{"managed", "check"}},
		{"check-profile", managedBody, violation, []string{"managed", "check", "--profile", "prod-erp"}},
		{"check-violation", managedBody, violation, []string{"managed", "check"}},
		{"check-redefined", managedBody, "[profiles.prod-erp]\nengine = \"sqlite\"\npath = \"x.db\"\n", []string{"managed", "check"}},
		{"check-refused", "[locksql]\n", managedProject, []string{"managed", "check"}},
		{"usage", "", managedProject, []string{"managed", "fly"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := withManaged(t, tc.body)
			golden(t, tc.name, managedRun(t, dir, tc.cfg, tc.args...))
		})
	}
}

func TestManagedDoctorLine(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"doctor-none", ""},
		{"doctor-file", managedBody},
		{"doctor-refused", "version = 1\n[locksql.bounds]\ntier = \"root\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := withManaged(t, tc.body)
			c := managedCheck()
			got := strings.ReplaceAll(fmt.Sprintf("%s %s — %s\n", c.state, c.title, c.detail), dir, "<dir>")
			golden(t, tc.name, got)
		})
	}
}
