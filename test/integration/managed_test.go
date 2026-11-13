//go:build integration && linux && lockfamily_managed_test

package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The console built with lockfamily_managed_test reads the managed file at
// LOCKSQL_TEST_MANAGED (cmd/locksql/managed_testhook.go).
func init() { buildTags += ",lockfamily_managed_test" }

// managedSetup is a project, its console environment and a managed file.
type managedSetup struct {
	home, project, managedPath string
	env                        []string
	port                       int
}

func newManagedSetup(t *testing.T, port int, body string) *managedSetup {
	t.Helper()
	home := t.TempDir()
	s := &managedSetup{home: home, project: filepath.Join(home, "proj"), managedPath: filepath.Join(home, "managed.toml"), port: port}
	if err := os.MkdirAll(filepath.Join(s.project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.env = []string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_RUNTIME_DIR=" + runDir,
		"LOCKSQL_TEST_MANAGED=" + s.managedPath,
	}
	s.writeManaged(t, body)
	return s
}

func (s *managedSetup) writeManaged(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(s.managedPath, []byte("version = 1\norganisation = \"Acme\"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeProfile writes the project's profile dev at tier.
func (s *managedSetup) writeProfile(t *testing.T, tier string) {
	t.Helper()
	c := fmt.Sprintf("[profiles.dev]\nengine = \"postgres\"\nhost = \"127.0.0.1\"\nport = %d\nuser = \"ro\"\ndatabase = \"app\"\ntier = %q\n", s.port, tier)
	if err := os.WriteFile(filepath.Join(s.project, ".locksql", "config.toml"), []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *managedSetup) auditLog() string {
	b, _ := os.ReadFile(filepath.Join(s.home, "state", "locksql", "audit.log"))
	return string(b)
}

// listen answers the start-up questions until the console listens, and
// returns its socket.
func listen(t *testing.T, c *consoleProc) string {
	t.Helper()
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
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the console never listened")
		}
		time.Sleep(50 * time.Millisecond)
	}
	m := socketLine.FindStringSubmatch(c.expect("Listening…"))
	if m == nil {
		t.Fatal("no socket path")
	}
	return m[1]
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

// Under [locksql.bounds] tier = "write": a ddl profile is refused at start
// with no prompt and audited refused-managed; a write profile starts, its
// approval carries managed_sha256, an edit to ddl while it runs is refused
// at the next poll, and a DDL statement stays refused.
func TestManagedTierBound(t *testing.T) {
	srv := startPostgresVariant(t, "17", "managed-tier")
	s := newManagedSetup(t, srv.Port, "[locksql.bounds]\ntier = \"write\"\n")

	s.writeProfile(t, "ddl")
	c := startConsole(t, s.project, s.env, "--profile", "dev")
	c.expect("blocked by company policy: locksql.bounds.tier = write (profile dev: tier = ddl)")
	if code := exitCode(c.wait()); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
	if strings.Contains(c.output(), "Apply these changes?") {
		t.Fatal("a prompt before the managed refusal")
	}
	if !strings.Contains(s.auditLog(), `"decision":"refused-managed"`) {
		t.Fatalf("audit: %s", s.auditLog())
	}

	s.writeProfile(t, "write")
	c = startConsole(t, s.project, s.env, "--profile", "dev")
	c.expect("Managed by Acme (sha256:")
	sock := listen(t, c)
	key := config.ApprovedKey(s.project, "dev")
	b, err := os.ReadFile(filepath.Join(s.home, "state", "locksql", "approved", key+".json"))
	if err != nil || !strings.Contains(string(b), `"managed_sha256"`) {
		t.Fatalf("approved policy: %s %v", b, err)
	}

	s.writeProfile(t, "ddl")
	c.expect("refused by the company's managed configuration")
	c.expect("blocked by company policy: locksql.bounds.tier = write (profile dev: tier = ddl)")
	cl := dialConsole(t, sock)
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
		t.Fatal(e)
	}
	var pr ipc.PlanResult
	e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "CREATE TABLE x (id int)"}, &pr)
	if e == nil || !strings.Contains(e.Message, "tier") {
		t.Fatalf("DDL under the managed tier: %+v %v", pr, e)
	}
}

// A managed profile is served, and a query through it works; a user
// profile of its name makes the load fail.
func TestManagedProfile(t *testing.T) {
	srv := startPostgresVariant(t, "17", "managed-profile")
	s := newManagedSetup(t, srv.Port, fmt.Sprintf("[locksql.profiles.prod-erp]\nengine = \"postgres\"\nhost = \"127.0.0.1\"\nport = %d\nuser = \"ro\"\ndatabase = \"app\"\n", srv.Port))
	s.writeProfile(t, "read")

	c := startConsole(t, s.project, s.env, "--profile", "prod-erp")
	sock := listen(t, c)
	cl := dialConsole(t, sock)
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
		t.Fatal(e)
	}
	var pr ipc.PlanResult
	if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM small WHERE id = 1 LIMIT 1"}, &pr); e != nil {
		t.Fatalf("plan: %v", e)
	}
	var rr ipc.RunResult
	if e := cl.run(c.hub, pr.PlanID, &rr); e != nil {
		t.Fatalf("run: %v", e)
	}
	_ = c.cmd.Process.Kill()
	_ = c.wait()

	user := filepath.Join(s.home, "config", "locksql", "config.toml")
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte("[profiles.prod-erp]\nengine = \"sqlite\"\npath = \"x.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c = startConsole(t, s.project, s.env, "--profile", "prod-erp")
	c.expect(`profile "prod-erp" is provided by the company's managed configuration and cannot be redefined in the user config`)
	if code := exitCode(c.wait()); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
}
