//go:build integration && linux

package integration

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/DavidGodefroid/locksql/internal/engine/sqlite"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// With the profile's ticket limit at 1 and one ticket pending, the next
// run is not submitted: the agent reads the limit it reached, when to
// retry, and what to do next, from that ask alone (#204).
func TestTicketLimitEndToEnd(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(project, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)", "INSERT INTO items VALUES (1, 'a'), (2, 'b')"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()
	conf := `[profiles.uat]
engine = "sqlite"
path = "app.db"

[profiles.uat.limits]
tickets_per_window = 1
ticket_window = "10m"
`
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_RUNTIME_DIR=" + runDir,
	}
	c := startConsole(t, project, env, "--profile", "uat")
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	// The database file is writable by this user: more than tier read needs.
	c.expect(`Type "continue" to proceed: `)
	c.send("continue\n")
	seen := c.expect("Listening…")
	m := socketLine.FindStringSubmatch(seen)
	if m == nil {
		t.Fatalf("no socket path in %q", seen)
	}
	cl := dialConsole(t, m[1])
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
		t.Fatal(e)
	}
	run := func(sql string) (ipc.RunResult, *ipc.RPCError) {
		t.Helper()
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "main", SQL: sql}, &pr); e != nil {
			t.Fatalf("plan %q: %v", sql, e)
		}
		var rr ipc.RunResult
		e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		return rr, e
	}
	if rr, e := run("SELECT id, label FROM items WHERE id = 1 LIMIT 1"); e != nil || rr.Status != "pending" || rr.Ticket == "" {
		t.Fatalf("first run: %+v %v", rr, e)
	}
	rr, e := run("SELECT id, label FROM items WHERE id = 2 LIMIT 1")
	if e == nil || e.Code != ipc.CodeInternal {
		t.Fatalf("second run over the limit: %+v %v", rr, e)
	}
	for _, s := range []string{"not submitted: ", "(limit 1, raised by limits.tickets_per_window)", "retry after ", "; plan the query again after that (the plan is used)"} {
		if !strings.Contains(e.Message, s) {
			t.Errorf("refusal %q does not say %q", e.Message, s)
		}
	}
	c.send("\x03")
	_ = c.wait()
}
