//go:build firstquery && linux

// Package firstquery checks the README's quick start end to end and
// without a human, through the launcher and the image: locksql init,
// profile add and doctor --fix, then locksql console in a terminal. The
// agent's two calls (plan, run) and the human's approval in the console
// follow; approval stays a keystroke in the console's terminal, which the
// test types as the human would. It uses Docker volumes (locksql-run,
// locksql-home) and the container name locksql-console: CI runs it on a
// throwaway runner.
//
//	docker build -t locksql .
//	LOCKSQL_FIRSTQUERY=1 LOCKSQL_FIRSTQUERY_LAUNCHER=$PWD/scripts/locksql \
//	  go test -tags firstquery -v ./test/firstquery/
//
// The launcher of a clone runs the image tagged locksql (LOCKSQL_IMAGE
// overrides it).
package firstquery

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	_ "modernc.org/sqlite"
)

// launcher is the locksql launcher under test (scripts/locksql).
var launcher string

// human runs one of the human's commands through the launcher and logs it
// as typed; ok lists the exit codes that pass.
func human(t *testing.T, n int, dir string, args []string, ok ...int) {
	t.Helper()
	t.Logf("command %d: locksql %s", n, strings.Join(args, " "))
	cmd := exec.Command("sh", append([]string{launcher}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	code := cmd.ProcessState.ExitCode()
	for _, c := range append(ok, 0) {
		if code == c {
			return
		}
	}
	t.Fatalf("command %d failed: %v", n, err)
}

// agent runs a client command as the agent does: the launcher, which runs
// it in the image as the agent account.
func agent(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	t.Logf("agent: locksql %s", strings.Join(args, " "))
	cmd := exec.Command("sh", append([]string{launcher}, args...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

// screen collects the console's terminal output.
type screen struct {
	mu   sync.Mutex
	buf  strings.Builder
	done chan struct{} // closed when the console exits
	err  error         // the console's exit, once done is closed
}

func (s *screen) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }

// waitFor waits until one of the prompts appears after offset from, and
// returns which one and the new offset.
func (s *screen) waitFor(t *testing.T, from int, d time.Duration, prompts ...string) (string, int) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out := s.String()
		best, at := "", -1
		for _, p := range prompts {
			if i := strings.Index(out[from:], p); i >= 0 && (at < 0 || i < at) {
				best, at = p, i
			}
		}
		if at >= 0 {
			return best, from + at + len(best)
		}
		select {
		case <-s.done:
			t.Fatalf("console: exited (%v) before %q; screen:\n%s", s.err, prompts, s.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("console: none of %q within %s; screen:\n%s", prompts, d, s.String())
	return "", 0
}

func TestFirstQueryThroughTheLauncher(t *testing.T) {
	if os.Getenv("LOCKSQL_FIRSTQUERY") != "1" {
		t.Skip("set LOCKSQL_FIRSTQUERY=1 on a throwaway machine: this test uses Docker volumes and the container locksql-console")
	}
	launcher = os.Getenv("LOCKSQL_FIRSTQUERY_LAUNCHER")
	if launcher == "" {
		t.Fatal("LOCKSQL_FIRSTQUERY_LAUNCHER: the launcher, scripts/locksql")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as your own account, not as root")
	}

	// A project with a SQLite database, where every account may enter.
	project, err := os.MkdirTemp("", "locksql-demo-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(project, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(project, "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE orders (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL, placed TEXT NOT NULL)",
		"INSERT INTO orders (amount, placed) VALUES (10, '2026-10-01'), (25, '2026-10-02'), (7, '2026-10-02')",
		"ANALYZE",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	if err := os.Chmod(filepath.Join(project, "demo.db"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The human's commands of the quick start: the agent's files, a
	// profile, then .locksql/ given to the console account (doctor --fix
	// exits 1: the console's checks fail from its container, which runs
	// none).
	human(t, 1, project, []string{"init", "claude"})
	human(t, 2, project, []string{"profile", "add", "--profile", "dev", "--engine", "sqlite", "--path", "demo.db"})
	human(t, 3, project, []string{"doctor", "--fix", "--yes"}, 1)

	// The console, in a terminal: the launcher runs it as the console
	// account, in its own container.
	t.Log("command 4: locksql console")
	cmd := exec.Command("sh", launcher, "console")
	cmd.Dir = project
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 160})
	if err != nil {
		t.Fatal(err)
	}
	scr := &screen{done: make(chan struct{})}
	go func() { scr.err = cmd.Wait(); close(scr.done) }()
	go func() {
		r := bufio.NewReader(tty)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			scr.mu.Lock()
			scr.buf.Write(buf[:n])
			scr.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		tty.Write([]byte{3}) // Ctrl-C ends the session
		select {
		case <-scr.done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
		}
		tty.Close()
		t.Logf("console screen:\n%s", scr.String())
	}()

	// First start: approve the policy, answer the PII scan if it asks.
	at := 0
	for {
		var got string
		got, at = scr.waitFor(t, at, time.Minute, "Apply these changes? [y/N] ", "Accept all [a], review [r], skip [s]: ", "Listening…")
		if got == "Listening…" {
			break
		}
		if strings.HasPrefix(got, "Apply") {
			tty.Write([]byte("y\n"))
		} else {
			tty.Write([]byte("a\n"))
		}
	}

	// The agent plans a query, then runs it; the human approves it.
	out, err := agent(t, project, "plan", "--profile", "dev", "--db", "main", "--json", "SELECT count(*) AS n, sum(amount) AS total FROM orders LIMIT 1")
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	var plan struct {
		PlanID  string `json:"plan_id"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil || plan.PlanID == "" {
		t.Fatalf("plan output %q: %v", out, err)
	}
	t.Logf("plan %s, verdict %s", plan.PlanID, plan.Verdict)
	type result struct {
		out string
		err error
	}
	ran := make(chan result, 1)
	go func() {
		out, err := agent(t, project, "run", "--profile", "dev", "--json", plan.PlanID)
		ran <- result{out, err}
	}()
	_, at = scr.waitFor(t, at, time.Minute, "Approve? [y/N] ")
	tty.Write([]byte("y\n"))
	var res result
	select {
	case res = <-ran:
	case <-time.After(time.Minute):
		t.Fatal("run: no answer a minute after the approval")
	}
	if res.err != nil {
		t.Fatalf("run: %v\n%s", res.err, res.out)
	}
	var rows struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.Unmarshal([]byte(res.out), &rows); err != nil {
		t.Fatalf("run output %q: %v", res.out, err)
	}
	if len(rows.Rows) != 1 || fmt.Sprint(rows.Rows[0]) != "[3 42]" {
		t.Fatalf("first query: %v %v, want [[3 42]]", rows.Columns, rows.Rows)
	}
	t.Logf("first approved query: %v %v", rows.Columns, rows.Rows)
}
