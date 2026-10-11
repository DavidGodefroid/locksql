//go:build firstquery && linux

// Package firstquery checks the README's "first query in 3 commands" path
// on a fresh Linux machine, end to end and without a human: CI runs it on
// a throwaway runner (or container) where this account has password-less
// sudo. It changes the machine (an account, a group, /usr/local/bin,
// /etc/locksql): never run it on yours.
//
//	LOCKSQL_FIRSTQUERY=1 LOCKSQL_FIRSTQUERY_BIN=/path/to/locksql \
//	  go test -tags firstquery -v ./test/firstquery/
//
// The three commands are the human's: install the binary, locksql setup,
// locksql console in the console account. The agent's two calls (plan,
// run) and the human's approval in the console follow; approval stays a
// keystroke in the console's terminal, which the test types as the human
// would.
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

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// human runs one of the human's commands and logs it as typed.
func human(t *testing.T, n int, dir string, name string, args ...string) {
	t.Helper()
	t.Logf("command %d: %s %s", n, name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("command %d failed: %v", n, err)
	}
}

// agent runs a client command as the agent's account would after logging
// in again: with the client group that setup just gave it.
func agent(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	words := []string{"locksql"}
	for _, a := range args {
		words = append(words, shellQuote(a))
	}
	line := "cd " + shellQuote(dir) + " && " + strings.Join(words, " ")
	t.Logf("agent: %s", strings.Join(words, " "))
	out, err := exec.Command("sg", "locksql-clients", "-c", line).CombinedOutput()
	return string(out), err
}

// screen collects the console's terminal output.
type screen struct {
	mu   sync.Mutex
	buf  strings.Builder
	done chan struct{} // closed when the console exits
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
			t.Fatalf("console: exited before %q; screen:\n%s", prompts, s.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("console: none of %q within %s; screen:\n%s", prompts, d, s.String())
	return "", 0
}

func TestFirstQueryInThreeCommands(t *testing.T) {
	if os.Getenv("LOCKSQL_FIRSTQUERY") != "1" {
		t.Skip("set LOCKSQL_FIRSTQUERY=1 on a throwaway machine: this test installs locksql system-wide")
	}
	bin := os.Getenv("LOCKSQL_FIRSTQUERY_BIN")
	if bin == "" {
		t.Fatal("LOCKSQL_FIRSTQUERY_BIN: the locksql binary to install")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as the agent's account (with sudo), not as root")
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

	// 1. Install the binary (what scripts/install.sh does with a release).
	human(t, 1, project, "sudo", "install", "-m", "0755", bin, "/usr/local/bin/locksql")
	// 2. Set up: the console account, the agents, the profile, the access.
	human(t, 2, project, "locksql", "setup", "--yes", "--engine", "sqlite", "--path", "demo.db")

	// 3. The console, in the console account and a terminal of its own:
	// script(1) run as the console account gives it a terminal the agent's
	// account does not own. A process of a login session of the agent's
	// account would be refused by the console (that session shares the
	// human's display and terminal): there, a transient systemd service
	// stands in for the console account's own session.
	console := []string{"sudo", "-u", "locksql", "-H", "--", "script", "-qfec", "locksql console --project " + shellQuote(project), "/dev/null"}
	if lu, _ := os.ReadFile("/proc/self/loginuid"); strings.TrimSpace(string(lu)) != "4294967295" && len(lu) > 0 {
		console = []string{"sudo", "systemd-run", "--quiet", "--pty", "--uid=locksql", "--property=WorkingDirectory=/",
			"/usr/local/bin/locksql", "console", "--project", project}
	}
	t.Logf("command 3: %s", strings.Join(console, " "))
	cmd := exec.Command(console[0], console[1:]...)
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 160})
	if err != nil {
		t.Fatal(err)
	}
	scr := &screen{done: make(chan struct{})}
	go func() { cmd.Wait(); close(scr.done) }()
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
