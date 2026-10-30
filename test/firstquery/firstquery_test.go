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

// setup skips the test unless LOCKSQL_FIRSTQUERY=1, and finds the launcher.
func setup(t *testing.T) {
	t.Helper()
	if os.Getenv("LOCKSQL_FIRSTQUERY") != "1" {
		t.Skip("set LOCKSQL_FIRSTQUERY=1 on a throwaway machine: this test uses Docker volumes and console containers")
	}
	launcher = os.Getenv("LOCKSQL_FIRSTQUERY_LAUNCHER")
	if launcher == "" {
		t.Fatal("LOCKSQL_FIRSTQUERY_LAUNCHER: the launcher, scripts/locksql")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as your own account, not as root")
	}
}

// startConsole starts cmd in a terminal and returns its screen, the
// terminal, and the function that ends it (Ctrl-C) and logs the screen.
func startConsole(t *testing.T, cmd *exec.Cmd) (*screen, *os.File, func()) {
	t.Helper()
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
	return scr, tty, func() {
		tty.Write([]byte{3}) // Ctrl-C ends the session
		select {
		case <-scr.done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
		}
		tty.Close()
		t.Logf("console screen:\n%s", scr.String())
	}
}

// The quick start, with the project mounted read-write in the console's
// container, then read-only but for .locksql (LOCKSQL_READONLY_PROJECT=1,
// as lea runs it): there the console checks, through Docker's bind mount,
// that .locksql has the device and inode the launcher checked.
func TestFirstQueryThroughTheLauncher(t *testing.T) {
	setup(t)
	t.Run("read-write project", func(t *testing.T) { firstQuery(t, nil) })
	t.Run("read-only project", func(t *testing.T) { firstQuery(t, []string{"LOCKSQL_READONLY_PROJECT=1"}) })
}

// A console given a .locksql other than the one the launcher checked (here
// a device and inode no directory has) refuses to start.
func TestConsoleRefusesAnotherLocksqlDir(t *testing.T) {
	setup(t)
	project := demoProject(t)
	human(t, 1, project, []string{"init", "claude"})
	human(t, 2, project, []string{"doctor", "--fix", "--yes"}, 1)
	image := os.Getenv("LOCKSQL_IMAGE")
	if image == "" {
		image = "locksql"
	}
	dir := filepath.Join(project, ".locksql")
	cmd := exec.Command("docker", "run", "-it", "--rm", "--user", "locksql", "-v", project+":"+project+":ro",
		"-v", dir+":"+dir, "-v", "locksql-run:/run/locksql", "-v", "locksql-home:/home/locksql",
		"-e", "LOCKSQL_EXPECT_DIR=0:0", image, "console", "--project", project)
	scr, _, end := startConsole(t, cmd)
	defer end()
	scr.waitFor(t, 0, time.Minute, "is not the directory the launcher checked")
	select {
	case <-scr.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the console still runs")
	}
}

// demoProject is a project with a SQLite database, where every account may
// enter.
func demoProject(t *testing.T) string {
	t.Helper()
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
	return project
}

// firstQuery runs the quick start in a new project, the console with env.
func firstQuery(t *testing.T, env []string) {
	project := demoProject(t)

	// The human's commands of the quick start: the agent's files, a
	// profile, then .locksql/ given to the console account (doctor --fix
	// exits 1: the console's checks fail from its container, which runs
	// none).
	human(t, 1, project, []string{"init", "claude"})
	human(t, 2, project, []string{"profile", "add", "--profile", "dev", "--engine", "sqlite", "--path", "demo.db"})
	human(t, 3, project, []string{"doctor", "--fix", "--yes"}, 1)

	// The console, in a terminal: the launcher runs it as the console
	// account, in its own container.
	t.Logf("command 4: %s locksql console", strings.Join(env, " "))
	cmd := exec.Command("sh", launcher, "console")
	cmd.Dir = project
	cmd.Env = append(os.Environ(), env...)
	scr, tty, end := startConsole(t, cmd)
	defer end()

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

// An agent in a container of its own runs as a uid with no account in the
// image (lea's agents: the host user's uid), with the socket volume and
// the clients group. The image as it is (no allowed_uids) refuses it; a
// console started with --allowed-uids serves that uid and no other one.
// Its own volumes and container names, removed at the end.
func TestConsoleAllowedUIDs(t *testing.T) {
	setup(t)
	project := demoProject(t)
	human(t, 1, project, []string{"profile", "add", "--profile", "dev", "--engine", "sqlite", "--path", "demo.db"})
	human(t, 2, project, []string{"doctor", "--fix", "--yes"}, 1)
	image := os.Getenv("LOCKSQL_IMAGE")
	if image == "" {
		image = "locksql"
	}
	runVol, homeVol := "locksql-e2e-allowed-run", "locksql-e2e-allowed-home"
	t.Cleanup(func() {
		for _, n := range []string{"locksql-e2e-allowed-1", "locksql-e2e-allowed-2", "locksql-e2e-allowed-3"} {
			exec.Command("docker", "rm", "-f", n).Run()
		}
		exec.Command("docker", "volume", "rm", runVol, homeVol).Run()
	})
	console := func(name string, extra ...string) *exec.Cmd {
		return exec.Command("docker", append([]string{"run", "-it", "--rm", "--name", name, "--user", "locksql",
			"-v", project + ":" + project, "-v", runVol + ":/run/locksql", "-v", homeVol + ":/home/locksql",
			image, "console", "--project", project}, extra...)...)
	}
	// listen answers the first start's prompts until the console listens.
	listen := func(scr *screen, tty *os.File) {
		at := 0
		for {
			var got string
			got, at = scr.waitFor(t, at, time.Minute, "Apply these changes? [y/N] ", "Accept all [a], review [r], skip [s]: ", "Listening…")
			if got == "Listening…" {
				return
			}
			if strings.HasPrefix(got, "Apply") {
				tty.Write([]byte("y\n"))
			} else {
				tty.Write([]byte("a\n"))
			}
		}
	}
	// foreign is the agent's status as uid, in a container of its own.
	foreign := func(uid string) (string, error) {
		out, err := exec.Command("docker", "run", "--rm", "--user", uid, "--group-add", "10000", "-e", "HOME=/tmp",
			"-v", project+":"+project, "-w", project, "-v", runVol+":/run/locksql",
			image, "status", "--profile", "dev").CombinedOutput()
		t.Logf("uid %s: locksql status: %v\n%s", uid, err, out)
		return string(out), err
	}
	served := func(uid string) bool { _, err := foreign(uid); return err == nil }

	scr, tty, end := startConsole(t, console("locksql-e2e-allowed-1"))
	listen(scr, tty)
	if served("4242") {
		t.Error("no --allowed-uids: uid 4242 served")
	}
	if _, err := exec.Command("docker", "run", "--rm", "-v", project+":"+project, "-w", project, "-v", runVol+":/run/locksql",
		image, "status", "--profile", "dev").CombinedOutput(); err != nil {
		t.Errorf("the image's agent refused: %v", err)
	}
	end()
	exec.Command("docker", "wait", "locksql-e2e-allowed-1").Run()

	scr, tty, end = startConsole(t, console("locksql-e2e-allowed-2", "--allowed-uids", "4242"))
	listen(scr, tty)
	if !strings.Contains(scr.String(), "allowed uids besides locksql-clients (--allowed-uids): 4242") {
		t.Error("the console does not print the allowed uids")
	}
	if !served("4242") {
		t.Error("--allowed-uids 4242: uid 4242 refused")
	}
	if served("4243") {
		t.Error("--allowed-uids 4242: uid 4243 served")
	}
	end()
	exec.Command("docker", "wait", "locksql-e2e-allowed-2").Run()

	// The console's own uid would void the separation; root is refused
	// before anything else.
	scr, _, end = startConsole(t, console("locksql-e2e-allowed-3", "--allowed-uids", "10001"))
	scr.waitFor(t, 0, time.Minute, "may also connect as a client")
	end()
	out, err := exec.Command("docker", "run", "--rm", "--user", "locksql", image, "console", "--allowed-uids", "0").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "leading zero") {
		t.Errorf("--allowed-uids 0: %v\n%s", err, out)
	}
}
