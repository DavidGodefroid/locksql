//go:build firstquery && linux

// Package firstquery checks the README's quick start end to end and
// without a human, through the launcher and the image: locksql init,
// profile add and doctor --fix, then the console in a terminal, attached
// to a lockhub as `lox up` starts it (here a fake lockhub served by the
// test, reached over the host network). The console's start-up prompts
// stay keystrokes in its terminal, which the test types as the human
// would; the agent's plan and run follow, the run answers pending with a
// ticket, the test approves it in the fake lockhub as the human would, and
// the run of the ticket returns the rows. It uses Docker volumes
// (locksql-run, locksql-home) and the container name locksql-console: CI
// runs it on a throwaway runner.
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
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/creack/pty"
	_ "modernc.org/sqlite"
)

// instances counts the fake lockhubs: each knows its console by an
// instance name of its own, as the console keeps the hub state of an
// instance (its watch cursor) in the home volume, from one start to the
// next.
var instances int

// imageName is the image the launcher of a clone runs.
func imageName() string {
	if image := os.Getenv("LOCKSQL_IMAGE"); image != "" {
		return image
	}
	return "locksql"
}

// fakeHub serves a fake lockhub for the console whose home is the volume
// homeVol, as lox up pins it: the console's instance key (made in that
// volume by locksql hub-key) at the hub, the hub's key in a directory of
// the project (mounted in the console's container) owned by the console
// account. It returns the hub and the
// console's hub flags; the console reaches the hub on the host network
// (LOCKSQL_DOCKER_ARGS=--network host, or --network host for docker run).
func fakeHub(t *testing.T, homeVol, project string) (*hubtest.Hub, []string) {
	t.Helper()
	instances++
	instance := fmt.Sprintf("sql-dev-%d-%d", os.Getpid(), instances)
	out, err := exec.Command("docker", "run", "--rm", "--user", "locksql", "-v", homeVol+":/home/locksql",
		imageName(), "hub-key", "--instance", instance).Output()
	if err != nil {
		t.Fatalf("locksql hub-key: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("locksql hub-key printed %q: %v", out, err)
	}
	hub := hubtest.New(t, instance, ed25519.PublicKey(pub))
	// The console reads the hub's key only from a directory root or its
	// own account owns, as lox up's: given to the console account.
	dir := filepath.Join(project, ".hub")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "hub.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "run", "--rm", "--user", "0", "--entrypoint", "chown", "-v", dir+":"+dir,
		imageName(), "-R", "locksql:locksql", dir).CombinedOutput(); err != nil {
		t.Fatalf("chown %s: %v\n%s", dir, err, out)
	}
	return hub, []string{"--hub", hub.URL(), "--hub-key-file", keyFile, "--instance", instance}
}

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
	image := imageName()
	_, hubFlags := fakeHub(t, "locksql-home", project)
	dir := filepath.Join(project, ".locksql")
	cmd := exec.Command("docker", append([]string{"run", "-it", "--rm", "--network", "host", "--user", "locksql", "-v", project + ":" + project + ":ro",
		"-v", dir + ":" + dir, "-v", "locksql-run:/run/locksql", "-v", "locksql-home:/home/locksql",
		"-e", "LOCKSQL_EXPECT_DIR=0:0", image, "console", "--project", project}, hubFlags...)...)
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

	// The console, in a terminal, as lox up starts it: the launcher runs it
	// as the console account, in its own container, attached to the hub.
	hub, hubFlags := fakeHub(t, "locksql-home", project)
	env = append(env, "LOCKSQL_DOCKER_ARGS=--network host")
	t.Logf("command 4: %s locksql console %s", strings.Join(env, " "), strings.Join(hubFlags, " "))
	cmd := exec.Command("sh", append([]string{launcher, "console"}, hubFlags...)...)
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

	// The agent plans a query, then runs it: pending, until the human
	// approves its ticket in lockhub; then the run of the ticket.
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
	out, err = agent(t, project, "run", "--profile", "dev", "--json", plan.PlanID)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	var pending struct {
		Status string `json:"status"`
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(out), &pending); err != nil || pending.Status != "pending" || pending.Ticket == "" {
		t.Fatalf("run output %q, want pending with a ticket: %v", out, err)
	}
	if strings.Contains(scr.String()[at:], "Approve?") {
		t.Fatal("the console asked for the approval in its terminal")
	}
	hub.Decide(pending.Ticket, ticket.Approved, "")
	deadline := time.Now().Add(time.Minute)
	for {
		out, err = agent(t, project, "run", "--profile", "dev", "--json", pending.Ticket)
		if err == nil || !strings.Contains(out, "no decision") || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("run of the ticket: %v\n%s", err, out)
	}
	var rows struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("run output %q: %v", out, err)
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
	image := imageName()
	runVol, homeVol := "locksql-e2e-allowed-run", "locksql-e2e-allowed-home"
	t.Cleanup(func() {
		for _, n := range []string{"locksql-e2e-allowed-1", "locksql-e2e-allowed-2", "locksql-e2e-allowed-3"} {
			exec.Command("docker", "rm", "-f", n).Run()
		}
		exec.Command("docker", "volume", "rm", runVol, homeVol).Run()
	})
	_, hubFlags := fakeHub(t, homeVol, project)
	console := func(name string, extra ...string) *exec.Cmd {
		return exec.Command("docker", append(append([]string{"run", "-it", "--rm", "--network", "host", "--name", name, "--user", "locksql",
			"-v", project + ":" + project, "-v", runVol + ":/run/locksql", "-v", homeVol + ":/home/locksql",
			image, "console", "--project", project}, hubFlags...), extra...)...)
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
	out, err := exec.Command("docker", append([]string{"run", "--rm", "--user", "locksql", image, "console", "--allowed-uids", "0"}, hubFlags...)...).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "leading zero") {
		t.Errorf("--allowed-uids 0: %v\n%s", err, out)
	}
}
