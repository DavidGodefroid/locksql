//go:build integration && linux

package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The phase-1 demo of the approval hub, end to end with real binaries:
// lockhub and lock built from a lockhub checkout (LOCKHUB_SRC), locksql
// from this tree, a throwaway Postgres. An agent plans and runs, gets
// pending with a ticket; a human approves with `lock approve` in a
// terminal; the agent runs the ticket and gets the rows; the hub's audit
// verifies. Then the refusals: a denial, a schema change between the
// approval and the run (stale, a new ticket), a decision replayed, the
// hub stopped (pending, nothing runs).
//
//	LOCKHUB_E2E=1 LOCKHUB_SRC=~/Documents/lockhub go test -tags integration -run TestHubPhase1 ./test/integration

const hubInst = "crm-test"

func hubE2E(t *testing.T) string {
	t.Helper()
	if os.Getenv("LOCKHUB_E2E") != "1" {
		t.Skip("set LOCKHUB_E2E=1 (and LOCKHUB_SRC) to run the hub end to end")
	}
	src := os.Getenv("LOCKHUB_SRC")
	if src == "" {
		t.Fatal("LOCKHUB_SRC: the lockhub checkout to build lockhub and lock from")
	}
	return src
}

// buildHub builds lockhub and lock from src into dir.
func buildHub(t *testing.T, src, dir string) (hubBin, lockBin string) {
	t.Helper()
	for _, c := range []string{"lockhub", "lock"} {
		cmd := exec.Command("go", "build", "-p", "2", "-o", filepath.Join(dir, c), "./cmd/"+c)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOMAXPROCS=2")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", c, err, out)
		}
	}
	return filepath.Join(dir, "lockhub"), filepath.Join(dir, "lock")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// hubProc is a running `lockhub serve`.
type hubProc struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  strings.Builder
	done chan struct{}
}

func (h *hubProc) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.out.Write(p)
}

func (h *hubProc) output() string { h.mu.Lock(); defer h.mu.Unlock(); return h.out.String() }

func (h *hubProc) stop() {
	_ = h.cmd.Process.Signal(os.Interrupt)
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
}

func startHub(t *testing.T, bin, data, addr, facade string) *hubProc {
	t.Helper()
	h := &hubProc{done: make(chan struct{})}
	h.cmd = exec.Command(bin, "serve", "--listen", addr, "--data", data, "--facade-socket", facade)
	h.cmd.Stdout, h.cmd.Stderr = h, h
	if err := h.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.cmd.Wait(); close(h.done) }()
	t.Cleanup(func() {
		h.stop()
		if t.Failed() {
			t.Logf("lockhub output:\n%s", h.output())
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return h
		}
		select {
		case <-h.done:
			t.Fatalf("lockhub exited:\n%s", h.output())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("lockhub never listened:\n%s", h.output())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// approveOnce runs `lock approve --once` in a terminal and types answer
// at the ticket's prompt; it returns the facade's output.
func approveOnce(t *testing.T, lockBin, facade, answer string) string {
	t.Helper()
	cmd := exec.Command(lockBin, "approve", "--once", "--socket", facade)
	cmd.Env = append(os.Environ(), "TERM=xterm", "USER=e2e-human")
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	var mu sync.Mutex
	var out strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tty.Read(buf)
			mu.Lock()
			out.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	seen := func() string { mu.Lock(); defer mu.Unlock(); return out.String() }
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(seen(), "approve? [y]es") {
		if strings.Contains(seen(), "no ticket waiting") || time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("lock approve: no prompt:\n%s", seen())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := tty.WriteString(answer + "\n"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("lock approve: %v\n%s", err, seen())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("lock approve did not exit:\n%s", seen())
	}
	return seen()
}

type pendingResult struct {
	Status      string `json:"status"`
	Ticket      string `json:"ticket"`
	Lock        string `json:"lock"`
	StaleTicket string `json:"stale_ticket"`
}

func TestHubPhase1(t *testing.T) {
	src := hubE2E(t)
	srv := startPostgresVariant(t, "17", "hube2e")
	psql := func(sql string) {
		t.Helper()
		if err := Exec(srv, sql, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app"); err != nil {
			t.Fatal(err)
		}
	}
	psql(`CREATE TABLE hub_t (id int PRIMARY KEY, label text);
INSERT INTO hub_t VALUES (1, 'alpha'), (2, 'beta');
CREATE VIEW hub_v AS SELECT id, label FROM hub_t;
GRANT SELECT ON hub_t, hub_v TO ro;`)

	bins := t.TempDir()
	hubBin, lockBin := buildHub(t, src, bins)
	if _, err := buildLocksql(); err != nil {
		t.Fatal(err)
	}
	locksqlBin, _ := buildLocksql()

	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("[profiles.uat]\nengine = \"postgres\"\nhost = \"127.0.0.1\"\nport = %d\nuser = \"ro\"\ndatabase = \"app\"\n", srv.Port)
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

	// 1. The hub: its key, the lock's key pinned, serving.
	data := filepath.Join(home, "hubdata")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(hubBin, "keygen", "--data", data).Output()
	if err != nil {
		t.Fatalf("lockhub keygen: %v", err)
	}
	hubPub := filepath.Join(home, "hub.pub")
	if err := os.WriteFile(hubPub, out, 0o644); err != nil {
		t.Fatal(err)
	}
	hk := exec.Command(locksqlBin, "hub-key", "--instance", hubInst)
	hk.Env = env
	lockPub, err := hk.Output()
	if err != nil {
		t.Fatalf("locksql hub-key: %v", err)
	}
	again := exec.Command(locksqlBin, "hub-key", "--instance", hubInst)
	again.Env = env
	if b, _ := again.Output(); string(b) != string(lockPub) {
		t.Fatalf("hub-key changed: %q then %q", lockPub, b)
	}
	locks, _ := json.Marshal(map[string]any{"locks": map[string]any{hubInst: map[string]string{"public_key": strings.TrimSpace(string(lockPub))}}})
	if err := os.WriteFile(filepath.Join(data, "locks.json"), locks, 0o600); err != nil {
		t.Fatal(err)
	}
	fdir := filepath.Join(home, "facade")
	if err := os.Mkdir(fdir, 0o700); err != nil {
		t.Fatal(err)
	}
	facade := filepath.Join(fdir, "f.sock")
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	hub := startHub(t, hubBin, data, addr, facade)

	// 2. The console in hub mode.
	c := startConsole(t, project, env, "--profile", "uat", "--hub", "http://"+addr, "--hub-key-file", hubPub, "--instance", hubInst)
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	c.expect("Password for ro@127.0.0.1: ")
	c.send(ROPassword + "\n")
	seen := ""
	deadline := time.Now().Add(60 * time.Second)
	for {
		o := c.output()
		if strings.Contains(o[c.mark:], "Accept all [a]") {
			c.expect("Accept all [a], review [r], skip [s]: ")
			c.send("a\n")
		}
		if strings.Contains(o[c.mark:], "Listening…") {
			seen = c.expect("Listening…")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the console never listened")
		}
		time.Sleep(50 * time.Millisecond)
	}
	m := socketLine.FindStringSubmatch(seen)
	if m == nil {
		t.Fatalf("no socket path in %q", seen)
	}
	cl := dialConsole(t, m[1])
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
		t.Fatal(e)
	}

	// 3. The agent: plan, run → pending with a ticket.
	submit := func(sql string) pendingResult {
		t.Helper()
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: sql}, &pr); e != nil {
			t.Fatalf("plan: %+v", e)
		}
		var p pendingResult
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &p); e != nil {
			t.Fatalf("run: %+v", e)
		}
		if p.Status != "pending" || p.Ticket == "" || p.Lock != "locksql" {
			t.Fatalf("run: want pending, got %+v", p)
		}
		return p
	}
	// runTicket runs a ticket, waiting for the decision to reach the lock.
	runTicket := func(tk string) (json.RawMessage, *ipc.RPCError) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for {
			var raw json.RawMessage
			e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}, &raw)
			if e == nil || !strings.Contains(e.Message, "no decision yet") || time.Now().After(deadline) {
				return raw, e
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	const query = "SELECT id, label FROM hub_v ORDER BY id LIMIT 10"
	p := submit(query)
	if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: p.Ticket}, nil); e == nil {
		t.Fatal("the ticket ran before a decision")
	}

	// 4. The human approves in `lock approve`.
	if fo := approveOnce(t, lockBin, facade, "y"); !strings.Contains(fo, "approved") || !strings.Contains(fo, p.Ticket) {
		t.Fatalf("facade:\n%s", fo)
	}

	// 5. The agent runs the ticket.
	raw, e := runTicket(p.Ticket)
	if e != nil {
		t.Fatalf("run ticket: %+v", e)
	}
	var rr ipc.RunResult
	if err := json.Unmarshal(raw, &rr); err != nil || len(rr.Rows) != 2 || fmt.Sprint(rr.Rows[0][1]) != "alpha" {
		t.Fatalf("rows: %s %v", raw, err)
	}

	// runs counts the runs of ticket tk in the console's audit log (its
	// "run" records).
	runs := func(tk string) int {
		t.Helper()
		n := 0
		_ = filepath.WalkDir(filepath.Join(home, "state"), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != "audit.log" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range strings.Split(string(b), "\n") {
				if strings.Contains(l, `"event":"run"`) && strings.Contains(l, `"ticket":"`+tk+`"`) {
					n++
				}
			}
			return nil
		})
		return n
	}
	if n := runs(p.Ticket); n != 1 {
		t.Fatalf("the approved ticket is audited as run %d times, want 1", n)
	}

	t.Run("replayed decision refused", func(t *testing.T) {
		_, e := runTicket(p.Ticket)
		if e == nil || e.Code != ipc.CodeDenied || !strings.Contains(e.Message, "used") {
			t.Fatalf("replay: want CodeDenied, plan already used; got %+v", e)
		}
		if n := runs(p.Ticket); n != 1 {
			t.Fatalf("the replay ran: %d runs", n)
		}
	})

	t.Run("denied", func(t *testing.T) {
		d := submit("SELECT id FROM hub_t ORDER BY id LIMIT 10")
		approveOnce(t, lockBin, facade, "n not now")
		_, e := runTicket(d.Ticket)
		if e == nil || e.Code != ipc.CodeDenied || !strings.Contains(e.Message, "not now") {
			t.Fatalf("denied ticket: %+v", e)
		}
	})

	t.Run("schema change between approval and run is stale", func(t *testing.T) {
		s := submit(query)
		approveOnce(t, lockBin, facade, "y")
		psql(`CREATE OR REPLACE VIEW hub_v AS SELECT id, label FROM hub_t WHERE id > 1;`)
		raw, e := runTicket(s.Ticket)
		if e != nil {
			t.Fatalf("stale run: %+v", e)
		}
		var st pendingResult
		if err := json.Unmarshal(raw, &st); err != nil || st.Status != "stale" || st.Ticket == "" || st.Ticket == s.Ticket || st.StaleTicket != s.Ticket {
			t.Fatalf("want stale with a new ticket, got %s", raw)
		}
		var rows struct {
			Rows []any `json:"rows"`
		}
		if json.Unmarshal(raw, &rows) != nil || rows.Rows != nil {
			t.Fatalf("the stale answer carries rows: %s", raw)
		}
		if n := runs(s.Ticket); n != 0 {
			t.Fatalf("the stale ticket ran: %d runs", n)
		}
	})

	// 6. The hub's audit: chained, every decision signed and recorded.
	t.Run("lock audit verify", func(t *testing.T) {
		out, err := exec.Command(lockBin, "audit", "verify", "--data", data, "--hub-key-file", hubPub).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "OK:") {
			t.Fatalf("lock audit verify: %v\n%s", err, out)
		}
	})

	t.Run("hub stopped: pending, nothing runs", func(t *testing.T) {
		hub.stop()
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT label FROM hub_t WHERE id = 2 LIMIT 1"}, &pr); e != nil {
			t.Fatalf("plan: %+v", e)
		}
		var raw json.RawMessage
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &raw); e != nil {
			t.Fatalf("run with the hub down: %+v", e)
		}
		var d pendingResult
		if err := json.Unmarshal(raw, &d); err != nil || d.Status != "pending" || d.Ticket == "" {
			t.Fatalf("hub down: want pending, got %s", raw)
		}
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: d.Ticket}, nil); e == nil {
			t.Fatal("ran with the hub down")
		}
		if n := runs(d.Ticket); n != 0 {
			t.Fatalf("ran with the hub down: %d runs", n)
		}
	})
}
