//go:build integration && linux

package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
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
// hub stopped (pending, nothing runs). The console reaches the hub through
// a proxy that forges the decision of one ticket in flight: signed by a key
// the console did not pin, or one byte of it changed; neither runs. Last,
// one byte of the hub's audit log changed fails `lock audit verify`.
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

// hubProxy forwards the console's requests to lockhub. The decision on
// ticket target, as it comes back from GET /v1/decisions, is replaced by
// forge(decision): a hub with another key, or someone on the wire.
type hubProxy struct {
	mu     sync.Mutex
	target string
	forge  func(raw []byte) ([]byte, error)
	forged chan forgery
}

// forgery is a decision the proxy replaced: what lockhub sent, what the
// console got instead.
type forgery struct {
	orig, sent []byte
	err        error
}

func startHubProxy(t *testing.T, hubAddr string) (*hubProxy, string) {
	t.Helper()
	p := &hubProxy{forged: make(chan forgery, 1)}
	rp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: hubAddr})
	rp.ModifyResponse = p.modify
	srv := httptest.NewServer(rp)
	t.Cleanup(func() { srv.CloseClientConnections(); srv.Close() })
	return p, srv.Listener.Addr().String()
}

// forgeNext arms the proxy for the decision on tk.
func (p *hubProxy) forgeNext(tk string, forge func([]byte) ([]byte, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.target, p.forge = tk, forge
}

func (p *hubProxy) modify(resp *http.Response) error {
	if resp.Request.URL.Path != "/v1/decisions" || resp.StatusCode != http.StatusOK {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.target == "" {
		return nil
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	var res map[string]json.RawMessage
	var ds []map[string]json.RawMessage
	if json.Unmarshal(b, &res) == nil && json.Unmarshal(res["decisions"], &ds) == nil {
		for _, d := range ds {
			var tk string
			if json.Unmarshal(d["ticket"], &tk) != nil || tk != p.target {
				continue
			}
			f := forgery{orig: append([]byte(nil), d["decision"]...)}
			f.sent, f.err = p.forge(f.orig)
			if f.err == nil {
				d["decision"] = f.sent
				res["decisions"] = rawJSON(ds)
				b = rawJSON(res)
			}
			p.target = ""
			p.forged <- f
			break
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", fmt.Sprint(len(b)))
	return nil
}

// rawJSON marshals v leaving the raw decisions in it byte for byte.
func rawJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
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
	proxy, proxyAddr := startHubProxy(t, addr)
	pinned, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(pinned) != ed25519.PublicKeySize {
		t.Fatalf("hub key %q: %v", out, err)
	}

	// 2. The console in hub mode, reaching the hub through the proxy.
	c := startConsole(t, project, env, "--profile", "uat", "--hub", "http://"+proxyAddr, "--hub-key-file", hubPub, "--instance", hubInst)
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
	// decided counts the decisions the human made in lockhub.
	decided := 0
	decide := func(answer string) string {
		t.Helper()
		decided++
		return approveOnce(t, lockBin, facade, answer)
	}
	const query = "SELECT id, label FROM hub_v ORDER BY id LIMIT 10"
	p := submit(query)
	if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: p.Ticket}, nil); e == nil {
		t.Fatal("the ticket ran before a decision")
	}

	// 4. The human approves in `lock approve`.
	if fo := decide("y"); !strings.Contains(fo, "approved") || !strings.Contains(fo, p.Ticket) {
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
		decide("n not now")
		_, e := runTicket(d.Ticket)
		if e == nil || e.Code != ipc.CodeDenied || !strings.Contains(e.Message, "not now") {
			t.Fatalf("denied ticket: %+v", e)
		}
	})

	t.Run("another agent's ticket refused", func(t *testing.T) {
		alice := ipc.Requester{Agent: "dev-alice", Token: "hash-of-alice"}
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM hub_t WHERE id = 1 LIMIT 1", Requester: alice}, &pr); e != nil {
			t.Fatalf("plan: %+v", e)
		}
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil); e == nil || e.Code != ipc.CodeWrongRequester {
			t.Fatalf("another agent's plan id: %+v", e)
		}
		var p pendingResult
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID, Requester: alice}, &p); e != nil || p.Status != "pending" {
			t.Fatalf("run: %+v %+v", p, e)
		}
		decide("y")
		deadline := time.Now().Add(60 * time.Second)
		for {
			e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: p.Ticket, Requester: ipc.Requester{Agent: "dev-bob", Token: "hash-of-bob"}}, nil)
			if e != nil && strings.Contains(e.Message, "no decision yet") && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if e == nil || e.Code != ipc.CodeWrongRequester {
				t.Fatalf("another agent's ticket: %+v", e)
			}
			break
		}
		if n := runs(p.Ticket); n != 0 {
			t.Fatalf("another agent's ticket ran: %d runs", n)
		}
		var rr ipc.RunResult
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: p.Ticket, Requester: alice}, &rr); e != nil || len(rr.Rows) != 1 {
			t.Fatalf("the requester's run: %+v %+v", rr, e)
		}
	})

	// The forgeries run before the stale ticket below, which leaves its new
	// ticket waiting at the hub for the next `lock approve`.
	//
	// forged submits sql, arms the proxy with forge for its ticket and
	// approves the ticket in lockhub; check looks at what the console got
	// instead. The console must drop it: the ticket stays undecided and
	// nothing runs.
	forged := func(t *testing.T, sql string, forge func([]byte) ([]byte, error), check func(t *testing.T, f forgery)) {
		t.Helper()
		f := submit(sql)
		proxy.forgeNext(f.Ticket, forge)
		defer proxy.forgeNext("", nil)
		decide("y")
		var got forgery
		select {
		case got = <-proxy.forged:
		case <-time.After(60 * time.Second):
			t.Fatal("the decision never came back through the proxy")
		}
		if got.err != nil {
			t.Fatalf("forge: %v", got.err)
		}
		if _, err := ticket.VerifyDecision(pinned, got.orig); err != nil {
			t.Fatalf("lockhub's own decision does not verify: %v\n%s", err, got.orig)
		}
		if bytes.Equal(got.orig, got.sent) {
			t.Fatal("nothing forged")
		}
		check(t, got)
		want := "decision refused: ticket " + f.Ticket
		deadline := time.Now().Add(60 * time.Second)
		for !strings.Contains(c.output(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("the console never refused the decision (%q):\n%s", want, c.output())
			}
			time.Sleep(100 * time.Millisecond)
		}
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: f.Ticket}, nil); e == nil || !strings.Contains(e.Message, "no decision yet") {
			t.Fatalf("run of the forged ticket: want no decision yet, got %+v", e)
		}
		if n := runs(f.Ticket); n != 0 {
			t.Fatalf("the forged decision ran: %d runs", n)
		}
	}
	// resign signs a decision again with key; keepID keeps the pinned hub
	// key's id in it.
	resign := func(key ed25519.PrivateKey, keepID bool) func([]byte) ([]byte, error) {
		return func(raw []byte) ([]byte, error) {
			var d ticket.Decision
			if err := json.Unmarshal(raw, &d); err != nil {
				return nil, err
			}
			d.Sig = ""
			if !keepID {
				d.HubKeyID = ""
				if err := d.Sign(key); err != nil {
					return nil, err
				}
				return d.Marshal()
			}
			b, err := ticket.Canonical(&d)
			if err != nil {
				return nil, err
			}
			d.Sig = ticket.SignBytes(key, ticket.ContextDecision, b)
			return d.Marshal()
		}
	}

	t.Run("decision signed by an unpinned hub key refused", func(t *testing.T) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		forged(t, "SELECT id FROM hub_t WHERE id = 1 LIMIT 2", resign(key, false), func(t *testing.T, f forgery) {
			// A well-formed decision of another hub: it verifies under
			// that hub's key, not under the pinned one.
			if _, err := ticket.VerifyDecision(pub, f.sent); err != nil {
				t.Fatalf("the other hub's decision does not verify under its key: %v", err)
			}
			if _, err := ticket.VerifyDecision(pinned, f.sent); !errors.Is(err, ticket.ErrBadSignature) {
				t.Fatalf("under the pinned key: want a bad signature, got %v", err)
			}
		})
	})

	t.Run("decision naming the pinned key, signed by another, refused", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		forged(t, "SELECT id FROM hub_t WHERE id = 1 LIMIT 3", resign(key, true), func(t *testing.T, f forgery) {
			var d ticket.Decision
			if err := json.Unmarshal(f.sent, &d); err != nil || d.HubKeyID != ticket.KeyID(pinned) {
				t.Fatalf("the forged decision names hub key %q (%v), not the pinned one", d.HubKeyID, err)
			}
			// Only the signature tells it apart.
			if _, err := ticket.VerifyDecision(pinned, f.sent); !errors.Is(err, ticket.ErrBadSignature) {
				t.Fatalf("want a bad signature, got %v", err)
			}
		})
	})

	t.Run("tampered decision refused", func(t *testing.T) {
		// One byte of the facade the decision was made on: a field only
		// the signature covers (the decision still matches the ticket).
		tamper := func(raw []byte) ([]byte, error) {
			const at = `"facade":"`
			i := bytes.Index(raw, []byte(at))
			if i < 0 {
				return nil, fmt.Errorf("no facade in %s", raw)
			}
			i += len(at)
			b := append([]byte(nil), raw...)
			if b[i] == 'x' {
				b[i] = 'y'
			} else {
				b[i] = 'x'
			}
			return b, nil
		}
		forged(t, "SELECT id FROM hub_t WHERE id = 1 LIMIT 4", tamper, func(t *testing.T, f forgery) {
			diff := 0
			for i := range f.sent {
				if i < len(f.orig) && f.sent[i] != f.orig[i] {
					diff++
				}
			}
			if len(f.sent) != len(f.orig) || diff != 1 {
				t.Fatalf("want one byte changed, got %d of %d (was %d)", diff, len(f.sent), len(f.orig))
			}
			// Still a well-formed decision: only the signature fails.
			if _, err := ticket.VerifyDecision(pinned, f.sent); !errors.Is(err, ticket.ErrBadSignature) {
				t.Fatalf("want a bad signature, got %v", err)
			}
		})
	})

	t.Run("schema change between approval and run is stale", func(t *testing.T) {
		s := submit(query)
		decide("y")
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
	auditVerify := func() (string, error) {
		out, err := exec.Command(lockBin, "audit", "verify", "--data", data, "--hub-key-file", hubPub).CombinedOutput()
		return string(out), err
	}
	verified := func(t *testing.T) {
		t.Helper()
		out, err := auditVerify()
		want := fmt.Sprintf(", %d decisions signed and recorded", decided)
		if err != nil || !strings.Contains(out, "OK:") || !strings.Contains(out, want) {
			t.Fatalf("lock audit verify: want %q: %v\n%s", want, err, out)
		}
	}
	t.Run("lock audit verify", func(t *testing.T) {
		if decided != 7 {
			t.Fatalf("%d decisions made, want 7", decided)
		}
		verified(t)
	})

	// 7. The console's audit, against the hub's (#118): the decisions it
	// acted on (the first approval, the denial, alice's approval) carry
	// the hub's signature; the forged ones and the stale one it never
	// acted on are the hub's alone.
	t.Run("lock audit verify --lock: the console's records are signed", func(t *testing.T) {
		var logs []string
		_ = filepath.WalkDir(filepath.Join(home, "state"), func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && d.Name() == "audit.log" {
				logs = append(logs, path)
			}
			return nil
		})
		if len(logs) != 1 {
			t.Fatalf("console audit logs %q, want one", logs)
		}
		out, err := exec.Command(lockBin, "audit", "verify", "--data", data, "--hub-key-file", hubPub, "--lock", hubInst+"="+logs[0]).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "OK: "+hubInst+": ") || !strings.Contains(string(out), ", 3 hub decisions match the hub's") ||
			strings.Contains(string(out), "without the hub's signature") || !strings.Contains(string(out), "4 hub decision(s) on it not in this log") {
			t.Fatalf("lock audit verify --lock: want 3 signed hub decisions, 4 not acted on: %v\n%s", err, out)
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

	t.Run("audit log tampered: lock audit verify fails", func(t *testing.T) {
		hub.stop()
		log := filepath.Join(data, "tickets.jsonl")
		orig, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(log)
		if err != nil {
			t.Fatal(err)
		}
		write := func(b []byte) {
			t.Helper()
			if err := os.Chmod(log, fi.Mode().Perm()|0o200); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(log, b, 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(log, fi.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}
		verified(t)
		// One hex digit of the hash a decision record holds of its signed
		// decision.
		const at = `"decision":"sha256:`
		i := bytes.Index(orig, []byte(at))
		if i < 0 {
			t.Fatalf("no decision record in the audit log:\n%s", orig)
		}
		i += len(at)
		bad := append([]byte(nil), orig...)
		if bad[i] == '0' {
			bad[i] = '1'
		} else {
			bad[i] = '0'
		}
		write(bad)
		out, err := auditVerify()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() == 0 || !strings.Contains(out, "FAIL") {
			t.Fatalf("lock audit verify of a tampered log: want FAIL and a non-zero exit, got %v\n%s", err, out)
		}
		// The byte put back, the log verifies again: that byte was it.
		write(orig)
		verified(t)
	})
}
