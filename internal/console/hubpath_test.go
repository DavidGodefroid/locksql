package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// hubTicket decodes the ticket the console pushed to the hub.
func hubTicket(t *testing.T, hub *hubtest.Hub, tk string) ticket.Ticket {
	t.Helper()
	var out ticket.Ticket
	if err := json.Unmarshal(hub.Ticket(tk), &out); err != nil {
		t.Fatalf("ticket %s: %v", tk, err)
	}
	return out
}

// The ticket of a production profile carries Flags.Production, which
// lockhub needs to ask for the typed instance name; a non-production
// ticket does not. A denial on production reaches the agent with the
// human's reason, and nothing runs.
func TestHubProductionTicketFlag(t *testing.T) {
	for _, c := range []struct {
		name    string
		profile config.Profile
		want    bool
	}{{"uat", uatProfile(), false}, {"prod", prodProfile(), true}} {
		var hub *hubtest.Hub
		h := newHarness(t, c.profile, withHub(t, &hub))
		pr := h.plan(t, selectUsers, false)
		tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
		if got := hubTicket(t, hub, tk).Flags.Production; got != c.want {
			t.Errorf("%s: Flags.Production = %v, want %v", c.name, got, c.want)
		}
		if !c.want {
			continue
		}
		hub.Decide(tk, ticket.Denied, "not on prod")
		r := runTicket(t, h, tk)
		wantCode(t, r, ipc.CodeDenied)
		if r.Error.Message != "denied by the human: not on prod; do not retry unless asked" || h.sess.runCount() != 0 {
			t.Errorf("denial %q, runs %d", r.Error.Message, h.sess.runCount())
		}
	}
}

// The run of an approved ticket plans the statement again; when that
// analysis fails (the catalog cannot be read), nothing runs and the
// failure is audited with the ticket, a value its message quotes redacted.
func TestHubRunTimeAnalysisFailureAudited(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, "SELECT id, email, note FROM users WHERE email = 'bob@example.com' LIMIT 5", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	h.sess.colsErr = errors.New("catalog read failed near carol@example.net")
	h.s.catalogCache = nil
	runs := h.sess.runCount()
	r := runTicket(t, h, tk)
	if r.Error == nil {
		t.Fatal("the run succeeded")
	}
	if h.sess.runCount() != runs {
		t.Fatal("a statement ran")
	}
	recs := auditRecords(t, h, "run", tk)
	if len(recs) == 0 {
		t.Fatalf("no audit record of the failed run:\n%s", h.auditLog(t))
	}
	last := recs[len(recs)-1]
	if last["decision"] != "failed" || errText(last) == "" || strings.Contains(errText(last), "carol@") {
		t.Errorf("run record %v", last)
	}
	if ap := auditRecords(t, h, "approved", tk); len(ap) != 1 || ap[0]["hub_sig"] == nil {
		t.Errorf("no signed approval record before the failed run: %v", ap)
	}
}

// A client of the socket cannot answer the console's own terminal prompts
// (:unmask, :review): whatever it writes while a prompt waits, the
// decision stays the human's and nothing is approved.
func TestSocketCannotAnswerConsolePrompts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs the peer credentials of a Unix socket")
	}
	root := t.TempDir()
	writeProjectConfig(t, root, 100)
	load := func() (config.Policy, error) {
		cfg, err := config.LoadFrom(root, "")
		if err != nil {
			return config.Policy{}, err
		}
		r, err := pii.LoadRules(root)
		if err != nil {
			return config.Policy{}, err
		}
		return config.NewPolicy(cfg.Profiles["uat"], r.Mask, r.Allow), nil
	}
	initial, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{":unmask", ":review"} {
		h := newHarness(t, initial.Profile, func(c *ServerConfig) {
			c.Policy = initial
			c.RulesPath = filepath.Join(root, pii.RulesFile)
			c.ApprovedKey = config.ApprovedKey(root, "uat")
			c.LoadPolicy = load
		})
		if cmd == ":review" {
			// A loosening waits for :review.
			writeProjectConfig(t, root, 5000)
			h.s.CheckPolicy()
		}
		dir, err := os.MkdirTemp("", "lsa")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "a.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			os.RemoveAll(dir)
			t.Skipf("unix sockets unavailable: %v", err)
		}
		h.io.mu.Lock()
		h.io.block = true
		h.io.blocked = make(chan struct{})
		blocked := h.io.blocked
		h.io.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		lines := make(chan string, 1)
		served := make(chan error, 1)
		go func() { served <- h.s.Serve(ctx, ln, lines) }()
		lines <- cmd
		select {
		case <-blocked:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: prompt not reached", cmd)
		}
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{"y\n", "Y\n", `{"jsonrpc":"2.0","id":1,"result":"y"}` + "\n", `{"jsonrpc":"2.0","id":2,"method":"status"}` + "\n"} {
			if _, err := c.Write([]byte(raw)); err != nil {
				break
			}
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var resp ipc.Response
		_ = ipc.ReadMsg(bufio.NewReader(c), &resp)
		c.Close()
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Serve did not stop", cmd)
		}
		os.RemoveAll(dir)
		switch cmd {
		case ":unmask":
			if h.s.allowUnmask() {
				t.Error(":unmask: bytes from the socket turned unmasked output on")
			}
		case ":review":
			if got := h.s.profile.Limits.MaxRows; got != 100 {
				t.Errorf(":review: bytes from the socket applied the loosening: max_rows=%d", got)
			}
			if ap, err := config.LoadApproved(h.state, config.ApprovedKey(root, "uat")); err == nil && ap.Profile.Limits.MaxRows == 5000 {
				t.Error(":review: the loosening was saved as approved")
			}
		}
		writeProjectConfig(t, root, 100)
	}
}

// A denial without a reason says so once, without the hub client's own
// error text.
func TestHubDenialWithoutReason(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Denied, "")
	r := runTicket(t, h, tk)
	wantCode(t, r, ipc.CodeDenied)
	if r.Error.Message != "denied by the human; do not retry unless asked" {
		t.Errorf("denial %q", r.Error.Message)
	}
}
