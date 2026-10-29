package console

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

const hubInstanceName = "sql-uat"

// withHub puts the harness console in hub mode against a fake lockhub.
func withHub(t *testing.T, hub **hubtest.Hub) hopt {
	return func(c *ServerConfig) {
		home := t.TempDir()
		key, err := hubclient.InstanceKey(home, hubInstanceName)
		if err != nil {
			t.Fatal(err)
		}
		*hub = hubtest.New(t, hubInstanceName, key.Public().(ed25519.PublicKey))
		keyFile := filepath.Join(t.TempDir(), "hub.pub")
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString((*hub).Pub)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h, err := kconsole.OpenHub(product.P, kconsole.HubOptions{URL: (*hub).URL(), KeyFile: keyFile, Instance: hubInstanceName, Home: home}, t.TempDir(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		c.Hub = h
		c.Approver = h.Approver(newTypedApprover(c.IO))
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go h.Watch(ctx, c.IO)
	}
}

func pendingTicket(t *testing.T, resp ipc.Response, status string) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("query.run: %d %q", resp.Error.Code, resp.Error.Message)
	}
	var m map[string]string
	if err := json.Unmarshal(resp.Result, &m); err != nil || m["status"] != status || m["ticket"] == "" || m["lock"] != "locksql" {
		t.Fatalf("result %s, want %s with a ticket", resp.Result, status)
	}
	return m["ticket"]
}

// runTicket runs a ticket until the hub's decision has reached the console.
func runTicket(t *testing.T, h *harness, tk string) ipc.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk})
		if r.Error == nil || !strings.Contains(r.Error.Message, "no decision") || time.Now().After(deadline) {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Hub mode: query.run answers pending with a ticket, nothing is asked on
// the terminal and the ticket carries no value of the statement in clear;
// the ticket runs once, after the hub approved it.
func TestHubModePendingThenRun(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	const q = "SELECT id, email, note FROM users WHERE email = 'alice@example.com' LIMIT 10"
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	// Only the k-anonymity counts ran, before the ticket.
	if h.io.promptCount() != 0 || slices.Contains(h.sess.runs, q) {
		t.Fatalf("prompts %q runs %q in hub mode", h.io.prompts, h.sess.runs)
	}
	raw := hub.Ticket(tk)
	if raw == nil || strings.Contains(string(raw), "alice@example.com") {
		t.Fatalf("hub ticket %s", raw)
	}
	if !strings.Contains(h.auditLog(t), `"event":"pending"`) {
		t.Errorf("no pending record:\n%s", h.auditLog(t))
	}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}); r.Error == nil {
		t.Fatal("ran before a decision")
	}
	hub.Decide(tk, ticket.Approved, "")
	r := runTicket(t, h, tk)
	if r.Error != nil {
		t.Fatalf("run of the approved ticket: %q", r.Error.Message)
	}
	var rr ipc.RunResult
	if err := json.Unmarshal(r.Result, &rr); err != nil || strings.Contains(rr.Text, "alice@") || len(rr.Rows) != 1 {
		t.Fatalf("result %s", r.Result)
	}
	if !hub.Consumed(tk) || h.io.promptCount() != 0 {
		t.Errorf("consumed %v, prompts %q", hub.Consumed(tk), h.io.prompts)
	}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}); r.Error == nil {
		t.Fatal("a ticket ran twice")
	}
	if strings.Contains(h.io.output(), "auto mode:") {
		t.Error("auto mode in hub mode")
	}
	h.s.Key(KeyShiftTab)
	if h.s.autoApprove() {
		t.Error("Shift+Tab turned auto mode on in hub mode")
	}
}

// A denial reaches the agent with the human's reason, and nothing runs.
func TestHubModeDenied(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Denied, "too wide")
	r := runTicket(t, h, tk)
	wantCode(t, r, ipc.CodeDenied)
	if !strings.Contains(r.Error.Message, "too wide") || h.sess.runCount() != 0 {
		t.Fatalf("denial %q, runs %d", r.Error.Message, h.sess.runCount())
	}
}

// What the statement resolves to changed between the decision and the
// run: stale, with a new ticket, and nothing ran.
func TestHubModeStale(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	st := guarded(h)
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	st.Objects[1].Def = "SELECT 2" // CREATE OR REPLACE FUNCTION
	r := runTicket(t, h, tk)
	next := pendingTicket(t, r, "stale")
	if next == tk || h.sess.runCount() != 0 || hub.Pushed() != 2 {
		t.Fatalf("new ticket %q (old %q), runs %d, pushed %d", next, tk, h.sess.runCount(), hub.Pushed())
	}
	// The new ticket runs once approved.
	hub.Decide(next, ticket.Approved, "")
	if r := runTicket(t, h, next); r.Error != nil {
		t.Fatalf("run of the new ticket: %q", r.Error.Message)
	}
}

// Values typed in the console cannot be typed in hub mode.
func TestHubModeRefusesPlaceholders(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	pr := h.plan(t, typedQ, false)
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, r, ipc.CodeRefused)
	if hub.Pushed() != 0 || h.io.promptCount() != 0 {
		t.Fatalf("pushed %d prompts %q", hub.Pushed(), h.io.prompts)
	}
}
