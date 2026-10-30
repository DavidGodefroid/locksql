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
	"sync"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// testClock is a clock a test moves forward.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }

func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

// approveAt approves ticket tk at the hub, dated by clock.
func approveAt(hub *hubtest.Hub, tk string, clock *testClock) {
	hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = clock.now().UTC().Truncate(time.Millisecond) })
}

// withHubAt is withHub with the hub's plans and state under stateDir and
// the hub client on clock now; stop, when not nil, is set to what stops
// the hub before the test's end (the console stopping).
func withHubAt(t *testing.T, hub **hubtest.Hub, stateDir string, now func() time.Time, stop *func()) hopt {
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
		h, err := kconsole.OpenHub(product.P, kconsole.HubOptions{URL: (*hub).URL(), KeyFile: keyFile, Instance: hubInstanceName, Home: home}, stateDir, now)
		if err != nil {
			t.Fatal(err)
		}
		c.Hub = h
		c.Approver = h.Approver(newTypedApprover(c.IO))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); h.Watch(ctx, c.IO) }()
		var once sync.Once
		end := func() {
			once.Do(func() {
				cancel()
				<-done
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		if stop != nil {
			*stop = end
		}
		t.Cleanup(end)
	}
}

const hubWrite = "UPDATE users SET note = 'x' WHERE id = 1"

// pushedTicket is the ticket tk as the hub received it.
func pushedTicket(t *testing.T, hub *hubtest.Hub, tk string) ticket.Ticket {
	t.Helper()
	var out ticket.Ticket
	if err := json.Unmarshal(hub.Ticket(tk), &out); err != nil {
		t.Fatalf("ticket %s: %v", tk, err)
	}
	return out
}

// The recompute of a renewal is the recheck's: the same plan hash and
// input digests as planning the statement again; a moved definition shows
// up by name ("state"), and nothing else does.
func TestHubRecomputeIsTheRecheck(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, writeProfile(), withHub(t, &hub))
	st := guarded(h)
	pl, r := h.s.buildPlan(context.Background(), 1, ipc.PlanParams{DB: "app", SQL: hubWrite})
	if r != nil {
		t.Fatalf("plan: %+v", r.Error)
	}
	if want, err := h.s.planHash(pl, st); err != nil || want != pl.hash {
		t.Fatalf("plan hash %s, recheck %s (%v)", pl.hash, want, err)
	}
	for _, k := range []string{"v", "profile", "engine", "host", "db", "sql", "unmask", "policy_fp", "state"} {
		if pl.inputs[k] == "" {
			t.Errorf("no digest of input %q: %v", k, pl.inputs)
		}
	}
	st.Objects[1].Def = "SELECT 2"
	again, r := h.s.buildPlan(context.Background(), 1, ipc.PlanParams{DB: "app", SQL: hubWrite})
	if r != nil {
		t.Fatalf("plan: %+v", r.Error)
	}
	got := ticket.DiffInputs(pl.inputs, again.inputs)
	if len(got) != 1 || got[0].Input != "state" || got[0].Change != ticket.ChangeChanged || again.hash == pl.hash {
		t.Fatalf("changes %+v", got)
	}

	// On the hub's goroutine (no session): the session-free inputs are
	// recomputed, the statement and the definitions unchecked (never
	// their stored digests), the plan hash kept as stored.
	body, _ := json.Marshal(hubPlan{DB: "app", SQL: hubWrite})
	fp, _ := ticket.HashOf(h.s.approved)
	p := &plans.Plan{Body: body, Binding: plans.Binding{PolicyFP: fp, PlanHash: pl.hash, Inputs: pl.inputs}}
	gfp, ghash, gin, err := h.s.hubRecompute(p)
	want := []ticket.Change{{Input: "sql", Change: ticket.ChangeUnchecked}, {Input: "state", Change: ticket.ChangeUnchecked}}
	if err != nil || gfp != fp || ghash != pl.hash || !slices.Equal(ticket.DiffInputs(pl.inputs, gin), want) {
		t.Fatalf("hub-side recompute: %s %s %v %v", gfp, ghash, ticket.DiffInputs(pl.inputs, gin), err)
	}
	// A moved policy shows on that side too (lockkit then refuses the
	// renewal: plan again).
	next := h.s.approved
	next.PIIMask = append(slices.Clone(next.PIIMask), "app.users.note")
	if err := h.s.adopt(next, "tightened"); err != nil {
		t.Fatal(err)
	}
	gfp, _, gin, err = h.s.hubRecompute(p)
	if err != nil || gfp == fp || !slices.ContainsFunc(ticket.DiffInputs(pl.inputs, gin), func(c ticket.Change) bool { return c.Input == "policy_fp" }) {
		t.Fatalf("policy change: %s %v %v", gfp, ticket.DiffInputs(pl.inputs, gin), err)
	}
}

// H1 end to end: a write's ticket expires before its run; the run answers
// pending with a new ticket that renews the old one and names the input
// that moved; approved, the renewal runs once.
func TestHubModeExpiredTicketIsAskedAgain(t *testing.T) {
	var hub *hubtest.Hub
	clock := &testClock{at: time.Now()}
	h := newHarness(t, writeProfile(), withHubAt(t, &hub, t.TempDir(), clock.now, nil))
	st := guarded(h)
	pr := h.plan(t, hubWrite, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if tt := pushedTicket(t, hub, tk); tt.Risk != ticket.RiskWrite {
		t.Fatalf("risk %s", tt.Risk)
	}
	clock.add(ticket.RiskWrite.TTL() + time.Hour)
	st.Objects[1].Def = "SELECT 2" // CREATE OR REPLACE FUNCTION while it waited
	next := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}), "pending")
	if next == tk || h.sess.runCount() != 0 {
		t.Fatalf("new ticket %q (old %q), runs %d", next, tk, h.sess.runCount())
	}
	nt := pushedTicket(t, hub, next)
	if nt.Renews == nil || nt.Renews.Of != tk || nt.Renews.Reason != ticket.RenewExpired || !nt.Renews.Checked {
		t.Fatalf("renews %+v", nt.Renews)
	}
	if len(nt.Renews.Changes) != 1 || nt.Renews.Changes[0].Input != "state" {
		t.Fatalf("changes %+v, want the definitions (state)", nt.Renews.Changes)
	}
	// The expired ticket stays expired: running it again names the same
	// renewal, nothing runs.
	if again := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}), "pending"); again != next {
		t.Fatalf("second run of the expired ticket: %q, want %q", again, next)
	}
	approveAt(hub, next, clock)
	if r := runTicket(t, h, next); r.Error != nil {
		t.Fatalf("run of the renewal: %q", r.Error.Message)
	}
	if h.sess.runCount() != 1 || !hub.Consumed(next) {
		t.Fatalf("runs %d consumed %v", h.sess.runCount(), hub.Consumed(next))
	}
	if r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: next}); r.Error == nil || h.sess.runCount() != 1 {
		t.Fatal("the renewal ran twice")
	}
}

// A renewal the human asks for in lockhub (a renew request) is checked
// and audited; the agent then runs the new ticket.
func TestHubRenewRequestIsAudited(t *testing.T) {
	var hub *hubtest.Hub
	clock := &testClock{at: time.Now()}
	h := newHarness(t, writeProfile(), withHubAt(t, &hub, t.TempDir(), clock.now, nil))
	guarded(h)
	pr := h.plan(t, hubWrite, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	clock.add(ticket.RiskWrite.TTL() + time.Hour)
	hub.Request(tk, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = clock.now().UTC().Truncate(time.Millisecond) })
	var next string
	deadline := time.Now().Add(10 * time.Second)
	for next == "" && time.Now().Before(deadline) {
		for _, id := range hub.Tickets() {
			if id != tk {
				next = id
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if next == "" {
		t.Fatalf("no renewal pushed:\n%s", h.io.output())
	}
	nt := pushedTicket(t, hub, next)
	// Without a session the statement and its definitions are not
	// checked: the renewal says so, never "unchanged".
	if nt.Renews == nil || nt.Renews.Of != tk || nt.Renews.Unchanged() ||
		!slices.Equal(nt.Renews.Changes, []ticket.Change{{Input: "sql", Change: ticket.ChangeUnchecked}, {Input: "state", Change: ticket.ChangeUnchecked}}) {
		t.Fatalf("renews %+v", nt.Renews)
	}
	for time.Now().Before(deadline) && !strings.Contains(h.auditLog(t), `"event":"renew"`) {
		time.Sleep(20 * time.Millisecond)
	}
	if log := h.auditLog(t); !strings.Contains(log, `"event":"renew"`) || !strings.Contains(log, `"ticket":"`+tk+`"`) {
		t.Fatalf("no renew record:\n%s", log)
	}
	approveAt(hub, next, clock)
	if r := runTicket(t, h, next); r.Error != nil || h.sess.runCount() != 1 {
		t.Fatalf("run of the renewal: %+v, runs %d", r.Error, h.sess.runCount())
	}
}

// A plan stored without its inputs (made by a console before them,
// pending at the upgrade), renewed from lockhub: never "checked,
// unchanged", since the statement and its definitions were not checked.
func TestHubRenewRequestOfALegacyPlan(t *testing.T) {
	var hub *hubtest.Hub
	clock := &testClock{at: time.Now()}
	h := newHarness(t, writeProfile(), withHubAt(t, &hub, t.TempDir(), clock.now, nil))
	guarded(h)
	pr := h.plan(t, hubWrite, false)
	h.s.plans[pr.PlanID].inputs = nil // as an older console stored it
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if p, err := h.s.cfg.Hub.Store.TicketPlan(tk); err != nil || p.Binding.Inputs != nil {
		t.Fatalf("plan %+v %v, want no inputs", p, err)
	}
	clock.add(ticket.RiskWrite.TTL() + time.Hour)
	hub.Request(tk, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = clock.now().UTC().Truncate(time.Millisecond) })
	var next string
	for deadline := time.Now().Add(10 * time.Second); next == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, id := range hub.Tickets() {
			if id != tk {
				next = id
			}
		}
	}
	if next == "" {
		t.Fatalf("no renewal pushed:\n%s", h.io.output())
	}
	nt := pushedTicket(t, hub, next)
	if nt.Renews == nil || nt.Renews.Unchanged() || !slices.ContainsFunc(nt.Renews.Changes, func(c ticket.Change) bool {
		return c.Input == "state" && c.Change == ticket.ChangeUnchecked
	}) {
		t.Fatalf("renews %+v: a legacy plan renewed as unchanged", nt.Renews)
	}
}

// The console's clear screen reaches the plan (SubmitClear): what a
// reveal or a pinned device shows, never sent to the hub as it is.
func TestHubClearScreenInPlan(t *testing.T) {
	var hub *hubtest.Hub
	h := newHarness(t, uatProfile(), withHub(t, &hub))
	const q = "SELECT id, email, note FROM users WHERE email = 'alice@example.com' LIMIT 10"
	pr := h.plan(t, q, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	p, err := h.s.cfg.Hub.Store.TicketPlan(tk)
	if err != nil {
		t.Fatal(err)
	}
	if p.Clear == nil || !strings.Contains(strings.Join(p.Clear.Body, "\n"), "alice@example.com") || !strings.Contains(p.Clear.Header, "tier") {
		t.Fatalf("clear screen %+v", p.Clear)
	}
	if strings.Contains(string(hub.Ticket(tk)), "alice@example.com") {
		t.Fatal("the hub got the clear screen")
	}
}

// Rollback (D.5): a console started standalone after hub mode withdraws
// the plans hub mode left pending and refuses a run of their tickets
// explicitly; nothing runs, even once the hub approved it.
func TestStandaloneAfterHubModeWithdraws(t *testing.T) {
	var hub *hubtest.Hub
	stateDir := t.TempDir()
	var stop func()
	hubbed := newHarness(t, writeProfile(), withHubAt(t, &hub, stateDir, time.Now, &stop))
	pr := hubbed.plan(t, hubWrite, false)
	tk := pendingTicket(t, hubbed.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	hub.Decide(tk, ticket.Approved, "")
	stop() // the console stops

	io := &fakeIO{}
	withdrawStandalone(io, stateDir)
	if out := io.output(); !strings.Contains(out, "1 pending ticket(s) of "+hubInstanceName+" withdrawn") {
		t.Fatalf("standalone start said %q", out)
	}
	st, err := plans.Open(filepath.Join(stateDir, product.P.Name, "hub", hubInstanceName, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.TicketPlan(tk)
	_ = st.Close()
	if err != nil || p.State != plans.Withdrawn {
		t.Fatalf("plan %+v %v, want withdrawn", p, err)
	}

	h := newHarness(t, writeProfile())
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk})
	wantCode(t, r, ipc.CodeWithdrawn)
	if !strings.Contains(r.Error.Message, "withdrawn") || h.sess.runCount() != 0 || hubbed.sess.runCount() != 0 {
		t.Fatalf("answer %q, runs %d", r.Error.Message, h.sess.runCount())
	}
}

// The run of an expired ticket is audited as its renewal, once (#118); an
// approval the lock could not use (dated ahead of its clock) is recorded
// with the hub's signature on it.
func TestHubModeRenewalIsAudited(t *testing.T) {
	var hub *hubtest.Hub
	clock := &testClock{at: time.Now()}
	h := newHarness(t, writeProfile(), withHubAt(t, &hub, t.TempDir(), clock.now, nil))
	guarded(h)
	pr := h.plan(t, hubWrite, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	d := decideSigned(t, hub, tk, ticket.Approved, "", func(d *ticket.Decision) {
		d.At = clock.now().Add(10 * time.Minute).UTC().Truncate(time.Millisecond)
	})
	next := pendingTicket(t, runTicket(t, h, tk), "pending")
	if next == tk || h.sess.runCount() != 0 {
		t.Fatalf("new ticket %q (old %q), runs %d", next, tk, h.sess.runCount())
	}
	if again := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}), "pending"); again != next {
		t.Fatalf("second run of the expired ticket: %q, want %q", again, next)
	}
	renew := auditRecords(t, h, "renew", tk)
	if len(renew) != 1 || renew[0]["decision"] != "renewed" || renew[0]["reason"] != "renewed by ticket "+next || renew[0]["sql"] != hubWrite {
		t.Fatalf("renewal records %v", renew)
	}
	wantHubSigned(t, renew[0], d)

	// Expired pending: no decision, no signature.
	clock.add(ticket.RiskWrite.TTL() + time.Hour)
	last := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{Ticket: next}), "pending")
	renew = auditRecords(t, h, "renew", next)
	if len(renew) != 1 || renew[0]["reason"] != "renewed by ticket "+last || renew[0]["hub_sig"] != nil || renew[0]["approver"] != nil {
		t.Fatalf("renewal records of an expired pending ticket %v", renew)
	}
}
