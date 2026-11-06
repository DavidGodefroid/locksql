package console

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

func connectDenyProfile(base config.Profile) config.Profile {
	base.Tier = config.TierDDL
	base.Auto = &config.AutoRules{Connect: config.AutoDeny}
	return base
}

// wantConnectDeniedEnd checks a session ended by connect = deny: ended,
// on record with the rule, and no further statement served.
func wantConnectDeniedEnd(t *testing.T, h *harness, stage string) {
	t.Helper()
	wantConnectDeniedRecord(t, h, stage)
	before := h.sess.runCount()
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers})
	if resp.Error == nil {
		var plan ipc.PlanResult
		if err := json.Unmarshal(resp.Result, &plan); err != nil {
			t.Fatal(err)
		}
		pr := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: plan.PlanID})
		if pr.Error == nil {
			t.Fatalf("a statement was served after connect = deny: %s", pr.Result)
		}
	}
	if h.sess.runCount() != before || h.hub.Pushed() != 0 {
		t.Fatal("a statement ran or reached the hub after connect = deny")
	}
}

// wantConnectDeniedRecord checks a session ended by connect = deny, on
// record with the rule.
func wantConnectDeniedRecord(t *testing.T, h *harness, stage string) {
	t.Helper()
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "auto rules deny the connection") {
		t.Fatalf("session not ended by connect = deny: %q %v\n%s", reason, ended, h.io.output())
	}
	var found bool
	for _, l := range strings.Split(strings.TrimSpace(h.auditLog(t)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		e, _ := r["error"].(string)
		if r["event"] == "login" && r["decision"] == "refused" && r["auto_rule"] == "auto.connect = deny" && strings.HasPrefix(e, stage+": ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no login refused record for %s:\n%s", stage, h.auditLog(t))
	}
}

// connect = deny tightened in the files while the console runs: applied
// at once (a tightening), and the session ends, on record.
func TestAutoRulesConnectDenyFromTheFilesEndsTheSession(t *testing.T) {
	start := autoProfile(nil)
	cur := config.NewPolicy(start, []string{"app.users.email"}, nil)
	h := newHarness(t, start, func(c *ServerConfig) {
		c.LoadPolicy = func() (config.Policy, error) { return cur, nil }
	})
	cur = config.NewPolicy(connectDenyProfile(uatProfile()), []string{"app.users.email"}, nil)
	h.s.CheckPolicy()
	if h.io.promptCount() != 0 {
		t.Fatal("a tightening to connect = deny asked")
	}
	wantConnectDeniedEnd(t, h, "policy changed")
}

// connect = deny in a reviewed change (with a loosening beside it): the
// approved policy ends the session.
func TestAutoRulesConnectDenyAtReviewEndsTheSession(t *testing.T) {
	h := newHarness(t, autoProfile(nil))
	next := connectDenyProfile(uatProfile())
	next.Auto.Write = config.AutoAuto // a loosening: awaits :review
	h.s.setPending(config.NewPolicy(next, []string{"app.users.email"}, nil))
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended before the review")
	}
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	wantConnectDeniedEnd(t, h, "policy changed")
}

// A reconnection under a policy that denies the connection opens
// nothing: the session ends, on record, and Reconnect is never called.
func TestAutoRulesConnectDenyRefusesReconnect(t *testing.T) {
	called := 0
	h := newHarness(t, autoProfile(nil), func(c *ServerConfig) {
		c.Reconnect = func(context.Context, config.Profile) (engine.Session, error) {
			called++
			return nil, errors.New("not reached")
		}
	})
	denied := config.NewPolicy(connectDenyProfile(uatProfile()), []string{"app.users.email"}, nil)
	_, err := h.s.reconnect(context.Background(), kpolicy{denied})
	var end *kconsole.EndError
	if !errors.As(err, &end) || !errors.Is(err, errConnectDenied) {
		t.Fatalf("reconnect under connect = deny: %v", err)
	}
	if called != 0 {
		t.Fatal("Reconnect was called under connect = deny")
	}
	wantConnectDeniedRecord(t, h, "reconnect")
}

// A server is never built on a start policy that denies the connection.
func TestAutoRulesConnectDenyRefusesTheServer(t *testing.T) {
	p := connectDenyProfile(uatProfile())
	log, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{Policy: config.NewPolicy(p, nil, nil), Session: &fakeSession{origin: true, dbs: []string{"app"}}, Audit: log, IO: &fakeIO{}}
	var hub *hubtest.Hub
	attachHub(t, &hub)(&cfg)
	if _, err := NewServer(cfg); !errors.Is(err, errConnectDenied) {
		t.Fatalf("NewServer under connect = deny: %v", err)
	}
}

// An auto rule's approval of a grant is refused by the lock: the grant
// is not activated, the refusal is on record, the ticket withdrawn.
// Under read = auto too: a grant covers many reads, only a human grants
// one.
func TestAutoRulesLockRefusesAutoApprovalOfGrant(t *testing.T) {
	h := newHarness(t, autoProfile(&config.FullAutoRules))
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	if !neverAutoOf(t, h.hub, tk) {
		t.Fatal("a grant ticket left to auto")
	}
	if pend := auditRecords(t, h, "pending", tk); len(pend) != 1 || pend[0]["auto_rule"] != "auto.read = auto" {
		t.Fatalf("pending records %v", pend)
	}
	autoDecide(t, h.hub, tk, "auto-grant")
	resp := activateGrant(t, h, tk, ipc.Requester{})
	wantCode(t, resp, ipc.CodeDenied)
	if !strings.Contains(resp.Error.Message, "approved by an auto rule") {
		t.Fatalf("message %q", resp.Error.Message)
	}
	if g := grantStatus(t, h); len(g) != 0 {
		t.Fatalf("grant activated on an auto approval: %+v", g)
	}
	refused := auditRecords(t, h, "refused", tk)
	if len(refused) != 1 || refused[0]["decided_by"] != "auto:auto-grant" || refused[0]["grant_scope"] == nil {
		t.Fatalf("refused records %v", refused)
	}
	if _, ok := h.hub.Withdrawn(tk); !ok {
		t.Fatal("the ticket was not withdrawn")
	}
	if r := auditRecords(t, h, "grant", tk); len(r) != 0 {
		t.Fatalf("grant records %v", r)
	}
	// A human's approval of a new grant activates it.
	tk = askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	decideSigned(t, h.hub, tk, ticket.Approved, "", func(d *ticket.Decision) {
		d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleHuman}
	})
	if r := activateGrant(t, h, tk, ipc.Requester{}); r.Error != nil {
		t.Fatalf("human-approved grant: %q", r.Error.Message)
	}
}
