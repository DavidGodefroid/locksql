package console

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// One statement of each action the auto rules decide.
var autoStatements = []struct {
	action config.AutoAction
	sql    string
	unmask bool
}{
	{config.ActionRead, selectUsers, false},
	{config.ActionUnmask, selectUsers, true},
	{config.ActionWrite, "UPDATE users SET note = 'x' WHERE id = 1", false},
	{config.ActionDDL, "CREATE TABLE t2 (id INT)", false},
}

func autoProfile(r *config.AutoRules) config.Profile {
	p := uatProfile()
	p.Tier, p.Auto = config.TierDDL, r
	return p
}

// neverAutoOf reads the never-auto flag of the ticket the hub received.
func neverAutoOf(t *testing.T, hub *hubtest.Hub, tk string) bool {
	t.Helper()
	var v struct {
		Flags struct {
			NeverAuto bool `json:"never_auto"`
		} `json:"flags"`
	}
	raw := hub.Ticket(tk)
	if raw == nil || json.Unmarshal(raw, &v) != nil {
		t.Fatalf("hub ticket %s: %s", tk, raw)
	}
	return v.Flags.NeverAuto
}

func refusalCode(resp ipc.Response) refusal.Code {
	if resp.Error == nil || resp.Error.Data == nil {
		return ""
	}
	return resp.Error.Data.Code
}

// Each action × each value: auto leaves the ticket to lox run's auto mode,
// ask marks it never-auto, deny refuses at plan time, before any ticket.
func TestAutoRulesEveryActionAndValue(t *testing.T) {
	for _, st := range autoStatements {
		for _, v := range []config.AutoValue{config.AutoAuto, config.AutoAsk, config.AutoDeny} {
			t.Run(string(st.action)+"="+string(v), func(t *testing.T) {
				r := config.DefaultAutoRules
				switch st.action {
				case config.ActionRead:
					r.Read = v
				case config.ActionUnmask:
					// Read stays auto: the unmask rule alone decides.
					r.Unmask = v
				case config.ActionWrite:
					r.Write = v
				case config.ActionDDL:
					r.DDL = v
				}
				h := newHarness(t, autoProfile(&r), allowUnmask)
				resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: st.sql, Unmask: st.unmask})
				if v == config.AutoDeny {
					wantCode(t, resp, ipc.CodeRefused)
					if refusalCode(resp) != refusal.AutoDeny || !strings.Contains(resp.Error.Message, "auto."+string(st.action)+" = deny") {
						t.Fatalf("refusal %q, want E_AUTO_DENY naming auto.%s", resp.Error.Message, st.action)
					}
					if h.hub.Pushed() != 0 {
						t.Fatal("a denied action reached the hub")
					}
					if log := h.auditLog(t); !strings.Contains(log, `"code":"E_AUTO_DENY"`) || !strings.Contains(log, `"auto_rule":"auto.`+string(st.action)+` = deny"`) {
						t.Fatalf("audit:\n%s", log)
					}
					return
				}
				if resp.Error != nil {
					t.Fatalf("plan: %q", resp.Error.Message)
				}
				var pr ipc.PlanResult
				if err := json.Unmarshal(resp.Result, &pr); err != nil {
					t.Fatal(err)
				}
				tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
				if got, want := neverAutoOf(t, h.hub, tk), v == config.AutoAsk; got != want {
					t.Fatalf("never_auto %v, want %v", got, want)
				}
				if log := h.auditLog(t); !strings.Contains(log, `"auto_rule":"auto.`+string(st.action)+` = `+string(v)+`"`) {
					t.Fatalf("pending record without its rule:\n%s", log)
				}
			})
		}
	}
}

// An unmasked read is decided by the stricter of read and unmask.
func TestAutoRulesUnmaskedReadTakesTheStricter(t *testing.T) {
	r := config.AutoRules{Read: config.AutoAsk, Unmask: config.AutoAuto}
	h := newHarness(t, autoProfile(&r), allowUnmask)
	pr := h.plan(t, selectUsers, true)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if !neverAutoOf(t, h.hub, tk) {
		t.Fatal("read = ask, unmask = auto: an unmasked read left to auto")
	}
	r = config.AutoRules{Read: config.AutoDeny, Unmask: config.AutoAuto}
	h = newHarness(t, autoProfile(&r), allowUnmask)
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Unmask: true})
	if refusalCode(resp) != refusal.AutoDeny {
		t.Fatalf("read = deny: unmasked read %+v", resp.Error)
	}
}

// The defaults: reads auto, writes and schema changes asked.
func TestAutoRulesDefaultsOnTickets(t *testing.T) {
	h := newHarness(t, autoProfile(nil))
	for _, st := range autoStatements {
		if st.unmask {
			continue
		}
		pr := h.plan(t, st.sql, false)
		tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
		if got := neverAutoOf(t, h.hub, tk); got != (st.action != config.ActionRead) {
			t.Errorf("%s: never_auto %v", st.action, got)
		}
	}
}

// autoDecide approves tk as the auto rule id of a decider (lox run) would.
func autoDecide(t *testing.T, hub *hubtest.Hub, tk, id string) *ticket.Decision {
	t.Helper()
	return decideSigned(t, hub, tk, ticket.Approved, "", func(d *ticket.Decision) {
		d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleAuto, ID: id}
	})
}

// The lock holds its rules whatever the decider does: an auto rule's
// approval of an asked write is refused and nothing runs; an auto read
// auto-approved runs, and the audit names the rule in force and the rule
// that decided.
func TestAutoRulesLockRefusesAutoApprovalOfAskedTicket(t *testing.T) {
	h := newHarness(t, autoProfile(nil))
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	autoDecide(t, h.hub, tk, "auto-write")
	resp := runTicket(t, h, tk)
	wantCode(t, resp, ipc.CodeDenied)
	if !strings.Contains(resp.Error.Message, "approved by an auto rule") {
		t.Fatalf("message %q", resp.Error.Message)
	}
	if h.sess.runCount() != 0 {
		t.Fatalf("ran %d statements on an auto approval of an asked write", h.sess.runCount())
	}
	refused := auditRecords(t, h, "refused", tk)
	if len(refused) != 1 || refused[0]["decided_by"] != "auto:auto-write" || refused[0]["auto_rule"] != "auto.write = ask" {
		t.Fatalf("refused records %v", refused)
	}

	pr = h.plan(t, selectUsers, false)
	tk = pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	autoDecide(t, h.hub, tk, "auto-read")
	if r := runTicket(t, h, tk); r.Error != nil {
		t.Fatalf("auto read: %q", r.Error.Message)
	}
	approved := auditRecords(t, h, "approved", tk)
	if len(approved) != 1 || approved[0]["decided_by"] != "auto:auto-read" || approved[0]["auto_rule"] != "auto.read = auto" {
		t.Fatalf("approved records %v", approved)
	}

	// A human's approval of the asked write runs it.
	pr = h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	tk = pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	decideSigned(t, h.hub, tk, ticket.Approved, "", func(d *ticket.Decision) {
		d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleHuman}
	})
	if r := runTicket(t, h, tk); r.Error != nil {
		t.Fatalf("human-approved write: %q", r.Error.Message)
	}
	approved = auditRecords(t, h, "approved", tk)
	if len(approved) != 1 || approved[0]["decided_by"] != "human" || approved[0]["auto_rule"] != "auto.write = ask" {
		t.Fatalf("approved records %v", approved)
	}
}

// A rule tightened to deny after the plan refuses at run time; loosening
// one is a policy loosening, reviewed like any other.
func TestAutoRulesTightenedToDenyAfterThePlan(t *testing.T) {
	cur := config.NewPolicy(autoProfile(nil), []string{"app.users.email"}, nil)
	h := newHarness(t, autoProfile(nil), func(c *ServerConfig) {
		c.LoadPolicy = func() (config.Policy, error) { return cur, nil }
	})
	pr := h.plan(t, "UPDATE users SET note = 'x' WHERE id = 1", false)
	cur = config.NewPolicy(autoProfile(&config.AutoRules{Write: config.AutoDeny}), []string{"app.users.email"}, nil)
	h.s.CheckPolicy()
	if h.io.promptCount() != 0 {
		t.Fatal("a tightening of the auto rules asked")
	}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if refusalCode(resp) != refusal.AutoDeny {
		t.Fatalf("run after write = deny: %+v", resp.Error)
	}
}

// Loosening the auto rules of a production profile at :review takes the
// typed profile name (lockkit#8); a plain y refuses it.
func TestAutoRulesProductionLooseningNeedsTheName(t *testing.T) {
	for _, tc := range []struct {
		answer  string
		applied bool
	}{{"y", false}, {"prod", true}} {
		start := prodProfile()
		h := newHarness(t, start)
		next := start
		next.Auto = &config.FullAutoRules
		h.s.setPending(config.NewPolicy(next, []string{"app.users.email"}, nil))
		h.io.answers = []string{tc.answer}
		h.s.Command(context.Background(), ":review")
		if !strings.Contains(strings.Join(h.io.prompts, "\n"), `Type the profile name "prod"`) {
			t.Fatalf("prompts %q", h.io.prompts)
		}
		if got := h.s.profile.AutoRules() == config.FullAutoRules; got != tc.applied {
			t.Fatalf("answer %q: full-auto applied %v\n%s", tc.answer, got, h.io.output())
		}
		if !strings.Contains(h.io.output(), "auto.write: ask → auto  (loosens)") {
			t.Errorf("the loosening is not listed:\n%s", h.io.output())
		}
	}
}

// Grants are reads: read = deny refuses them.
func TestAutoRulesReadDenyRefusesGrants(t *testing.T) {
	h := newHarness(t, autoProfile(&config.AutoRules{Read: config.AutoDeny}))
	resp := h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: ipc.Requester{Agent: "a", Token: "tok-a"}, DB: "app", Tables: []string{"users"}})
	if refusalCode(resp) != refusal.AutoDeny {
		t.Fatalf("grant under read = deny: %+v", resp.Error)
	}
}

// The status answer and :status show the rules in force.
func TestAutoRulesInStatus(t *testing.T) {
	h := newHarness(t, autoProfile(&config.FullAutoRules))
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Auto != config.FullAutoRules {
		t.Fatalf("status auto %+v", st.Auto)
	}
	if got := strings.Join(describePolicy(h.s.approved), "\n"); !strings.Contains(got, "auto mode (lox run): connect auto · read auto · write auto · ddl auto · unmask auto (full-auto)") {
		t.Fatalf("describePolicy:\n%s", got)
	}
}
