package console

import (
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// Every hub-mode plan ticket is a version-2 one that names its kind and
// its profile, so that `lox run`'s rules can decide it (locksql#195): a
// version-1 ticket is always asked. The risk and flags stay the lock's.
func TestHubTicketKindAndSubject(t *testing.T) {
	for _, prod := range []bool{false, true} {
		p := autoProfile(nil)
		if prod {
			p.Name, p.Host, p.Production, p.Limits = "prod", "db.example.com", true, config.DefaultLimits(true)
		}
		for _, tc := range []struct {
			action    config.AutoAction
			kind      ticket.Kind
			risk      ticket.Risk
			neverAuto bool
		}{
			{config.ActionRead, ticket.KindRead, ticket.RiskRead, false},
			{config.ActionUnmask, ticket.KindRead, ticket.RiskReadPII, true},
			{config.ActionWrite, ticket.KindWrite, ticket.RiskWrite, true},
			{config.ActionDDL, ticket.KindDDL, ticket.RiskWrite, true},
		} {
			t.Run(p.Name+"/"+string(tc.action), func(t *testing.T) {
				var sql string
				var unmask bool
				for _, st := range autoStatements {
					if st.action == tc.action {
						sql, unmask = st.sql, st.unmask
					}
				}
				risk := tc.risk
				if prod && tc.kind != ticket.KindRead {
					risk = ticket.RiskProdWrite
				}
				h := newHarness(t, p, allowUnmask)
				pr := h.plan(t, sql, unmask)
				tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
				got := pushedTicket(t, h.hub, tk)
				if got.V != ticket.VersionKinds || got.Kind != tc.kind || got.Subject == nil || got.Subject.Profile != p.Name {
					t.Fatalf("ticket v%d kind %q subject %+v, want v%d %s of profile %s", got.V, got.Kind, got.Subject, ticket.VersionKinds, tc.kind, p.Name)
				}
				if got.Risk != risk || got.Flags.NeverAuto != tc.neverAuto || got.Flags.Production != prod || got.Flags.Retype != "" {
					t.Fatalf("risk %s flags %+v, want %s never_auto %v production %v", got.Risk, got.Flags, risk, tc.neverAuto, prod)
				}
			})
		}
	}
}

// read = ask marks a version-2 read never-auto, like any other ticket.
func TestHubTicketReadAskIsNeverAuto(t *testing.T) {
	r := config.DefaultAutoRules
	r.Read = config.AutoAsk
	h := newHarness(t, autoProfile(&r))
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if got := pushedTicket(t, h.hub, tk); got.Kind != ticket.KindRead || !got.Flags.NeverAuto {
		t.Fatalf("read = ask: kind %q flags %+v", got.Kind, got.Flags)
	}
}

// A production SELECT under the default rules, approved by lox run's
// default read rule, runs with no question, and the audit names the rule.
func TestHubTicketProductionReadAutoApproved(t *testing.T) {
	p := prodProfile()
	h := newHarness(t, p)
	pr := h.plan(t, selectUsers, false)
	tk := pendingTicket(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	if got := pushedTicket(t, h.hub, tk); got.V != ticket.VersionKinds || got.Kind != ticket.KindRead || got.Flags.NeverAuto {
		t.Fatalf("ticket v%d kind %q flags %+v", got.V, got.Kind, got.Flags)
	}
	autoDecide(t, h.hub, tk, "default:read")
	if r := runTicket(t, h, tk); r.Error != nil {
		t.Fatalf("auto-approved production read: %q", r.Error.Message)
	}
	approved := auditRecords(t, h, "approved", tk)
	if len(approved) != 1 || approved[0]["decided_by"] != "auto:default:read" {
		t.Fatalf("approved records %v", approved)
	}
	if h.io.promptCount() != 0 {
		t.Fatalf("asked on the terminal: %q", h.io.prompts)
	}
}

// A grant's ticket is a version-2 read of risk grant, never auto.
func TestHubGrantTicketKind(t *testing.T) {
	h := newHarness(t, prodProfile())
	tk := askGrant(t, h, ipc.GrantParams{Tables: []string{"users"}})
	got := pushedTicket(t, h.hub, tk)
	if got.V != ticket.VersionKinds || got.Kind != ticket.KindRead || got.Subject == nil || got.Subject.Profile != "prod" ||
		got.Risk != ticket.RiskGrant || !got.Flags.NeverAuto {
		t.Fatalf("grant ticket v%d kind %q subject %+v risk %s flags %+v", got.V, got.Kind, got.Subject, got.Risk, got.Flags)
	}
}
