package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// Hub mode (--hub, --hub-key-file, --instance): the human decides in
// lockhub, not on this terminal. query.run answers pending with a ticket;
// query.run with that ticket runs the plan once the hub's signed decision
// approves it, after planning the statement again: a plan hash that no
// longer matches answers stale, with a new ticket.

// hubPlan is the body of a hub-mode plan in the plans store: what the run
// of its ticket plans again from (the store survives a restart).
type hubPlan struct {
	DB     string `json:"db"`
	SQL    string `json:"sql"`
	Unmask bool   `json:"unmask,omitempty"`
	Intent string `json:"intent,omitempty"`
	// Refuse: the weight check refused it under a PII filter; the refusal
	// waits for the decision, so that answering tells no more than one.
	Refuse bool `json:"refuse,omitempty"`
}

// hubCaller is the client behind ctx, the only one that may run the
// ticket of its plan. Clients send no requester token yet: the peer's
// account binds the plan.
func hubCaller(ctx context.Context) plans.Caller {
	c, _ := kconsole.PeerFrom(ctx)
	return plans.Caller{UID: c.UID}
}

// hubRisk is the risk class of pl's ticket.
func (s *Server) hubRisk(pl *plan) ticket.Risk {
	switch {
	case pl.st.Class != sqlclass.Read && s.profile.Production:
		return ticket.RiskProdWrite
	case pl.st.Class != sqlclass.Read:
		return ticket.RiskWrite
	case pl.unmask:
		return ticket.RiskReadPII
	}
	return ticket.RiskRead
}

// hubScreen is the approval screen of pl as it leaves the lock: the
// structure of the statement, every literal masked (the hub and its
// facades never see a value of the statement in clear), the verdict and
// the warnings.
func (s *Server) hubScreen(pl *plan) render.MaskedScreen {
	db := pl.db
	if db == "" {
		db = "(default)"
	}
	src := render.ScreenSource{
		Header: fmt.Sprintf("%s / %s · tier %s", s.host(), db, s.profile.Tier),
		Note:   pl.intent, Warnings: pl.warnings, Red: s.profile.Production || pl.st.Class != sqlclass.Read,
	}
	for _, l := range strings.Split(pl.st.SQL, "\n") {
		src.Body = append(src.Body, statementLine(s.dialect, l))
	}
	class := strings.ToUpper(pl.st.Class.String())
	src.Body = append(src.Body, render.Structure(""), render.Structure(fmt.Sprintf("class %s · verdict %s", class, pl.level)))
	if pl.unmask {
		src.Body = append(src.Body, render.Structure("PII: UNMASKED"))
	}
	return render.MaskScreen(src, render.Masking{Detectors: s.detectors, Personal: func(string, string) bool { return true }})
}

// statementLine is one line of a statement in parts: its literals values,
// the rest structure.
func statementLine(d sqlclass.Dialect, line string) render.Line {
	toks, err := sqlclass.Lex(d, line)
	if err != nil {
		return render.Line{{Text: line, Value: true, Column: "statement"}}
	}
	var out render.Line
	pos := 0
	for _, t := range toks {
		if t.Kind != sqlclass.TokString && t.Kind != sqlclass.TokNumber {
			continue
		}
		if t.Pos > pos {
			out = append(out, render.Part{Text: line[pos:t.Pos]})
		}
		out = append(out, render.Part{Text: line[t.Pos:t.End], Value: true, Column: "literal"})
		pos = t.End
	}
	if pos < len(line) {
		out = append(out, render.Part{Text: line[pos:]})
	}
	return out
}

// hubSubmit hands pl to the hub instead of asking here: the plan goes to
// the plans store, bound to the client and the plan hash, and the client
// gets pending with the ticket. hidden is a refusal the human must see
// first (estimates hidden under a PII filter).
func (s *Server) hubSubmit(ctx context.Context, id int64, sess engine.Session, pl *plan, rec audit.Record, hidden *refusal.Error) ipc.Response {
	if pl.an != nil && len(pl.an.Values) > 0 {
		return s.refuseRec(id, rec, pl.src, refusal.New(refusal.Placeholder, "placeholders and cell references are typed in the console: not in hub mode; write the statement without them"))
	}
	if hidden == nil {
		kw, refused, err := s.kCount(ctx, sess, pl)
		if refused != nil {
			return s.refuseWarned(ctx, id, pl, rec.Class, refused)
		}
		if err != nil {
			s.auditRunFailed(rec, s.auditErrText(err, pl))
			return s.failedPlan(id, "k-anonymity check", err, pl)
		}
		pl.warnings = append(pl.warnings, kw...)
		rec.Warnings = pl.warnings
	}
	fp, err := ticket.HashOf(s.approved)
	if err != nil {
		return errResp(id, ipc.CodeInternal, "policy fingerprint: "+err.Error())
	}
	body, err := json.Marshal(hubPlan{DB: pl.db, SQL: pl.src, Unmask: pl.unmask, Intent: pl.intent, Refuse: hidden != nil})
	if err != nil {
		return errResp(id, ipc.CodeInternal, err.Error())
	}
	caller := hubCaller(ctx)
	h := s.cfg.Hub
	hp, err := h.Store.Create(plans.Binding{UID: caller.UID, TokenHash: plans.HashToken(caller.Token), PolicyFP: fp, PlanHash: pl.hash}, body, 0)
	if err != nil {
		return errResp(id, ipc.CodeInternal, "plan store: "+err.Error())
	}
	sc := &kconsole.Screen{Hub: &kconsole.HubTicket{PlanID: hp.ID, Caller: caller, Risk: s.hubRisk(pl), Masked: s.hubScreen(pl),
		Requester: ticket.Requester{Agent: kconsole.PeerText(ctx)}}}
	a := s.asker().Ask(ctx, id, kconsole.Ask{Frame: s.frameColour(), Production: s.profile.Production, Screen: sc}, func(b kaudit.Base) {
		rec.Event, rec.Decision, rec.Reason, rec.Error, rec.Approval = b.Event, b.Decision, b.Reason, b.Error, b.Approval
		if b.Ticket != "" {
			// The 0.8 record has no ticket field yet (#92).
			rec.Reason = "ticket " + b.Ticket
		}
		s.audit(rec)
	})
	return a.Refusal
}

// queryRunTicket runs the plan of a decided ticket: the hub's decision is
// verified and matched (hubclient.Begin), the statement planned again from
// the stored text, and its plan hash and policy compared with the plan's
// before anything runs; the run itself checks the hash again in its own
// transaction.
func (s *Server) queryRunTicket(ctx context.Context, id int64, ticketID string) ipc.Response {
	h := s.cfg.Hub
	if h == nil {
		return errResp(id, ipc.CodeInvalidParams, "this console is not in hub mode: run a plan by its plan_id")
	}
	caller := hubCaller(ctx)
	var pl *plan
	var body hubPlan
	var planResp *ipc.Response
	hp, dec, err := h.Client.Begin(h.Store, ticketID, caller, func(p *plans.Plan) (string, string, error) {
		if err := json.Unmarshal(p.Body, &body); err != nil {
			return "", "", err
		}
		pl, planResp = s.buildPlan(ctx, id, ipc.PlanParams{DB: body.DB, SQL: body.SQL, Unmask: body.Unmask, Intent: body.Intent})
		if planResp != nil {
			return "", "", errReplan
		}
		fp, err := ticket.HashOf(s.approved)
		return fp, pl.hash, err
	})
	switch {
	case errors.Is(err, errReplan):
		s.withdraw(ctx, ticketID, caller)
		return *planResp
	case errors.Is(err, plans.ErrStale):
		return s.hubStale(ctx, id, body, ticketID)
	case errors.Is(err, hubclient.ErrDenied):
		msg := "denied by the human; do not retry unless asked"
		if _, reason, ok := strings.Cut(err.Error(), ": "); ok && reason != "denied" {
			msg = "denied by the human: " + s.safeReason(reason) + "; do not retry unless asked"
		}
		return errResp(id, ipc.CodeDenied, msg)
	case err != nil:
		return errResp(id, ipc.CodeDenied, "ticket "+ticketID+": "+s.safeReason(err.Error()))
	}
	finish := func(ok bool, reason string) {
		if err := h.Client.Finish(ctx, h.Store, hp.ID, caller, ok, reason); err != nil {
			s.println(paint.Fail("hub: " + safeText(err.Error(), false)))
		}
	}
	sess, r := s.session(ctx, id)
	if r != nil {
		finish(false, "connection lost")
		return *r
	}
	class := pl.st.Class.String()
	pl.warnings = s.warnings(ctx, sess, pl)
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask,
		Warnings: pl.warnings, Intent: pl.intent})
	if body.Refuse {
		finish(false, "refused by the weight check")
		return refusedResp(id, hiddenWeightRefusal, refusal.New(refusal.Cost, hiddenWeightRefusal).Info("", 0))
	}
	s.println(paint.Step("ticket " + safeText(ticketID, false) + " approved in lockhub: running"))
	rec.Event, rec.Decision, rec.Approval, rec.Reason = audit.EventApproved, "approved", kconsole.HubApproval, "ticket "+ticketID
	if dec != nil {
		rec.Reason += " approved by " + dec.Approver.ID + " on " + dec.Facade
	}
	resp := s.runApproved(ctx, id, sess, pl, rec, class, time.Time{})
	if resp.Error != nil {
		if d := resp.Error.Data; d != nil && d.Code == refusal.Stale {
			finish(false, "stale")
			return s.hubStale(ctx, id, body, ticketID)
		}
		finish(false, "failed")
		return resp
	}
	finish(true, "")
	return resp
}

// errReplan marks a run whose statement no longer plans.
var errReplan = errors.New("console: the statement no longer plans")

// hubStale answers a ticket whose plan no longer matches: the statement is
// planned and submitted again, and the client gets stale with the new
// ticket.
func (s *Server) hubStale(ctx context.Context, id int64, body hubPlan, old string) ipc.Response {
	s.println(paint.Warn("ticket " + safeText(old, false) + " is stale: what the statement resolves to changed; a new ticket is submitted"))
	pl, r := s.buildPlan(ctx, id, ipc.PlanParams{DB: body.DB, SQL: body.SQL, Unmask: body.Unmask, Intent: body.Intent})
	if r != nil {
		return *r
	}
	sess, r := s.session(ctx, id)
	if r != nil {
		return *r
	}
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: pl.st.Class.String(), Verdict: pl.level, Unmasked: pl.unmask, Intent: pl.intent})
	resp := s.hubSubmit(ctx, id, sess, pl, rec, nil)
	var p struct {
		Status, Ticket string
	}
	if resp.Error != nil || json.Unmarshal(resp.Result, &p) != nil || p.Status != "pending" {
		return resp
	}
	return okResp(id, map[string]string{"status": "stale", "ticket": p.Ticket, "lock": product.P.Name, "stale_ticket": old})
}

// withdraw ends the plan of a ticket that can no longer run.
func (s *Server) withdraw(ctx context.Context, ticketID string, caller plans.Caller) {
	h := s.cfg.Hub
	if p, err := h.Store.ByTicket(ticketID, caller); err == nil {
		_ = h.Client.Withdraw(ctx, h.Store, p.ID, caller, "the statement no longer plans")
	}
}

func (s *Server) safeReason(r string) string { return safeText(r, false) }
