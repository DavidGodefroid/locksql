package console

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
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
	"github.com/DavidGodefroid/locksql/internal/weight"
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
	// MaxAffected is the most rows the write may change, shown on the
	// ticket's screen: the run checks it in its own transaction, before
	// the commit, and rolls back as stale past it (0: not a write).
	MaxAffected int64 `json:"max_affected,omitempty"`
}

// hubCaller is the client behind ctx and the agent it reports, the only
// one that may run the ticket of its plan: the peer's account and the
// agent's lea token (plans.Caller; the store keeps the token hashed).
func hubCaller(ctx context.Context, who ipc.Requester) plans.Caller {
	c, _ := kconsole.PeerFrom(ctx)
	return plans.Caller{UID: c.UID, Token: who.Token}
}

// wrongRequester answers a plan or ticket presented by another agent.
const wrongRequester = "this plan was asked for by another agent: only the agent that planned it may run it; plan the query yourself"

// sameRequester reports that b is the agent that made a plan for a
// (same lea token; both empty outside lea).
func sameRequester(a, b ipc.Requester) bool {
	return subtle.ConstantTimeCompare([]byte(plans.HashToken(a.Token)), []byte(plans.HashToken(b.Token))) == 1
}

// agentName is the requesting agent as the screens name it: the peer as
// the kernel reports it, then the lea name the client sent, labelled as
// its unverified claim (any agent of the account can send any name).
func agentName(ctx context.Context, who ipc.Requester) string {
	peer := kconsole.PeerText(ctx)
	if who.Agent == "" {
		return peer
	}
	name := who.Agent
	if r := []rune(name); len(r) > 64 {
		name = string(r[:64]) + "…"
	}
	name = safeText(name, false)
	return peer + " · claims lea agent " + strconv.Quote(name)
}

// nestedDML reports a statement with a data-modifying statement inside
// it (PostgreSQL's WITH u AS (DELETE ...) ...): its command tag counts
// only the outer statement's rows, so its rowcount bound would not hold.
// Only PostgreSQL has them, and only as the body of a WITH query: the
// word right after "AS (" or "[NOT] MATERIALIZED (".
func nestedDML(d sqlclass.Dialect, sql string) bool {
	if d != sqlclass.Postgres {
		return false
	}
	toks, err := sqlclass.Lex(d, sql)
	if err != nil {
		return true
	}
	word := func(i int, w string) bool {
		return i >= 0 && toks[i].Kind == sqlclass.TokWord && toks[i].Text == w
	}
	for i, t := range toks {
		if t.Kind != sqlclass.TokWord || i < 2 {
			continue
		}
		switch t.Text {
		case "INSERT", "UPDATE", "DELETE", "MERGE":
		default:
			continue
		}
		if toks[i-1].Kind == sqlclass.TokPunct && toks[i-1].Text == "(" && (word(i-2, "AS") || word(i-2, "MATERIALIZED")) {
			return true
		}
	}
	return false
}

// sideEffects lists, from the definitions a write resolves to, what
// changes rows beside the statement itself: triggers, rules and foreign
// keys that cascade (ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT).
func sideEffects(st engine.ObjectState) []string {
	var out []string
	for _, o := range st.Objects {
		switch o.Kind {
		case "trigger", "rule":
			out = append(out, o.Kind+" "+o.Name)
		case "function":
			// A volatile function may write; its rows are not the
			// statement's. provolatile is the first field, one letter.
			if vol, _, _ := strings.Cut(o.Def, "\x1f"); vol == "v" {
				out = append(out, "function "+o.Name)
			}
		case "constraint":
			def := strings.ToUpper(o.Def)
			for _, a := range []string{"CASCADE", "SET NULL", "SET DEFAULT"} {
				if strings.Contains(def, "ON DELETE "+a) || strings.Contains(def, "ON UPDATE "+a) {
					out = append(out, "foreign key "+o.Name)
					break
				}
			}
		}
	}
	return out
}

// bindRows sets the rowcount bound of pl from its stored body. A write
// stored without one (a plan store from an older console) never runs
// unbounded: it is stale, planned again with a bound.
func (pl *plan) bindRows(body hubPlan) error {
	pl.maxAffected = body.MaxAffected
	if pl.st.Class == sqlclass.Write && body.MaxAffected <= 0 {
		return fmt.Errorf("%w: the write has no rowcount bound", plans.ErrStale)
	}
	return nil
}

// rowSlack is the margin of a write's rowcount bound over its estimate.
const rowSlack = 10

// rowBound is the rowcount bound of a write expected to change about n
// rows: twice as many, and at least rowSlack more.
func rowBound(n int64) int64 {
	n = max(n, 0)
	if n > math.MaxInt64/2-rowSlack {
		return math.MaxInt64
	}
	return n + max(n, rowSlack)
}

// writeEstimate is the planner's estimate of the rows a write changes
// (EXPLAIN without running it), 0 when the engine gives none.
func (s *Server) writeEstimate(ctx context.Context, sess engine.Session, pl *plan) int64 {
	ep, err := sess.Explain(ctx, pl.db, pl.st.SQL)
	if err != nil {
		return 0
	}
	return weight.Assess(ep, s.profile.Limits, s.profile.Production).EstimatedRows
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
	src.Body = append(src.Body, statementLines(s.dialect, pl.st.SQL)...)
	class := strings.ToUpper(pl.st.Class.String())
	src.Body = append(src.Body, render.Structure(""), render.Structure(fmt.Sprintf("class %s · verdict %s", class, pl.level)))
	if pl.unmask {
		src.Body = append(src.Body, render.Structure("PII: UNMASKED"))
	}
	if pl.maxAffected > 0 {
		src.Body = append(src.Body, render.Structure(fmt.Sprintf("rows changed: at most %d by the statement itself (checked before the commit; more rolls back); rows changed by triggers, rules, foreign-key cascades or functions are not counted", pl.maxAffected)))
	}
	return render.MaskScreen(src, render.Masking{Detectors: s.detectors, Personal: func(string, string) bool { return true }})
}

// statementLines are the lines of a statement in parts: its literals
// values, the rest structure. The statement is lexed whole, so that a
// literal over several lines is a value on each of them; a statement that
// does not lex is a value throughout.
func statementLines(d sqlclass.Dialect, sql string) []render.Line {
	toks, err := sqlclass.Lex(d, sql)
	if err != nil {
		var out []render.Line
		for _, l := range strings.Split(sql, "\n") {
			out = append(out, render.Line{{Text: l, Value: true, Column: "statement"}})
		}
		return out
	}
	// value[i] marks the bytes of sql inside a literal.
	value := make([]bool, len(sql))
	for _, t := range toks {
		if t.Kind == sqlclass.TokString || t.Kind == sqlclass.TokNumber {
			for i := t.Pos; i < t.End; i++ {
				value[i] = true
			}
		}
	}
	var out []render.Line
	var line render.Line
	flush := func(from, to int, v bool) {
		if to <= from {
			return
		}
		part := render.Part{Text: sql[from:to]}
		if v {
			part.Value, part.Column = true, "literal"
		}
		line = append(line, part)
	}
	from := 0
	for i := 0; i <= len(sql); i++ {
		if i == len(sql) || sql[i] == '\n' {
			flush(from, i, from < len(sql) && value[from])
			out = append(out, line)
			line, from = nil, i+1
			continue
		}
		if value[i] != value[from] {
			flush(from, i, value[from])
			from = i
		}
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
	if pl.st.Class == sqlclass.Write && nestedDML(s.dialect, pl.st.SQL) {
		return s.refuseRec(id, rec, pl.src, refusal.New(refusal.StatementKind, "a statement with a data-modifying statement inside it (WITH ... AS (INSERT/UPDATE/DELETE ...)) is not run in hub mode: its row count would not cover every row it changes; write one statement per change"))
	}
	if pl.st.Class == sqlclass.Write {
		if len(pl.sideEffects) > 0 {
			pl.warnings = append(pl.warnings, "rows the bound does not count may change too: "+strings.Join(pl.sideEffects, ", "))
			rec.Warnings = pl.warnings
		}
		// The rows the write may change: about what the planner expects,
		// or what a rolled-back run of an earlier ticket would have
		// changed. The run checks it before its commit (H2).
		pl.maxAffected = rowBound(max(s.writeEstimate(ctx, sess, pl), pl.affected))
		if pl.staleTicket != "" && pl.affected > 0 {
			pl.warnings = append(pl.warnings, fmt.Sprintf("the approved run of ticket %s would have changed %d rows: rolled back", pl.staleTicket, pl.affected))
			rec.Warnings = pl.warnings
		}
	}
	fp, err := ticket.HashOf(s.approved)
	if err != nil {
		return errResp(id, ipc.CodeInternal, "policy fingerprint: "+err.Error())
	}
	body, err := json.Marshal(hubPlan{DB: pl.db, SQL: pl.src, Unmask: pl.unmask, Intent: pl.intent, Refuse: hidden != nil, MaxAffected: pl.maxAffected})
	if err != nil {
		return errResp(id, ipc.CodeInternal, err.Error())
	}
	caller := hubCaller(ctx, pl.requester)
	agent := agentName(ctx, pl.requester)
	h := s.cfg.Hub
	hp, err := h.Store.Create(plans.Binding{UID: caller.UID, Agent: agent, TokenHash: plans.HashToken(caller.Token), PolicyFP: fp, PlanHash: pl.hash}, body, 0)
	if err != nil {
		return errResp(id, ipc.CodeInternal, "plan store: "+err.Error())
	}
	sc := &kconsole.Screen{Hub: &kconsole.HubTicket{PlanID: hp.ID, Caller: caller, Risk: s.hubRisk(pl), Masked: s.hubScreen(pl),
		Requester: ticket.Requester{Agent: agent}}}
	a := s.asker().Ask(ctx, id, kconsole.Ask{Frame: s.frameColour(), Production: s.profile.Production, Screen: sc}, func(b kaudit.Base) {
		rec.Event, rec.Decision, rec.Reason, rec.Error, rec.Approval, rec.Ticket = b.Event, b.Decision, b.Reason, b.Error, b.Approval, b.Ticket
		s.audit(rec)
	})
	return a.Refusal
}

// queryRunTicket runs the plan of a decided ticket: the hub's decision is
// verified and matched (hubclient.Begin), the statement planned again from
// the stored text, and its plan hash and policy compared with the plan's
// before anything runs; the run itself checks the hash again in its own
// transaction.
func (s *Server) queryRunTicket(ctx context.Context, id int64, ticketID string, who ipc.Requester) ipc.Response {
	h := s.cfg.Hub
	if h == nil {
		return errResp(id, ipc.CodeInvalidParams, "this console is not in hub mode: run a plan by its plan_id")
	}
	caller := hubCaller(ctx, who)
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
		pl.requester = who
		if err := pl.bindRows(body); err != nil {
			return "", "", err
		}
		fp, err := ticket.HashOf(s.approved)
		return fp, pl.hash, err
	})
	switch {
	case errors.Is(err, plans.ErrWrongRequester):
		return errResp(id, ipc.CodeWrongRequester, "ticket "+ticketID+": "+wrongRequester)
	case errors.Is(err, errReplan):
		s.withdraw(ctx, ticketID, caller)
		return *planResp
	case errors.Is(err, plans.ErrStale):
		// Ended by Begin when the hash differs; a recheck refusal leaves
		// it pending: withdraw it (a no-op on an ended plan).
		s.withdraw(ctx, ticketID, caller)
		return s.hubStale(ctx, id, body, ticketID, who, 0)
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
	hidden, r := s.runChecks(ctx, id, pl)
	if r != nil {
		finish(false, "refused")
		return *r
	}
	pl.warnings = s.warnings(ctx, sess, pl)
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask,
		Warnings: pl.warnings, Intent: pl.intent})
	if body.Refuse || hidden != nil {
		finish(false, "refused by the weight check")
		return refusedResp(id, hiddenWeightRefusal, refusal.New(refusal.Cost, hiddenWeightRefusal).Info("", 0))
	}
	s.println(paint.Step("ticket " + safeText(ticketID, false) + " approved in lockhub: running"))
	rec.Event, rec.Decision, rec.Approval, rec.Ticket = audit.EventApproved, "approved", kconsole.HubApproval, ticketID
	if dec != nil {
		rec.Approver, rec.Facade = &dec.Approver, dec.Facade
	}
	resp := s.runApproved(ctx, id, sess, pl, rec, class, time.Time{})
	if resp.Error != nil {
		if d := resp.Error.Data; d != nil && d.Code == refusal.Stale {
			finish(false, "stale")
			return s.hubStale(ctx, id, body, ticketID, who, pl.affected)
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
// planned and submitted again, for the same agent, and the client gets
// stale with the new ticket. affected is what a write rolled back for its
// rowcount would have changed (0: another cause): the new ticket's bound
// covers it, and its screen says so.
func (s *Server) hubStale(ctx context.Context, id int64, body hubPlan, old string, who ipc.Requester, affected int64) ipc.Response {
	why := "what the statement resolves to changed"
	if affected > 0 {
		why = fmt.Sprintf("the write would have changed %d rows, more than approved", affected)
	}
	s.println(paint.Warn("ticket " + safeText(old, false) + " is stale: " + why + "; a new ticket is submitted"))
	pl, r := s.buildPlan(ctx, id, ipc.PlanParams{DB: body.DB, SQL: body.SQL, Unmask: body.Unmask, Intent: body.Intent})
	if r != nil {
		return *r
	}
	pl.requester, pl.affected, pl.staleTicket = who, affected, old
	hidden, r := s.runChecks(ctx, id, pl)
	if r != nil {
		return *r
	}
	sess, r := s.session(ctx, id)
	if r != nil {
		return *r
	}
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: pl.st.Class.String(), Verdict: pl.level, Unmasked: pl.unmask, Intent: pl.intent})
	resp := s.hubSubmit(ctx, id, sess, pl, rec, hidden)
	var p struct {
		Status, Ticket string
	}
	if resp.Error != nil || json.Unmarshal(resp.Result, &p) != nil || p.Status != "pending" {
		return resp
	}
	return okResp(id, map[string]string{"status": "stale", "ticket": p.Ticket, "lock": product.P.Name, "instance": s.cfg.Hub.Instance, "stale_ticket": old})
}

// withdraw ends the plan of a ticket that can no longer run.
func (s *Server) withdraw(ctx context.Context, ticketID string, caller plans.Caller) {
	h := s.cfg.Hub
	if p, err := h.Store.ByTicket(ticketID, caller); err == nil {
		_ = h.Client.Withdraw(ctx, h.Store, p.ID, caller, "the statement no longer plans")
	}
}

func (s *Server) safeReason(r string) string { return safeText(r, false) }
