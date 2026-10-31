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
	"github.com/DavidGodefroid/locksql/internal/pii"
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
	// KWarnings are the k-anonymity warnings of the counts run before the
	// ticket: the records of its run carry them, as the ticket did. They
	// name columns and counts, never a value.
	KWarnings []string `json:"k_warnings,omitempty"`
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
// (EXPLAIN without running it), 0 when the engine gives none, and at least
// the rows of its VALUES list (EXPLAIN gives none for them on MySQL and
// SQLite).
func (s *Server) writeEstimate(ctx context.Context, sess engine.Session, pl *plan) int64 {
	n := sqlclass.ValuesRows(s.dialect, pl.st.SQL)
	ep, err := sess.Explain(ctx, pl.db, pl.st.SQL)
	if err != nil {
		return n
	}
	return max(n, weight.Assess(ep, s.profile.Limits, s.profile.Production).EstimatedRows)
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
// the warnings. clear is the same screen unmasked: it stays in the plan
// (hubclient.SubmitClear), sealed only to a pinned device or to a pinned
// local facade that asks for it (a reveal, Ctrl-O).
func (s *Server) hubScreen(pl *plan) (masked render.MaskedScreen, clear kconsole.Screen) {
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
	return render.MaskScreen(src, render.Masking{Detectors: s.detectors, Personal: func(string, string) bool { return true }}), clearScreen(src)
}

// clearScreen is src as the console's clear screen: each line its parts'
// text, values included.
func clearScreen(src render.ScreenSource) kconsole.Screen {
	sc := kconsole.Screen{Header: src.Header, Note: src.Note, Warnings: src.Warnings, Red: src.Red}
	for _, l := range src.Body {
		var b strings.Builder
		for _, p := range l {
			b.WriteString(p.Text)
		}
		sc.Body = append(sc.Body, b.String())
	}
	return sc
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
	var kw []string
	if hidden == nil {
		var refused *refusal.Error
		var err error
		kw, refused, err = s.kCount(ctx, sess, pl)
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
	body, err := json.Marshal(hubPlan{DB: pl.db, SQL: pl.src, Unmask: pl.unmask, Intent: pl.intent, Refuse: hidden != nil, MaxAffected: pl.maxAffected, KWarnings: kw})
	if err != nil {
		return errResp(id, ipc.CodeInternal, err.Error())
	}
	caller := hubCaller(ctx, pl.requester)
	agent := agentName(ctx, pl.requester)
	h := s.cfg.Hub
	hp, err := h.Store.Create(plans.Binding{UID: caller.UID, Agent: agent, TokenHash: plans.HashToken(caller.Token), PolicyFP: fp, PlanHash: pl.hash, Inputs: pl.inputs}, body, 0)
	if err != nil {
		return errResp(id, ipc.CodeInternal, "plan store: "+err.Error())
	}
	// The screen carries the clear text too: the console's Submit hands it
	// to SubmitClear, for a reveal or a pinned device.
	masked, clear := s.hubScreen(pl)
	sc := &clear
	sc.Hub = &kconsole.HubTicket{PlanID: hp.ID, Caller: caller, Risk: s.hubRisk(pl), Masked: masked,
		Requester: ticket.Requester{Agent: agent}}
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
	case errors.Is(err, ticket.ErrExpired):
		return s.hubRenew(ctx, id, ticketID, caller, who, dec)
	case errors.Is(err, errReplan):
		s.withdraw(ctx, ticketID, caller)
		if e := planResp.Error; e != nil && e.Data == nil && dec != nil && dec.Decision == ticket.Approved {
			// Approved in lockhub, but the statement could not be planned
			// again: the run failed. A refusal, which carries its data, is
			// audited by buildPlan.
			s.auditReplanFailed(ctx, ticketID, body, dec, e.Message)
		}
		return *planResp
	case errors.Is(err, plans.ErrStale):
		// Ended by Begin when the hash differs; a recheck refusal leaves
		// it pending: withdraw it (a no-op on an ended plan).
		s.withdraw(ctx, ticketID, caller)
		return s.hubStale(ctx, id, body, ticketID, who, 0)
	case errors.Is(err, hubclient.ErrDenied):
		if dec != nil {
			s.auditHubDenial(ctx, ticketID, dec)
		}
		// The human's reason: the decision's, or what follows the
		// sentinel's own text ("hubclient: denied: <reason>").
		reason := strings.TrimPrefix(err.Error(), hubclient.ErrDenied.Error())
		reason = strings.TrimPrefix(reason, ": ")
		if dec != nil {
			reason = dec.Reason
		}
		msg := "denied by the human; do not retry unless asked"
		if reason = strings.TrimSpace(reason); reason != "" {
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
	pl.warnings = append(s.warnings(pl), body.KWarnings...)
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask,
		Warnings: pl.warnings, Intent: pl.intent})
	if body.Refuse || hidden != nil {
		finish(false, "refused by the weight check")
		// Audited with its reason and code, as the console shows it; the
		// client learns the code and its default hint only.
		rec.Event, rec.Ticket, rec.Code = audit.EventRefused, ticketID, string(refusal.Cost)
		if hidden != nil {
			rec.Error, rec.Code = hidden.Reason, string(hidden.Code)
		}
		s.audit(rec)
		return refusedResp(id, hiddenWeightRefusal, refusal.New(refusal.Cost, hiddenWeightRefusal).Info("", 0))
	}
	s.println(paint.Step("ticket " + safeText(ticketID, false) + " approved in lockhub: running"))
	rec.Event, rec.Decision, rec.Approval, rec.Ticket = audit.EventApproved, "approved", kconsole.HubApproval, ticketID
	if dec != nil {
		// The hub's signature of its decision, so that `lock audit verify
		// --lock` checks this record against the hub's key; runApproved
		// keeps it on the approval record only, not on the run's.
		rec.Approver, rec.Facade, rec.HubSig = &dec.Approver, dec.Facade, dec.Sig
	}
	resp := s.runApproved(ctx, id, sess, pl, rec, class, time.Time{})
	if resp.Error != nil {
		if d := resp.Error.Data; d != nil && d.Code == refusal.Stale {
			finish(false, "stale")
			return s.hubStale(ctx, id, body, ticketID, who, pl.affected)
		}
		if d := resp.Error.Data; d != nil && d.Code == refusal.StatementKind {
			finish(false, "refused")
			return resp
		}
		finish(false, "failed")
		return resp
	}
	finish(true, "")
	return resp
}

// auditReplanFailed records an approved ticket whose statement could not
// be planned again before its run: the hub's approval, with its
// signature, then the failed run, as runApproved records them.
func (s *Server) auditReplanFailed(ctx context.Context, ticketID string, body hubPlan, dec *ticket.Decision, msg string) {
	rec := withPeerRecord(ctx, audit.Record{Event: audit.EventApproved, Decision: "approved", DB: body.DB, SQL: capSQL(body.SQL),
		Unmasked: body.Unmask, Intent: body.Intent, Approval: kconsole.HubApproval, Ticket: ticketID,
		Approver: &dec.Approver, Facade: dec.Facade, HubSig: dec.Sig})
	s.audit(rec)
	rec.HubSig = ""
	if s.masking() {
		// As errText: a value the message quotes is redacted.
		msg = pii.RedactMessage(msg, body.SQL, s.detectors)
	}
	s.auditRunFailed(rec, msg)
}

// auditHubDenial records the hub's denial of ticket ticketID, as the run
// that found it: the statement of the stored plan (the recheck did not
// run), who denied it on which facade, the reason and the hub's signature.
// Begin ended the plan Denied, so a second run of the ticket finds it used
// and is not recorded again.
func (s *Server) auditHubDenial(ctx context.Context, ticketID string, dec *ticket.Decision) {
	rec := audit.Record{Event: audit.EventDenied, Decision: string(dec.Decision), Reason: s.safeReason(dec.Reason),
		Approval: kconsole.HubApproval, Ticket: ticketID, Approver: &dec.Approver, Facade: dec.Facade, HubSig: dec.Sig}
	if p, err := s.cfg.Hub.Store.TicketPlan(ticketID); err == nil {
		var body hubPlan
		if json.Unmarshal(p.Body, &body) == nil {
			rec.DB, rec.SQL, rec.Unmasked, rec.Intent = body.DB, body.SQL, body.Unmask, body.Intent
		}
	}
	s.audit(withPeerRecord(ctx, rec))
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
