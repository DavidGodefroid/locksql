package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

// Grants (#171): one human decision covering a bounded read scope, against
// approval fatigue. The agent asks for a database, tables, a duration and a
// read budget (statements run, rows and bytes returned); the console clamps
// them to the profile's limits and submits a ticket of risk grant, whose
// plan hash is the hash of the scope's canonical JSON, so that the hub's
// signed decision binds exactly that scope. Once decided, the agent
// activates it (scope.request with the ticket): the decision is verified
// and matched as for a run (hubclient.Begin), and the grant is active from
// then on, for its duration, in this console's memory only.
//
// query.run then runs a plan without a ticket when the first active grant
// of the same agent that covers its database and every table it reads
// (CTEs and subqueries included) has the budget for it; anything else asks
// as before. A grant never covers a write, an unmask, a statement that
// filters, groups or aggregates on a PII column (its k-anonymity counts:
// running at once or asking would tell the agent whether a count fell
// under k), a REFUSE verdict, nor a read whose EXPLAIN row estimate the
// remaining rows do not cover.

const (
	// grantKind marks a grant's body in the plans store.
	grantKind = "grant"
	// maxGrantTables bounds the tables of one grant, and maxGrantName the
	// length of each name as the agent sends it.
	maxGrantTables = 64
	maxGrantName   = 256
	// maxScreenLine is the longest line of a grant's approval screen
	// (lockhub refuses a line of 4096 bytes or more).
	maxScreenLine = 4000
	// minGrantBytes is the least byte budget a run under a grant needs:
	// each of its two renderings gets half, and a result's envelope alone
	// takes about a hundred bytes.
	minGrantBytes = 512
)

// grantScope is what a grant's decision binds: the plan hash of its ticket
// is ticket.HashOf of it. Tables are the relations as the analyser
// resolves them ("schema.table" or "database.table"), sorted.
type grantScope struct {
	Database string          `json:"database"`
	Tables   []string        `json:"tables"`
	Duration string          `json:"duration"`
	Budget   ipc.GrantBudget `json:"budget"`
}

func (sc grantScope) words() string {
	db := sc.Database
	if db == "" {
		db = "(default)"
	}
	return fmt.Sprintf("database %s · tables %s · %s · %d statements, %d rows, %d bytes",
		db, strings.Join(sc.Tables, ", "), sc.Duration, sc.Budget.Statements, sc.Budget.Rows, sc.Budget.Bytes)
}

// grant is an active grant. Grants live in the console's memory only: a
// restart ends them.
type grant struct {
	id    string // the ticket of its decision
	scope grantScope
	set   map[string]bool // scope.Tables
	// uid and tokenHash are the agent that asked for it: only it runs
	// under the grant.
	uid       int
	tokenHash string
	agent     string
	intent    string
	expires   time.Time
	duration  time.Duration
	left      ipc.GrantBudget
	// The hub's decision: its signature goes on every record of the grant.
	sig      string
	approver *ticket.Approver
	facade   string
}

// grantRequest serves scope.request: a new grant asked for, or with a
// ticket the decided one activated.
func (s *Server) grantRequest(ctx context.Context, req ipc.Request) ipc.Response {
	if r := s.policyPending(req.ID); r != nil {
		return *r
	}
	var p ipc.GrantParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	if p.Requester.Token == "" {
		// Outside lea every process of the account would share the
		// grant: it needs the agent's token.
		return s.refuse(ctx, req.ID, "", p.DB, "", "read", "", "", refusal.New(refusal.GrantNeedsAgent,
			"a grant needs the agent's lea token (LEA_AGENT_TOKEN), so that only that agent uses it: plan and run each query"))
	}
	if p.Ticket != "" {
		return s.grantActivate(ctx, req.ID, p.Ticket, p.Requester)
	}
	if len(p.Intent) > ipc.MaxIntent || !utf8.ValidString(p.Intent) || strings.ContainsAny(p.Intent, "\r\n") {
		return errResp(req.ID, ipc.CodeInvalidParams, fmt.Sprintf("intent must be one line of at most %d bytes", ipc.MaxIntent))
	}
	intent := strings.TrimSpace(p.Intent)
	lim, on := s.profile.Limits.Grants()
	if !on {
		return s.refuse(ctx, req.ID, intent, p.DB, "", "read", "", "", refusal.New(refusal.GrantsOff,
			"grants are off in this profile (limits.grant_max_duration = 0): plan and run each query"))
	}
	if len(p.Tables) == 0 || len(p.Tables) > maxGrantTables {
		return errResp(req.ID, ipc.CodeInvalidParams, fmt.Sprintf("a grant names 1 to %d tables", maxGrantTables))
	}
	for _, t := range p.Tables {
		if t == "" || len(t) > maxGrantName || !utf8.ValidString(t) || strings.ContainsFunc(t, unicode.IsControl) {
			return errResp(req.ID, ipc.CodeInvalidParams, fmt.Sprintf("a table name is 1 to %d bytes of text", maxGrantName))
		}
	}
	dur := lim.Duration
	if p.Duration != "" {
		d, err := time.ParseDuration(p.Duration)
		if err != nil || d < 0 {
			return errResp(req.ID, ipc.CodeInvalidParams, `duration: want a Go duration such as "30m"`)
		}
		if d > 0 {
			dur = min(d, lim.Duration)
		}
	}
	if p.Statements < 0 || p.Rows < 0 || p.Bytes < 0 {
		return errResp(req.ID, ipc.CodeInvalidParams, "the budget must not be negative")
	}
	clamp := func(v, limit int64) int64 {
		if v == 0 {
			return limit
		}
		return min(v, limit)
	}
	budget := ipc.GrantBudget{Statements: clamp(p.Statements, lim.Statements), Rows: clamp(p.Rows, lim.Rows), Bytes: clamp(p.Bytes, lim.Bytes)}
	db, r := s.checkDB(req.ID, p.DB)
	if r != nil {
		return *r
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	// Each table as the analyser will resolve it: a read is covered when
	// every relation it reads is one of them.
	cat := s.newCatalog(ctx, sess, db)
	var tables []string
	for _, t := range p.Tables {
		parts := strings.Split(t, ".")
		for i := range parts {
			parts[i] = fold(strings.TrimSpace(parts[i]))
		}
		found, err := cat.Lookup(parts)
		if err != nil {
			return s.failed(req.ID, "grant", err, "")
		}
		if len(found) != 1 {
			what := "unknown table %s (list them with locksql_list_tables)"
			if len(found) > 1 {
				what = "table %s is ambiguous (several schemas hold it); qualify it"
			}
			return s.refuse(ctx, req.ID, intent, db, "", "read", "", "", refusal.Newf(refusal.UnknownName, what, strings.ToLower(t)))
		}
		tables = append(tables, found[0].DB+"."+found[0].Name)
	}
	slices.Sort(tables)
	tables = slices.Compact(tables)
	scope := grantScope{Database: db, Tables: tables, Duration: dur.String(), Budget: budget}
	masked, clear, ok := s.grantScreen(scope, p, lim, intent)
	if !ok {
		return errResp(req.ID, ipc.CodeInvalidParams, "the tables of a grant must fit one screen line: ask for fewer tables")
	}
	hash, err := ticket.HashOf(scope)
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, "grant scope: "+err.Error())
	}
	fp, err := ticket.HashOf(s.approved)
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, "policy fingerprint: "+err.Error())
	}
	body, err := json.Marshal(hubPlan{Kind: grantKind, DB: db, Intent: intent, Class: "read", Grant: &scope})
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	caller := hubCaller(ctx, p.Requester)
	agent := agentName(ctx, p.Requester)
	h := s.cfg.Hub
	hp, err := h.Store.Create(plans.Binding{UID: caller.UID, Agent: agent, TokenHash: plans.HashToken(caller.Token), PolicyFP: fp, PlanHash: hash}, body, 0)
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, "plan store: "+err.Error())
	}
	sc := &clear
	sc.Hub = &kconsole.HubTicket{PlanID: hp.ID, Caller: caller, Risk: ticket.RiskGrant, Masked: masked, Requester: ticket.Requester{Agent: agent}}
	rec := withPeerRecord(ctx, audit.Record{DB: db, Class: "read", Intent: intent, GrantScope: scope.words()})
	s.println(paint.Step("grant asked for: " + safeText(scope.words(), false)))
	a := s.asker().Ask(ctx, req.ID, kconsole.Ask{Frame: s.frameColour(), Production: s.profile.Production, Screen: sc}, func(b kaudit.Base) {
		rec.Event, rec.Decision, rec.Reason, rec.Error, rec.Approval, rec.Ticket = b.Event, b.Decision, b.Reason, b.Error, b.Approval, b.Ticket
		s.audit(rec)
	})
	return a.Refusal
}

// grantScreen is the approval screen of a grant: the header names the
// instance, one line each for the tables, the duration and the budget, as
// clamped (a value the agent asked above the limit says so), and the
// agent's intent as the note. ok is false when a line would be too long.
func (s *Server) grantScreen(sc grantScope, p ipc.GrantParams, lim config.GrantLimits, intent string) (render.MaskedScreen, kconsole.Screen, bool) {
	db := sc.Database
	if db == "" {
		db = "(default)"
	}
	clamped := func(asked, got int64) string {
		if asked > got {
			return fmt.Sprintf(" (asked %d)", asked)
		}
		return ""
	}
	durLine := "duration: " + sc.Duration + " from its activation"
	if d, err := time.ParseDuration(p.Duration); err == nil && d > lim.Duration {
		durLine += " (asked " + d.String() + ", clamped to limits.grant_max_duration)"
	}
	src := render.ScreenSource{
		Header: "grant on " + s.cfg.Hub.Instance,
		Note:   intent,
		Red:    s.profile.Production,
		Body: []render.Line{
			render.Structure("tables of " + db + ": " + strings.Join(sc.Tables, ", ")),
			render.Structure(durLine),
			render.Structure(fmt.Sprintf("budget: %d statements%s · %d rows%s · %d bytes%s returned",
				sc.Budget.Statements, clamped(p.Statements, sc.Budget.Statements),
				sc.Budget.Rows, clamped(p.Rows, sc.Budget.Rows),
				sc.Budget.Bytes, clamped(p.Bytes, sc.Budget.Bytes))),
		},
	}
	for _, l := range src.Body {
		if len(l[0].Text) > maxScreenLine {
			return render.MaskedScreen{}, kconsole.Screen{}, false
		}
	}
	return render.MaskScreen(src, render.Masking{Detectors: s.detectors, Personal: func(string, string) bool { return true }}), clearScreen(src), true
}

// errNotGrant marks a ticket that is not a grant's, errGrantTicket a
// grant's ticket run as a statement's.
var (
	errNotGrant    = errors.New("console: not a grant")
	errGrantTicket = errors.New("console: a grant's ticket")
)

// grantActivate activates the grant of a decided ticket: the hub's
// decision is verified under the pinned hub key, matched with the ticket
// the lock signed and still usable (hubclient.Begin: ticket.VerifyDecision,
// Decision.Match, Decision.Usable within the 4 h of a grant ticket), and
// the scope and policy are those the ticket bound. The grant lasts its
// duration from now.
func (s *Server) grantActivate(ctx context.Context, id int64, ticketID string, who ipc.Requester) ipc.Response {
	h := s.cfg.Hub
	caller := hubCaller(ctx, who)
	var body hubPlan
	hp, dec, err := h.Client.Begin(h.Store, ticketID, caller, func(p *plans.Plan) (string, string, error) {
		if err := json.Unmarshal(p.Body, &body); err != nil {
			return "", "", err
		}
		if body.Kind != grantKind || body.Grant == nil {
			return "", "", errNotGrant
		}
		hash, err := ticket.HashOf(*body.Grant)
		if err != nil {
			return "", "", err
		}
		fp, err := ticket.HashOf(s.approved)
		return fp, hash, err
	})
	switch {
	case errors.Is(err, plans.ErrWrongRequester):
		return errResp(id, ipc.CodeWrongRequester, "ticket "+ticketID+": this grant was asked for by another agent: only that agent may activate it")
	case errors.Is(err, errNotGrant):
		return errResp(id, ipc.CodeInvalidParams, "ticket "+ticketID+" is not a grant's: run it with locksql_run")
	case errors.Is(err, ticket.ErrExpired):
		s.auditGrant(ctx, audit.Record{Event: audit.EventGrant, Decision: "expired", Ticket: ticketID, Error: "the decision was not acted on within its time"}, body, dec)
		return errResp(id, ipc.CodeTimeout, "ticket "+ticketID+": the grant was not activated in time (a grant ticket lasts 4 h): ask for a new grant")
	case errors.Is(err, plans.ErrStale):
		s.withdraw(ctx, ticketID, caller)
		s.auditGrant(ctx, audit.Record{Event: audit.EventGrant, Decision: "stale", Ticket: ticketID, Error: "the policy changed since the grant was asked for"}, body, dec)
		msg := "the policy changed since the grant was asked for: ask for a new grant"
		return refusedResp(id, msg, refusal.New(refusal.Stale, msg).Info("", 0))
	case errors.Is(err, hubclient.ErrDenied):
		if dec != nil {
			s.auditHubDenial(ctx, ticketID, dec)
		}
		msg := "grant denied by the human; do not ask again unless asked"
		if dec != nil && strings.TrimSpace(dec.Reason) != "" {
			msg = "grant denied by the human: " + s.safeReason(dec.Reason) + "; do not ask again unless asked"
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
	if _, on := s.profile.Limits.Grants(); !on {
		finish(false, "grants are off")
		return s.refuse(ctx, id, body.Intent, body.DB, "", "read", "", "", refusal.New(refusal.GrantsOff, "grants are off in this profile (limits.grant_max_duration = 0)"))
	}
	sc := *body.Grant
	d, err := time.ParseDuration(sc.Duration)
	if err != nil || d <= 0 {
		finish(false, "bad scope")
		return errResp(id, ipc.CodeInternal, "grant scope: bad duration")
	}
	g := &grant{id: ticketID, scope: sc, set: map[string]bool{}, uid: caller.UID, tokenHash: plans.HashToken(caller.Token),
		agent: hp.Binding.Agent, intent: body.Intent, expires: s.now().Add(d), duration: d, left: sc.Budget}
	for _, t := range sc.Tables {
		g.set[t] = true
	}
	if dec != nil {
		g.sig, g.approver, g.facade = dec.Sig, &dec.Approver, dec.Facade
	}
	// The activation is on record before the grant covers anything: one
	// that cannot be recorded is not active.
	rec := s.grantRecord(ctx, g, audit.EventGrant, "approved")
	if s.writeAudit(rec) != nil {
		finish(false, "audit")
		return errResp(id, ipc.CodeInternal, "the console could not record the grant in its audit log, so it is not active; ask the user to check the console")
	}
	finish(true, "")
	s.grants = append(s.grants, g)
	s.println(paint.Step("grant " + safeText(g.id, false) + " active for " + d.String() + ": " + safeText(sc.words(), false)))
	return okResp(id, ipc.GrantResult{Status: "active", Grant: s.grantInfo(g)})
}

// grantRecord is the audit record of g for event and decision: the grant
// id, its ticket, its scope and the hub's signature of its decision.
func (s *Server) grantRecord(ctx context.Context, g *grant, event, decision string) audit.Record {
	rec := audit.Record{Event: event, Decision: decision, DB: g.scope.Database, Class: "read", Intent: g.intent,
		Approval: kconsole.HubApproval, Ticket: g.id, Grant: g.id, GrantScope: g.scope.words(),
		Approver: g.approver, Facade: g.facade, HubSig: g.sig}
	return withPeerRecord(ctx, rec)
}

// auditGrant records a grant that could not be activated, with what the
// stored plan and the decision say.
func (s *Server) auditGrant(ctx context.Context, rec audit.Record, body hubPlan, dec *ticket.Decision) {
	rec.DB, rec.Intent, rec.Class, rec.Approval = body.DB, body.Intent, "read", kconsole.HubApproval
	if body.Grant != nil {
		rec.GrantScope = body.Grant.words()
	}
	if dec != nil {
		rec.Approver, rec.Facade, rec.HubSig = &dec.Approver, dec.Facade, dec.Sig
	}
	s.audit(withPeerRecord(ctx, rec))
}

// grantFor is the grant that covers pl for the agent that planned it, or
// nil when the plan must ask (a ticket, as without grants). Only the first
// active grant of that agent covering pl's database and every relation it
// reads is considered: it covers the run when its budget does.
func (s *Server) grantFor(ctx context.Context, pl *plan) *grant {
	s.expireGrants()
	if len(s.grants) == 0 || !grantable(pl) || s.steersOnDetected(pl) || pl.policyFP != s.policyFP() {
		return nil
	}
	if _, on := s.profile.Limits.Grants(); !on {
		return nil
	}
	caller := hubCaller(ctx, pl.requester)
	if caller.Token == "" {
		return nil // no agent token: no grant (scope.request refuses one)
	}
	hash := plans.HashToken(caller.Token)
	for _, g := range s.grants {
		if g.uid != caller.UID || !sameTokenHash(g.tokenHash, hash) || g.scope.Database != pl.db {
			continue
		}
		if !slices.ContainsFunc(pl.an.Relations, func(r string) bool { return !g.set[r] }) {
			if !s.budgetCovers(g, pl) {
				return nil
			}
			return g
		}
	}
	return nil
}

// grantable reports a plan a grant may cover: a masked read whose every
// relation the analyser resolved, that reads at least one table, with no
// PII filter, grouping or aggregate under the k-anonymity check (decision
// 1: whether it ran at once or asked would tell the agent what the count
// says), and not refused by the weight check.
func grantable(pl *plan) bool {
	return pl.st.Class == sqlclass.Read && !pl.unmask && pl.an != nil && pl.explain != nil && len(pl.warnings) == 0 &&
		!pl.an.PIIFilter && len(pl.an.KChecks) == 0 && !estimatesHidden(pl) &&
		len(pl.an.Relations) > 0 && pl.level != weight.Refuse.String()
}

// steersOnDetected reports a plan whose result some column steers
// (filters, joins, groupings, orderings, expressions:
// sqlast.Analysis.Steering) while only the detectors protect it: a column
// no allow rule declares not personal whose type can hold what they mask.
// That is free text (string, JSON, binary, or a type the catalog does not
// give) and, when a detector that matches digits is on (lockkit's
// detectors scan integers and whole floats too: a national number or a
// card stored as a number), numbers too, but for the values the database
// generates itself (auto_increment, serial, identity, the SQLite rowid).
// Under a grant, such a read would be a ticket-free oracle on the masked
// values (the review of #171): it asks instead. Dates and times, booleans
// and uuids hold none of them.
func (s *Server) steersOnDetected(pl *plan) bool {
	digits := s.digitDetectors()
	for _, src := range pl.an.Steering {
		if !src.View && s.rules.Allowed(src.DB, src.Table, src.Column) {
			continue
		}
		ci, ok := s.columnInfo(src)
		if !ok {
			return true
		}
		class := typeClass(ci.Type)
		if ci.TypeLoose && !ci.Generated {
			// SQLite outside STRICT: any value in any column.
			class = typeText
		}
		switch class {
		case typeOpaque:
		case typeNumber:
			if digits && !ci.Generated {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// digitDetectors reports a detector on that can match digits. lockkit does
// not say which can: every detector but email (all of whose matches carry
// an '@') is taken to, a new one included.
func (s *Server) digitDetectors() bool {
	return slices.ContainsFunc(s.profile.Detectors, func(d string) bool { return d != "email" })
}

// columnInfo is the catalog entry of src.
func (s *Server) columnInfo(src sqlast.Source) (engine.ColumnInfo, bool) {
	for _, cols := range s.catalogCache {
		for _, c := range cols {
			if c.DB == src.DB && c.Table == src.Table && c.Column == src.Column {
				return c, true
			}
		}
	}
	return engine.ColumnInfo{}, false
}

// The classes of a column type for a grant's predicates.
const (
	typeText   = iota // may hold free text: string, JSON, binary, unknown
	typeNumber        // integers, decimals, floats
	typeOpaque        // dates and times, booleans, uuids
)

// typeClass is the class of a catalog type; an unknown or empty type is
// text.
func typeClass(t string) int {
	t = strings.ToLower(strings.TrimSpace(t))
	if i := strings.IndexAny(t, "( "); i >= 0 {
		t = t[:i]
	}
	switch t {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint", "int2", "int4", "int8",
		"serial", "smallserial", "bigserial", "serial2", "serial4", "serial8",
		"decimal", "numeric", "dec", "real", "double", "float", "float4", "float8":
		return typeNumber
	case "bool", "boolean",
		"date", "time", "timetz", "timestamp", "timestamptz", "datetime", "year", "interval",
		"uuid":
		return typeOpaque
	}
	return typeText
}

// budgetCovers reports whether g has the budget for pl: a statement, some
// rows and bytes left, and the rows left cover the EXPLAIN estimate (an
// EXPLAIN SELECT returns the plan, not the rows: its estimate is not
// charged).
func (s *Server) budgetCovers(g *grant, pl *plan) bool {
	if g.left.Statements < 1 || g.left.Rows < 1 || g.left.Bytes < minGrantBytes {
		return false
	}
	if pl.isExplain {
		return true
	}
	est := weight.Assess(*pl.explain, s.profile.Limits, s.profile.Production).EstimatedRows
	return est <= g.left.Rows
}

func sameTokenHash(a, b string) bool { return a == b }

// runGranted runs pl under g: one statement is charged before the run,
// whatever happens; the rows and bytes the agent gets are capped at what
// is left (and at max_rows and max_output_bytes) and charged after it.
func (s *Server) runGranted(ctx context.Context, id int64, sess engine.Session, pl *plan, g *grant, rec audit.Record) ipc.Response {
	g.left.Statements--
	pl.grant = g
	// Approved by the hub's decision on the grant: its signature and
	// approver, and the grant id, go on the approval and the run records.
	rec.Event, rec.Decision, rec.Approval = audit.EventApproved, "grant", kconsole.HubApproval
	rec.Ticket, rec.Grant, rec.HubSig, rec.Approver, rec.Facade = g.id, g.id, g.sig, g.approver, g.facade
	s.println(paint.Step("covered by grant " + safeText(g.id, false) + ": running without a ticket"))
	resp := s.runApproved(ctx, id, sess, pl, rec, pl.st.Class.String(), time.Time{})
	g.left.Rows = max(0, g.left.Rows-pl.grantRows)
	g.left.Bytes = max(0, g.left.Bytes-pl.grantBytes)
	if resp.Error == nil {
		var out ipc.RunResult
		if json.Unmarshal(resp.Result, &out) == nil {
			out.Grant = g.id
			left := g.left
			out.GrantLeft = &left
			resp = okResp(id, out)
		}
	}
	return resp
}

// grantCaps are the row and byte caps of a run under pl's grant: what is
// left, within max_rows and max_output_bytes. ok is false outside a grant.
func (s *Server) grantCaps(pl *plan) (config.Limits, bool) {
	l := s.profile.Limits
	if pl.grant == nil {
		return l, false
	}
	l.MaxRows = int(min(int64(l.MaxRows), pl.grant.left.Rows))
	// The JSON rows and the TSV text each get half of what is left, so
	// that the two together stay within it.
	l.MaxOutputBytes = int(min(int64(l.MaxOutputBytes), pl.grant.left.Bytes/2))
	return l, true
}

// expireGrants ends the grants past their time.
func (s *Server) expireGrants() {
	now := s.now()
	for _, g := range slices.Clone(s.grants) {
		if !now.Before(g.expires) {
			s.endGrant(g, "expired")
		}
	}
}

// endGrant ends g, audited with why.
func (s *Server) endGrant(g *grant, why string) {
	i := slices.Index(s.grants, g)
	if i < 0 {
		return
	}
	s.grants = slices.Delete(s.grants, i, i+1)
	rec := s.grantRecord(context.Background(), g, audit.EventGrantEnd, why)
	statements, bytes := g.scope.Budget.Statements-g.left.Statements, g.scope.Budget.Bytes-g.left.Bytes
	rec.Rows, rec.StatementsUsed, rec.BytesUsed = g.scope.Budget.Rows-g.left.Rows, &statements, &bytes
	s.audit(rec)
	s.println(paint.Warn("grant " + safeText(g.id, false) + " ended: " + why))
}

// endGrants ends every grant.
func (s *Server) endGrants(why string) {
	for _, g := range slices.Clone(s.grants) {
		s.endGrant(g, why)
	}
}

// revoke is :revoke (every grant) and :revoke ID (one).
func (s *Server) revoke(arg string) {
	s.expireGrants()
	if arg == "" {
		if len(s.grants) == 0 {
			s.println("no active grant")
			return
		}
		s.endGrants("revoked")
		return
	}
	for _, g := range s.grants {
		if strings.EqualFold(g.id, arg) {
			s.endGrant(g, "revoked")
			return
		}
	}
	s.println("no active grant " + safeText(arg, false) + " (:status lists them)")
}

// policyFP is the fingerprint of the policy in force.
func (s *Server) policyFP() string {
	if v := s.live.Load(); v != nil {
		return v.fp
	}
	return ""
}

// grantPolicyChanged ends every grant when the approved policy's
// fingerprint changes from oldFP to fp, a tightening too: a grant was
// decided under the policy it was asked for. The first policy (oldFP "")
// ends none, and neither does a change made only of added mask rules
// (pii.add, which any agent may send): every covered run is planned under
// the rules in force (grantFor refuses a plan made under another policy),
// so it masks the new columns.
func (s *Server) grantPolicyChanged(old config.Policy, oldFP string, cur config.Policy, fp string) {
	if oldFP == "" || oldFP == fp || masksAddedOnly(old, cur) {
		return
	}
	s.endGrants("policy_changed")
}

// masksAddedOnly reports a change from old to cur made only of added mask
// rules: every rule of old is kept with its mode, and nothing else moved.
func masksAddedOnly(old, cur config.Policy) bool {
	modes := func(p config.Policy, pat string) string {
		if m, ok := p.PIIModes[pat]; ok {
			return m
		}
		return config.DefaultMaskMode
	}
	for _, pat := range old.PIIMask {
		if !slices.Contains(cur.PIIMask, pat) || modes(old, pat) != modes(cur, pat) {
			return false
		}
	}
	rest := cur
	rest.PIIMask, rest.PIIModes = old.PIIMask, old.PIIModes
	return config.Fingerprint(rest) == config.Fingerprint(old)
}

// grantInfo is g as status and scope.request show it.
func (s *Server) grantInfo(g *grant) *ipc.GrantInfo {
	left := max(0, int(g.expires.Sub(s.now()).Seconds()))
	return &ipc.GrantInfo{ID: g.id, DB: g.scope.Database, Tables: slices.Clone(g.scope.Tables), Duration: g.scope.Duration,
		ExpiresInS: left, Budget: g.scope.Budget, Remaining: g.left, Agent: g.agent}
}

// grantInfos are the active grants, oldest first.
func (s *Server) grantInfos() []ipc.GrantInfo {
	s.expireGrants()
	var out []ipc.GrantInfo
	for _, g := range s.grants {
		out = append(out, *s.grantInfo(g))
	}
	return out
}

// grantRows are the :status rows of the active grants.
func (s *Server) grantRows() [][2]string {
	limits := "off (limits.grant_max_duration = 0)"
	if l, on := s.profile.Limits.Grants(); on {
		limits = fmt.Sprintf("%s · %d statements · %d rows · %d bytes", l.Duration, l.Statements, l.Rows, l.Bytes)
	}
	rows := [][2]string{{"grant limits", limits}}
	infos := s.grantInfos()
	if len(infos) == 0 {
		return append(rows, [2]string{"grants", "none"})
	}
	for _, gi := range infos {
		rows = append(rows, [2]string{"grant", safeText(fmt.Sprintf("%s · %s · %s · %d min left · %d/%d statements · %d/%d rows · %d/%d bytes left",
			gi.ID, gi.DB, strings.Join(gi.Tables, ", "), gi.ExpiresInS/60,
			gi.Remaining.Statements, gi.Budget.Statements, gi.Remaining.Rows, gi.Budget.Rows, gi.Remaining.Bytes, gi.Budget.Bytes), false)})
	}
	return rows
}

// isGrantTicket reports an expired ticket of a grant's plan.
func (s *Server) isGrantTicket(ticketID string, caller plans.Caller) bool {
	p, err := s.cfg.Hub.Store.ExpiredByTicket(ticketID, caller)
	if err != nil {
		return false
	}
	var body hubPlan
	return json.Unmarshal(p.Body, &body) == nil && body.Kind != ""
}
