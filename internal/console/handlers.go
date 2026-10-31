package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/render"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

const (
	// maxPlans bounds the one-shot plans kept at once.
	maxPlans = 64
	// runGrace is added to the statement timeout as a client-side guard on
	// top of the engine's own server-side timeout.
	runGrace = 5 * time.Second
)

func nonNil(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return out
}

func decode(req ipc.Request, v any) *ipc.Response {
	raw := bytes.TrimSpace(req.Params)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		r := errResp(req.ID, ipc.CodeInvalidParams, "invalid params for "+req.Method)
		return &r
	}
	return nil
}

// session returns the live session, reconnecting first when the login
// expired (credentials_ttl, a Vault lease) or the connection was lost
// (lockkit's console decides; reconnect opens the new one).
func (s *Server) session(ctx context.Context, id int64) (engine.Session, *ipc.Response) {
	ks, err := s.k.Session(ctx)
	if err != nil {
		r := errResp(id, ipc.CodeConnLost, err.Error())
		return nil, &r
	}
	sess, ok := kconsole.Unwrap(ks).(engine.Session)
	if !ok {
		r := errResp(id, ipc.CodeInternal, "internal error in the console: not a database session")
		return nil, &r
	}
	s.sess = sess
	return sess, nil
}

// failed maps an engine error to a response, dropping the session on a
// lost connection.
func (s *Server) failed(id int64, what string, err error) ipc.Response {
	if errors.Is(err, engine.ErrConnLost) {
		s.k.Lost()
		s.println("database connection lost")
		if s.cfg.Reconnect == nil {
			s.End("connection lost")
		}
		return errResp(id, ipc.CodeConnLost, "the database connection was lost")
	}
	return errResp(id, ipc.CodeInternal, what+": "+secrets.Sanitize(err))
}

// masking reports whether the session masks anything at all.
func (s *Server) masking() bool {
	return len(s.rules.Mask) > 0 || len(s.detectors) > 0
}

// errText is the text of a statement error for the client, the console and
// the audit log. With masking on, a value the server quotes in its message
// (a failed cast in a WHERE clause) is redacted: it reaches no result row,
// so neither the rules nor the detectors would mask it otherwise.
func (s *Server) errText(err error, sql string, unmask bool) string {
	msg := secrets.Sanitize(err)
	if unmask || !s.masking() {
		return msg
	}
	return pii.RedactMessage(msg, sql, s.detectors)
}

// auditErrText is the text of a statement error for the audit log.
func (s *Server) auditErrText(err error, pl *plan) string {
	return s.errText(err, pl.st.SQL, false)
}

// failedPlan is failed for an error raised while serving pl: the text
// reaching the client is scrubbed of the plan's values.
func (s *Server) failedPlan(id int64, what string, err error, pl *plan) ipc.Response {
	if errors.Is(err, engine.ErrConnLost) {
		return s.failed(id, what, err)
	}
	return errResp(id, ipc.CodeInternal, what+": "+s.errText(err, pl.st.SQL, false))
}

// checkDB resolves the database of a request: the given one, or the
// profile's. A named database must be one the console serves: the
// profile's alone when it names one, else one the session listed.
func (s *Server) checkDB(id int64, db string) (string, *ipc.Response) {
	if db == "" {
		db = s.profile.Database
	}
	if db == "" || slices.Contains(s.cfg.Databases, db) {
		return db, nil
	}
	ref := refusal.Newf(refusal.UnknownName, "unknown database %q; databases: %s", db, strings.Join(s.cfg.Databases, ", "))
	if s.profile.Database != "" {
		ref = refusal.Newf(refusal.DatabaseNotServed, "database %q is not served: this profile serves %q only (set database = \"\" to serve every database the account can see)", db, s.profile.Database)
	}
	r := refusedResp(id, ref.Reason, ref.Info("", 0))
	return "", &r
}

func (s *Server) catalog(ctx context.Context, req ipc.Request) ipc.Response {
	var p ipc.DescribeParams // a superset of TablesParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	if req.Method == ipc.MethodCatalogList && p.Table != "" {
		return errResp(req.ID, ipc.CodeInvalidParams, "invalid params for "+req.Method)
	}
	db, r := s.checkDB(req.ID, p.DB)
	if r != nil {
		return *r
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	rec := withPeerRecord(ctx, audit.Record{Event: audit.EventCatalog, DB: db, Decision: req.Method})
	var result any
	var err error
	if req.Method == ipc.MethodCatalogList {
		var tables []string
		tables, err = sess.Tables(ctx, db)
		result = ipc.TablesResult{DB: db, Tables: nonNil(tables)}
		rec.Rows = int64(len(tables))
	} else {
		if p.Table == "" {
			return errResp(req.ID, ipc.CodeInvalidParams, "catalog.describe needs a table")
		}
		rec.SQL = p.Table
		result, err = sess.Describe(ctx, db, p.Table)
	}
	if err != nil {
		rec.Error = secrets.Sanitize(err)
		s.audit(rec)
		return s.failed(req.ID, req.Method, err)
	}
	s.audit(rec)
	return okResp(req.ID, result)
}

// refuse audits and reports a refused plan; intent is the agent's. src is
// the statement as the agent sent it: the position of r counts in it.
func (s *Server) refuse(ctx context.Context, id int64, intent, db, sql, class, verdict, src string, r *refusal.Error) ipc.Response {
	return s.refuseRec(id, withPeerRecord(ctx, audit.Record{Event: audit.EventRefused, DB: db, SQL: sql, Class: class, Verdict: verdict, Intent: intent}), src, r)
}

// refuseWarned is refuse for a plan whose warnings are computed: the audit
// record carries them.
func (s *Server) refuseWarned(ctx context.Context, id int64, pl *plan, class string, r *refusal.Error) ipc.Response {
	return s.refuseRec(id, withPeerRecord(ctx, audit.Record{Event: audit.EventRefused, DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Warnings: pl.warnings, Intent: pl.intent}), pl.src, r)
}

// refuseRec audits and answers a refusal: its prose, its code and, when
// known, the place in src it points at.
func (s *Server) refuseRec(id int64, rec audit.Record, src string, r *refusal.Error) ipc.Response {
	info := r.Info(src, 0)
	if r.Secret {
		// The statement may carry a password: the record keeps its shape.
		rec.SQL = sqlclass.RedactLiterals(s.dialect, rec.SQL)
	}
	rec.Error, rec.Code, rec.Span = r.Reason, string(info.Code), info.Span
	s.audit(rec)
	s.println(paint.Fail("refused [" + string(info.Code) + "]: " + safeText(r.Reason, false)))
	return refusedResp(id, r.Reason, info)
}

// refusedResp is the one answer that carries ipc.CodeRefused: the prose
// message and its structured form.
func refusedResp(id int64, msg string, info refusal.Info) ipc.Response {
	r := errResp(id, ipc.CodeRefused, msg)
	r.Error.Data = &info
	return r
}

// shifted moves the position of the refusal err is (or the fail-closed
// one it becomes) by base bytes, from the text a check read to the
// statement the agent sent.
func shifted(err error, base int) *refusal.Error {
	r := refusal.From(err)
	r.Shift(base)
	return r
}

// lead is the offset of the statement in sql: the length of its leading
// blanks, which the checks trim.
func lead(sql string) int { return len(sql) - len(strings.TrimLeftFunc(sql, unicode.IsSpace)) }

func (s *Server) policyPending(id int64) *ipc.Response {
	if !s.pendingPolicy() {
		return nil
	}
	r := errResp(id, ipc.CodePolicyPending,
		"a policy change in the config files awaits the human's confirmation in the console (:review)")
	return &r
}

// planFailed answers an engine error raised while planning: the client
// gets the generic failure, never the database's text (it may quote
// values); the console shows the detail, redacted as errText does, and
// keeps it in s.planErr for the caller that audits it (a hub replan).
// A lost connection is failed's.
func (s *Server) planFailed(id int64, err error, sql string) ipc.Response {
	if errors.Is(err, engine.ErrConnLost) {
		s.planErr = "the database connection was lost"
		return s.failed(id, "plan", err)
	}
	s.planErr = s.errText(err, sql, false)
	s.println(paint.Fail("plan failed: " + safeText(s.planErr, false)))
	return errResp(id, ipc.CodeInternal, "plan failed: "+genericFailure)
}

func (s *Server) queryPlan(ctx context.Context, req ipc.Request) ipc.Response {
	if r := s.policyPending(req.ID); r != nil {
		return *r
	}
	var p ipc.PlanParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	pl, r := s.buildPlan(ctx, req.ID, p)
	if r != nil {
		return *r
	}
	db, class := pl.db, pl.st.Class.String()
	pl.requester = p.Requester
	s.prunePlans()
	pl.id = newID()
	s.plans[pl.id] = pl
	summary, reasons := clientSummary(pl)
	verdict := pl.level
	if estimatesHidden(pl) {
		verdict = weight.OK.String()
	}
	return okResp(req.ID, ipc.PlanResult{
		PlanID: pl.id, Profile: s.profile.Name, Host: s.host(), DB: db, SQL: pl.st.SQL,
		Class: class, Verdict: verdict, Summary: summary, Reasons: reasons, Unmask: pl.unmask,
		PlanHash: pl.hash,
	})
}

// buildPlan checks and plans the statement of p: the plan, or the answer
// that refuses it (audited). query.plan stores the plan; a hub-mode run
// plans again from the stored statement (hubmode.go).
func (s *Server) buildPlan(ctx context.Context, id int64, p ipc.PlanParams) (*plan, *ipc.Response) {
	s.planErr = ""
	if strings.TrimSpace(p.SQL) == "" {
		return nil, ptr(errResp(id, ipc.CodeInvalidParams, "query.plan needs sql"))
	}
	if len(p.Intent) > ipc.MaxIntent || !utf8.ValidString(p.Intent) || strings.ContainsAny(p.Intent, "\r\n") {
		return nil, ptr(errResp(id, ipc.CodeInvalidParams, fmt.Sprintf("intent must be one line of at most %d bytes", ipc.MaxIntent)))
	}
	p.Intent = strings.TrimSpace(p.Intent)
	db, r := s.checkDB(id, p.DB)
	if r != nil {
		return nil, r
	}
	auditSQL := capSQL(p.SQL)
	base := lead(p.SQL)
	if p.Unmask && !s.allowUnmask() {
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, auditSQL, "", "", p.SQL, refusal.New(refusal.UnmaskOff, "unmasked output is off in this console: run the query masked, or ask the human to allow it in the console (:unmask, or --allow-unmask at start)")))
	}
	inner, explain, off := splitExplain(s.dialect, p.SQL)
	st, err := sqlclass.Classify(s.dialect, inner, s.profile.Limits.MaxRows)
	if err != nil {
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, auditSQL, "", "", p.SQL, shifted(err, base+off)))
	}
	if st.Class == sqlclass.Read && st.Kind != "select" {
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, auditSQL, "read", "", p.SQL, refusal.Newf(refusal.StatementKind,
			"%s is not allowed: only SELECT, WITH ... SELECT and EXPLAIN SELECT are (use the catalog commands to list and describe tables)",
			strings.ToUpper(st.Kind)).At(base+off, strings.ToUpper(st.Kind))))
	}
	if explain && st.Class != sqlclass.Read {
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, auditSQL, st.Class.String(), "", p.SQL, refusal.New(refusal.StatementKind, "only EXPLAIN SELECT is allowed").At(base+off, "")))
	}
	class := st.Class.String()
	if int(st.Class) > int(s.profile.Tier) {
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, st.SQL, class, "", p.SQL, refusal.Newf(refusal.Tier,
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier)))
	}
	if sqlast.HasPlaceholder(s.dialect, st.SQL) {
		// Placeholders and cell references are not supported: refused
		// before anything is analysed, so that no value is looked up and
		// a write never runs with the literal text '${...}'.
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, st.SQL, class, "", p.SQL, refusal.New(refusal.Placeholder, sqlast.PlaceholderRefusal)))
	}
	sess, r := s.session(ctx, id)
	if r != nil {
		return nil, r
	}
	var shadow *shadowNames
	if s.profile.WriteFunctions == config.WriteFunctionsAllowlist {
		r, sn, err := s.strictWriteFunctions(ctx, sess, db, st)
		if err != nil {
			return nil, ptr(s.planFailed(id, err, p.SQL))
		}
		if r != nil {
			return nil, ptr(s.refuse(ctx, id, p.Intent, db, st.SQL, class, "", p.SQL, shifted(r, base)))
		}
		shadow = sn
	}
	pl := &plan{db: db, st: st, unmask: p.Unmask, intent: p.Intent, created: s.now(), level: weight.OK.String(), src: p.SQL, base: base, shadow: shadow}
	if !p.Unmask && st.Class != sqlclass.Read {
		// Before the run: a write's RETURNING list or a data-modifying
		// CTE must not move PII under another label, since refusing its
		// result afterwards would not undo the write.
		r, err := s.writePlan(ctx, sess, pl)
		if err != nil {
			return nil, ptr(s.planFailed(id, err, p.SQL))
		}
		if r != nil {
			return nil, ptr(s.refuse(ctx, id, p.Intent, db, st.SQL, class, "", p.SQL, r))
		}
	}
	if st.Class == sqlclass.Read {
		// The read path: the statement is parsed in full and every column
		// resolved before anything runs.
		full := strings.TrimSpace(p.SQL)
		r, err := s.readPlan(ctx, sess, pl, full)
		if err != nil {
			return nil, ptr(s.planFailed(id, err, p.SQL))
		}
		if r != nil {
			return nil, ptr(s.refuse(ctx, id, p.Intent, db, auditSQL, class, "", p.SQL, r))
		}
		pl.st.SQL = strings.TrimSuffix(full, ";")
		// Under a PII filter the verdict is a statistic of the filtered
		// value: it is decided by query.run, on the console.
		if r := s.assess(pl); r != nil && !estimatesHidden(pl) {
			return nil, ptr(s.refuse(ctx, id, p.Intent, db, pl.st.SQL, class, pl.level, p.SQL, r))
		}
	} else {
		pl.summary = "no EXPLAIN for " + strings.ToUpper(st.Kind)
		s.noteRefused(pl)
	}

	pl.refs = objectRefs(s.dialect, pl)
	state, err := s.planState(ctx, sess, pl)
	if err != nil {
		return nil, ptr(s.planFailed(id, err, p.SQL))
	}
	pl.guarded = state != nil
	switch {
	case state != nil && st.Class == sqlclass.Write:
		pl.sideEffects = sideEffects(*state)
	case st.Class == sqlclass.Write:
		// No object definitions (MySQL, SQLite): the triggers of the
		// tables the write names, for its ticket.
		tr, err := engine.TriggersOf(ctx, sess, pl.db, pl.refs.Relations)
		if err != nil && !errors.Is(err, engine.ErrNoTriggerList) {
			return nil, ptr(s.planFailed(id, err, p.SQL))
		}
		pl.sideEffects = tr
	}
	if pl.hash, pl.inputs, err = s.planDigests(pl, state); err != nil {
		return nil, ptr(s.planFailed(id, err, p.SQL))
	}

	return pl, nil
}

func ptr(r ipc.Response) *ipc.Response { return &r }

// assess sets the plan's weight verdict under the limits in force. It
// returns the refusal when the verdict is REFUSE.
func (s *Server) assess(pl *plan) *refusal.Error {
	v := weight.Assess(*pl.explain, s.profile.Limits, s.profile.Production)
	pl.level, pl.summary, pl.reasons = v.Level.String(), v.Summary, v.Reasons
	s.noteRefused(pl)
	if v.Level != weight.Refuse {
		return nil
	}
	if len(v.Reasons) == 0 {
		return refusal.New(refusal.Cost, "weight check: "+v.Summary)
	}
	return refusal.New(refusal.Cost, "weight check: "+strings.Join(v.Reasons, "; "))
}

func (s *Server) noteRefused(pl *plan) {
	if s.k.PolicyRefused() {
		pl.reasons = append(pl.reasons, "a policy change in the config files was refused by the human; the last approved policy applies")
	}
}

// capSQL keeps refused statements in the audit log within a sane size.
func capSQL(sql string) string {
	const max = 4096
	sql = strings.TrimSpace(sql)
	if len(sql) <= max {
		return sql
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(sql[cut]) {
		cut--
	}
	return sql[:cut] + "…"
}

func (s *Server) prunePlans() {
	now := s.now()
	for id, p := range s.plans {
		if now.Sub(p.created) > PlanTTL {
			delete(s.plans, id)
		}
	}
	for len(s.plans) >= maxPlans {
		oldest := ""
		for id, p := range s.plans {
			if oldest == "" || p.created.Before(s.plans[oldest].created) {
				oldest = id
			}
		}
		delete(s.plans, oldest)
	}
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) queryRun(ctx context.Context, req ipc.Request) ipc.Response {
	if r := s.policyPending(req.ID); r != nil {
		return *r
	}
	var p ipc.RunParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	if p.Ticket != "" {
		return s.queryRunTicket(ctx, req.ID, p.Ticket, p.Requester)
	}
	pl, ok := s.plans[p.PlanID]
	if ok && !sameRequester(pl.requester, p.Requester) {
		// Another agent's plan: refused, and left to the agent that made it.
		return errResp(req.ID, ipc.CodeWrongRequester, wrongRequester)
	}
	delete(s.plans, p.PlanID) // one-shot, whatever happens next
	if !ok || s.now().Sub(pl.created) > PlanTTL {
		return errResp(req.ID, ipc.CodeNoSuchPlan, "no such plan: it is unknown, already used or expired; plan the query again")
	}
	class := pl.st.Class.String()
	hiddenRefusal, r := s.runChecks(ctx, req.ID, pl)
	if r != nil {
		return *r
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	// What the plan resolves to may have changed since query.plan: refuse
	// before the human is asked. The run checks again, in its transaction.
	if pl.guarded {
		state, err := s.planState(ctx, sess, pl)
		if err != nil {
			return s.failedPlan(req.ID, "plan", err, pl)
		}
		if h, err := s.planHash(pl, state); err != nil || h != pl.hash {
			if err != nil {
				return s.failedPlan(req.ID, "plan", err, pl)
			}
			return s.refuse(ctx, req.ID, pl.intent, pl.db, pl.st.SQL, class, pl.level, pl.src, refusal.New(refusal.Stale, errStale{}.Error()))
		}
	}
	pl.warnings = s.warnings(pl)
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask, Warnings: pl.warnings, Intent: pl.intent})

	s.screen(ctx, pl)
	return s.hubSubmit(ctx, req.ID, sess, pl, rec, hiddenRefusal)
}

// runChecks are the checks of a plan at run time, under the policy and the
// switches in force now: the tier, unmasked output, and the weight check
// with the limits in force (a tightening applies at once). It returns the
// refusal to answer at once, or hidden, a weight refusal under a PII
// filter that waits for the human (an immediate answer would tell the
// agent the verdict).
func (s *Server) runChecks(ctx context.Context, id int64, pl *plan) (hidden *refusal.Error, resp *ipc.Response) {
	class := pl.st.Class.String()
	if int(pl.st.Class) > int(s.profile.Tier) {
		return nil, ptr(s.refuse(ctx, id, pl.intent, pl.db, pl.st.SQL, class, pl.level, pl.src, refusal.Newf(refusal.Tier,
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier)))
	}
	// Unmasked output may have been turned off (:unmask) since query.plan.
	if pl.unmask && !s.allowUnmask() {
		return nil, ptr(s.refuse(ctx, id, pl.intent, pl.db, pl.st.SQL, class, pl.level, pl.src, refusal.New(refusal.UnmaskOff, "unmasked output was turned off in this console since the plan: run the query masked")))
	}
	// The limits may have changed since query.plan (a tightening is applied
	// at once): the verdict shown and enforced is the one under the policy
	// in force now.
	if pl.explain != nil {
		r := s.assess(pl)
		if r == nil {
			if r = s.assessK(pl); r != nil {
				pl.level = weight.Refuse.String()
				pl.reasons = append(pl.reasons, r.Reason)
			}
		}
		if r != nil {
			if !estimatesHidden(pl) {
				return nil, ptr(s.refuse(ctx, id, pl.intent, pl.db, pl.st.SQL, class, pl.level, pl.src, r))
			}
			// Under a PII filter an immediate answer would tell the
			// agent the verdict: the refusal waits for the human.
			hidden = r
		}
	}
	return hidden, nil
}

// runApproved records the decision and runs the approved plan pl: the
// checks that may have changed while the human decided, the guarded run,
// the masking and the answer. start is when the response time is levelled
// from (zero: from the run).
func (s *Server) runApproved(ctx context.Context, id int64, sess engine.Session, pl *plan, rec audit.Record, class string, start time.Time) ipc.Response {
	// The decision is on record before anything runs: a console stopped
	// between the approval and the end of the run still leaves a trace of
	// what was approved. The run record follows, with the outcome. An
	// approval that cannot be recorded runs nothing.
	if s.writeAudit(rec) != nil {
		s.println(paint.Fail("refused: the approval could not be recorded in the audit log"))
		return errResp(id, ipc.CodeInternal, "the console could not record the approval in its audit log, so the query was not run; ask the user to check the console")
	}
	// The hub's signature is the decision's: the records that follow are
	// the run's, not another decision of the hub.
	rec.Event, rec.Decision, rec.HubSig = audit.EventRun, "ok", ""
	// The prompts may have waited: check the TTL again, so that an
	// approval or a value landing after it runs nothing.
	if s.now().Sub(pl.created) > PlanTTL {
		rec.Event, rec.Decision = audit.EventTimeout, "expired"
		s.audit(rec)
		s.println(paint.Fail("plan expired while waiting for approval: not run"))
		return errResp(id, ipc.CodeNoSuchPlan, "the plan expired while waiting for approval; plan the query again")
	}
	// A function or operator created since the plan would run instead of
	// the built-in: look them up again.
	if r, err := s.checkShadows(ctx, sess, pl.db, pl.shadow); err != nil || r != nil {
		if err != nil {
			s.auditRunFailed(rec, s.auditErrText(err, pl))
			return s.failedPlan(id, "plan", err, pl)
		}
		return s.refuseWarned(ctx, id, pl, class, r)
	}

	rctx := ctx
	if t := s.profile.Limits.StatementTimeout; t > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, t+runGrace)
		defer cancel()
	}
	if start.IsZero() {
		start = time.Now()
	}
	// Success or failure, the answer leaves on the next quantum.
	defer s.level(ctx, start)
	var res engine.Result
	var err error
	switch {
	case pl.isExplain:
		res = explainResult(pl.explain)
	default:
		st := pl.st
		if pl.an != nil {
			st.SQL = pl.runSQL
		}
		switch {
		case pl.guarded:
			res, err = engine.RunGuarded(rctx, sess, pl.db, st, s.profile.Limits.MaxRows, pl.refs, s.staleCheck(pl))
		case pl.maxAffected > 0:
			res, err = engine.RunCounted(rctx, sess, pl.db, st, s.profile.Limits.MaxRows, pl.rowCheck)
		default:
			res, err = sess.Run(rctx, pl.db, st, s.profile.Limits.MaxRows)
		}
	}
	if stale := (errStale{}); errors.As(err, &stale) {
		return s.refuseWarned(ctx, id, pl, class, refusal.New(refusal.Stale, stale.Error()))
	}
	if rc := (errRowcount{}); errors.As(err, &rc) {
		pl.affected = rc.affected
		s.println(paint.Warn(rc.Error() + ": rolled back"))
		return s.refuseWarned(ctx, id, pl, class, refusal.New(refusal.Stale, rc.Error()+": rolled back"))
	}
	if errors.Is(err, engine.ErrUncounted) {
		// Nothing ran, and the same statement is refused again: a typed
		// refusal, so that the agent does not retry it.
		return s.refuseWarned(ctx, id, pl, class, refusal.New(refusal.StatementKind, err.Error()+" (nothing ran; do not retry it as is)"))
	}
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		// The audit log never holds row data, even for an unmask run.
		s.auditRunFailed(rec, s.auditErrText(err, pl))
		s.println(paint.Fail("failed: " + safeText(s.errText(err, pl.st.SQL, false), false)))
		if errors.Is(err, engine.ErrConnLost) {
			return s.failed(id, "statement failed", err)
		}
		if errors.Is(rctx.Err(), context.DeadlineExceeded) {
			return errResp(id, ipc.CodeInternal, "statement timed out (limits.statement_timeout)")
		}
		// Never the server's message: it can quote values.
		return errResp(id, ipc.CodeInternal, genericFailure)
	}
	var clear *engine.Result
	if s.showResults() && !pl.unmask && len(res.Columns) > 0 {
		c := cloneResult(res)
		clear = &c
	}
	if !pl.unmask && pl.an != nil {
		if err := s.maskRead(&res, pl, sess); err != nil {
			s.println(paint.Fail("result dropped: " + safeText(err.Error(), false)))
			return s.refuseWarned(ctx, id, pl, class, refusal.New(refusal.MaskUncertain, "the result could not be masked with certainty and was dropped: "+err.Error()))
		}
	} else if !pl.unmask {
		origin := sess.OriginColumns()
		if pii.NeedsAliasCheck(res, origin) {
			if err := pii.ResultAliasViolation(pl.st, s.rules, s.dialect, res.Columns); err != nil {
				r := shifted(err, pl.base)
				if r.Code == refusal.Policy {
					r.Code = refusal.MaskUncertain
				}
				r.Reason += " (the result was dropped)"
				return s.refuseWarned(ctx, id, pl, class, r)
			}
		}
		pii.MaskResult(&res, s.rules, s.detectors, origin)
	}
	out, err := s.result(res)
	if err != nil {
		s.auditRunFailed(rec, secrets.Sanitize(err))
		return errResp(id, ipc.CodeInternal, "render: "+rec.Error)
	}
	rec.Rows, rec.Affected, rec.Truncated = int64(len(out.Rows)), res.Affected, out.Truncated
	s.audit(rec)
	if len(res.Columns) == 0 {
		s.println(paint.OK(fmt.Sprintf("done: %d rows affected in %d ms", res.Affected, rec.DurationMS)))
	} else {
		more := ""
		if out.Truncated {
			more = " (truncated)"
		}
		s.println(paint.OK(fmt.Sprintf("done: %d rows%s in %d ms", len(out.Rows), more, rec.DurationMS)))
		switch {
		case pl.unmask:
			s.showTable(red+"PII: UNMASKED result"+reset, res, nil)
		case clear != nil:
			s.showTable(paint.Yellow("result in clear (shown here only; the agent got it masked)"), *clear, &res)
		}
	}
	return okResp(id, out)
}

// auditRunFailed writes the run record of an approved statement that did
// not complete: errText is already sanitised.
func (s *Server) auditRunFailed(rec audit.Record, errText string) {
	rec.Event, rec.Decision, rec.Error = audit.EventRun, "failed", errText
	s.audit(rec)
}

// cloneResult copies the rows of res, which masking rewrites in place.
func cloneResult(res engine.Result) engine.Result {
	c := res
	c.Columns = slices.Clone(res.Columns)
	c.Rows = make([][]any, len(res.Rows))
	for i, r := range res.Rows {
		c.Rows[i] = slices.Clone(r)
	}
	return c
}

// result renders the masked result as capped JSON rows and TSV text.
func (s *Server) result(res engine.Result) (ipc.RunResult, error) {
	var jb, tb bytes.Buffer
	if err := render.Render(&jb, res, s.profile.Limits, render.FormatJSON); err != nil {
		return ipc.RunResult{}, err
	}
	if err := render.Render(&tb, res, s.profile.Limits, render.FormatTSV); err != nil {
		return ipc.RunResult{}, err
	}
	var j struct {
		Columns   []string `json:"columns"`
		Rows      [][]any  `json:"rows"`
		Truncated bool     `json:"truncated"`
		CutCells  int      `json:"cut_cells"`
	}
	dec := json.NewDecoder(&jb)
	dec.UseNumber() // keep 64-bit integers exact
	if err := dec.Decode(&j); err != nil {
		return ipc.RunResult{}, err
	}
	if j.Rows == nil {
		j.Rows = [][]any{}
	}
	return ipc.RunResult{Columns: j.Columns, Rows: j.Rows, Truncated: j.Truncated, CutCells: j.CutCells, Affected: res.Affected, Text: tb.String()}, nil
}
