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
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/render"
	"github.com/DavidGodefroid/locksql/internal/secrets"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

const (
	// maxPlans bounds the one-shot plans kept at once.
	maxPlans = 64
	// maxRequests bounds the queued change requests, maxRequestLen their size.
	maxRequests   = 20
	maxRequestLen = 500
	// runGrace is added to the statement timeout as a client-side guard on
	// top of the engine's own server-side timeout.
	runGrace = 5 * time.Second
)

// Handle serves one request. It is the whole client surface of the console:
// none of the methods loosens the policy.
func (s *Server) Handle(ctx context.Context, req ipc.Request) ipc.Response {
	s.lastSeen = s.now()
	switch req.Method {
	case ipc.MethodHello:
		return s.hello(req)
	case ipc.MethodStatus:
		return okResp(req.ID, s.status())
	case ipc.MethodCatalogList, ipc.MethodCatalogDescribe:
		return s.catalog(ctx, req)
	case ipc.MethodQueryPlan:
		return s.queryPlan(ctx, req)
	case ipc.MethodQueryRun:
		return s.queryRun(ctx, req)
	case ipc.MethodPIIList:
		return okResp(req.ID, ipc.PIIListResult{Mask: nonNil(s.rules.Mask), Allow: nonNil(s.rules.Allow)})
	case ipc.MethodPIIAdd:
		return s.piiAdd(req)
	case ipc.MethodChangeRequest:
		return s.changeRequest(req)
	case ipc.MethodLogout:
		s.println("logout requested by a client")
		s.End("logout")
		return okResp(req.ID, map[string]bool{"ok": true})
	}
	return errResp(req.ID, ipc.CodeMethodNotFound, fmt.Sprintf("unknown method %q", req.Method))
}

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

func (s *Server) hello(req ipc.Request) ipc.Response {
	var p ipc.HelloParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	if !ipc.Compatible(p.ProtocolMajor) {
		return errResp(req.ID, ipc.CodeInvalidRequest, fmt.Sprintf(
			"protocol mismatch: client speaks %d, console speaks %d; use the same locksql version on both sides",
			p.ProtocolMajor, ipc.ProtocolMajor))
	}
	return okResp(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, ConsoleVersion: s.cfg.Version, Profile: s.profile.Name})
}

func (s *Server) status() ipc.StatusResult {
	left := MaxSession - s.now().Sub(s.started)
	if left < 0 {
		left = 0
	}
	return ipc.StatusResult{
		Profile:         s.profile.Name,
		Engine:          s.profile.Engine,
		Host:            s.host(),
		HostConfirmed:   true, // the host is part of the approved policy
		Production:      s.profile.Production,
		SkipPermissions: s.autoApprove(),
		AllowUnmask:     s.cfg.AllowUnmask,
		ShowResults:     s.cfg.ShowResults,
		Tier:            s.profile.Tier.String(),
		Databases:       nonNil(s.cfg.Databases),
		Limits:          s.profile.Limits,
		IdleTimeoutInS:  int(IdleTimeout / time.Second),
		SessionEndsInS:  int(left / time.Second),
		Health:          s.cfg.Health,
	}
}

// session returns the live session, reconnecting after a lost connection.
func (s *Server) session(ctx context.Context, id int64) (engine.Session, *ipc.Response) {
	if ttl := s.profile.CredentialsTTL; s.sess != nil && ttl > 0 && s.now().Sub(s.connected) >= ttl {
		// A short-lived secret (a vault lease) has expired: close the
		// connection and ask for a fresh one.
		s.println(fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and the secret asked again", ttl))
		_ = s.sess.Close()
		s.sess = nil
		if s.cfg.Reconnect == nil {
			s.End("credentials expired")
		}
	}
	if s.sess != nil {
		return s.sess, nil
	}
	if s.cfg.Reconnect != nil {
		s.println("reconnecting to the database…")
		sess, err := s.cfg.Reconnect(ctx, s.profile) // the policy in force now, not the start-up one
		if err == nil {
			s.sess = sess
			s.connected = s.now()
			return sess, nil
		}
		s.println("reconnect failed: " + secrets.Sanitize(err))
		if errors.Is(err, errPrivilegeAudit) {
			s.End("privilege audit failed after reconnect")
		}
	}
	r := errResp(id, ipc.CodeConnLost, "the database connection is lost; the human must restart the console")
	return nil, &r
}

// failed maps an engine error to a response, dropping the session on a
// lost connection.
func (s *Server) failed(id int64, what string, err error) ipc.Response {
	if errors.Is(err, engine.ErrConnLost) {
		if s.sess != nil {
			_ = s.sess.Close()
			s.sess = nil
		}
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
// so neither the rules nor the detectors would mask it otherwise. The
// values substituted for the placeholders of pl are removed.
func (s *Server) errText(err error, sql string, unmask bool, pl *plan) string {
	msg := secrets.Sanitize(err, s.planValues(pl)...)
	if unmask || !s.masking() {
		return msg
	}
	return pii.RedactMessage(msg, sql, s.detectors)
}

// auditErrText is the text of a statement error for the audit log. When
// the plan substituted values, none of the database's text is kept: it may
// echo a value in a form no scrubbing recognises (cut, re-quoted).
func (s *Server) auditErrText(err error, pl *plan) string {
	if pl.an == nil || len(pl.an.Values) == 0 {
		return s.errText(err, pl.st.SQL, false, pl)
	}
	switch {
	case errors.Is(err, engine.ErrConnLost):
		return "the database connection was lost"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "statement interrupted"
	}
	return "statement refused by the database (the text is withheld: the statement holds placeholder values)"
}

// failedPlan is failed for an error raised while serving pl: the text
// reaching the client is scrubbed of the plan's values.
func (s *Server) failedPlan(id int64, what string, err error, pl *plan) ipc.Response {
	if errors.Is(err, engine.ErrConnLost) {
		return s.failed(id, what, err)
	}
	return errResp(id, ipc.CodeInternal, what+": "+s.errText(err, pl.st.SQL, false, pl))
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
	msg := fmt.Sprintf("unknown database %q; databases: %s", db, strings.Join(s.cfg.Databases, ", "))
	if s.profile.Database != "" {
		msg = fmt.Sprintf("database %q is not served: this profile serves %q only (set database = \"\" to serve every database the account can see)", db, s.profile.Database)
	}
	r := errResp(id, ipc.CodeRefused, msg)
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
	rec := audit.Record{Event: audit.EventCatalog, DB: db, Decision: req.Method}
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

// refuse audits and reports a refused plan.
func (s *Server) refuse(id int64, db, sql, class, verdict, reason string) ipc.Response {
	return s.refuseRec(id, audit.Record{Event: audit.EventRefused, DB: db, SQL: sql, Class: class, Verdict: verdict, Error: reason})
}

// refuseWarned is refuse for a plan whose warnings are computed: the audit
// record carries them.
func (s *Server) refuseWarned(id int64, pl *plan, class, reason string) ipc.Response {
	return s.refuseRec(id, audit.Record{Event: audit.EventRefused, DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Error: reason, Warnings: pl.warnings})
}

func (s *Server) refuseRec(id int64, rec audit.Record) ipc.Response {
	reason := rec.Error
	s.audit(rec)
	s.println(paint.Fail("refused: " + reason))
	return errResp(id, ipc.CodeRefused, reason)
}

func (s *Server) policyPending(id int64) *ipc.Response {
	if s.pending == nil {
		return nil
	}
	r := errResp(id, ipc.CodePolicyPending,
		"a policy change in the config files awaits the human's confirmation in the console (:review)")
	return &r
}

func (s *Server) queryPlan(ctx context.Context, req ipc.Request) ipc.Response {
	if r := s.policyPending(req.ID); r != nil {
		return *r
	}
	var p ipc.PlanParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	if strings.TrimSpace(p.SQL) == "" {
		return errResp(req.ID, ipc.CodeInvalidParams, "query.plan needs sql")
	}
	db, r := s.checkDB(req.ID, p.DB)
	if r != nil {
		return *r
	}
	auditSQL := capSQL(p.SQL)
	if p.Unmask && !s.cfg.AllowUnmask {
		return s.refuse(req.ID, db, auditSQL, "", "", "unmasked output is off in this console: run the query masked, or ask the human to restart the console with --allow-unmask")
	}
	inner, explain := splitExplain(s.dialect, p.SQL)
	st, err := sqlclass.Classify(s.dialect, inner, s.profile.Limits.MaxRows)
	if err != nil {
		return s.refuse(req.ID, db, auditSQL, "", "", err.Error())
	}
	if st.Class == sqlclass.Read && st.Kind != "select" {
		return s.refuse(req.ID, db, auditSQL, "read", "", fmt.Sprintf(
			"%s is not allowed: only SELECT, WITH ... SELECT and EXPLAIN SELECT are (use the catalog commands to list and describe tables)",
			strings.ToUpper(st.Kind)))
	}
	if explain && st.Class != sqlclass.Read {
		return s.refuse(req.ID, db, auditSQL, st.Class.String(), "", "only EXPLAIN SELECT is allowed")
	}
	class := st.Class.String()
	if int(st.Class) > int(s.profile.Tier) {
		return s.refuse(req.ID, db, st.SQL, class, "", fmt.Sprintf(
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier))
	}
	if st.Class != sqlclass.Read && sqlast.HasPlaceholder(s.dialect, st.SQL) {
		// A write is never analysed for placeholders: it would run with
		// the literal text '${...}'.
		return s.refuse(req.ID, db, st.SQL, class, "", "placeholders are only allowed in read statements, compared with a PII column: col = '${name}' or col IN ('${a}', '${b}')")
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	if !p.Unmask && st.Class != sqlclass.Read {
		// Before the run: a write's RETURNING list or a data-modifying
		// CTE must not move PII under another label, since refusing its
		// result afterwards would not undo the write.
		if err := pii.PlanCheck(st, s.rules, s.dialect, sess.OriginColumns()); err != nil {
			return s.refuse(req.ID, db, st.SQL, class, "", err.Error())
		}
	}

	pl := &plan{db: db, st: st, unmask: p.Unmask, created: s.now(), level: weight.OK.String()}
	if st.Class == sqlclass.Read {
		// The read path: the statement is parsed in full and every column
		// resolved before anything runs.
		full := strings.TrimSpace(p.SQL)
		reason, refused, err := s.readPlan(ctx, sess, pl, full)
		if err != nil {
			return s.failed(req.ID, "plan", err)
		}
		if refused {
			return s.refuse(req.ID, db, auditSQL, class, "", reason)
		}
		pl.st.SQL = strings.TrimSuffix(full, ";")
		if reason, refused := s.assess(pl); refused {
			return s.refuse(req.ID, db, pl.st.SQL, class, pl.level, reason)
		}
	} else {
		pl.summary = "no EXPLAIN for " + strings.ToUpper(st.Kind)
		s.noteRefused(pl)
	}

	s.prunePlans()
	pl.id = newID()
	s.plans[pl.id] = pl
	summary, reasons := clientSummary(pl)
	return okResp(req.ID, ipc.PlanResult{
		PlanID: pl.id, Profile: s.profile.Name, Host: s.host(), DB: db, SQL: pl.st.SQL,
		Class: class, Verdict: pl.level, Summary: summary, Reasons: reasons, Unmask: pl.unmask,
		Values: s.typedNames(),
	})
}

// assess sets the plan's weight verdict under the limits in force. It
// reports the refusal reason when the verdict is REFUSE.
func (s *Server) assess(pl *plan) (string, bool) {
	v := weight.Assess(*pl.explain, s.profile.Limits, s.profile.Production)
	pl.level, pl.summary, pl.reasons = v.Level.String(), v.Summary, v.Reasons
	s.noteRefused(pl)
	if v.Level != weight.Refuse {
		return "", false
	}
	if len(v.Reasons) == 0 {
		return "weight check: " + v.Summary, true
	}
	return "weight check: " + strings.Join(v.Reasons, "; "), true
}

func (s *Server) noteRefused(pl *plan) {
	if s.refused != "" {
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
	pl, ok := s.plans[p.PlanID]
	delete(s.plans, p.PlanID) // one-shot, whatever happens next
	if !ok || s.now().Sub(pl.created) > PlanTTL {
		return errResp(req.ID, ipc.CodeNoSuchPlan, "no such plan: it is unknown, already used or expired; plan the query again")
	}
	class := pl.st.Class.String()
	if int(pl.st.Class) > int(s.profile.Tier) {
		return s.refuse(req.ID, pl.db, pl.st.SQL, class, pl.level, fmt.Sprintf(
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier))
	}
	// The limits may have changed since query.plan (a tightening is applied
	// at once): the verdict shown and enforced is the one under the policy
	// in force now.
	if pl.explain != nil {
		if reason, refused := s.assess(pl); refused {
			return s.refuse(req.ID, pl.db, pl.st.SQL, class, pl.level, reason)
		}
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	pl.warnings = s.warnings(ctx, sess, pl)
	rec := audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask, Warnings: pl.warnings}

	s.screen(ctx, pl)
	// The values are asked before the approval, and asked even when the
	// approval is skipped: nothing runs while a placeholder has none.
	missing, _ := s.placeholders(pl)
	if r := s.askValues(ctx, req.ID, pl, rec, missing); r != nil {
		return *r
	}
	if s.autoApprove() && !pl.unmask {
		rec.Event, rec.Decision = audit.EventAuto, "auto"
		s.println(s.frameEnd(paint.Yellow("auto-approved") + " (--skip-permissions)"))
	} else {
		for {
			r, retype := s.approve(ctx, req.ID, pl, rec)
			if r != nil {
				return *r
			}
			if !retype {
				break
			}
			_, reused := s.placeholders(pl)
			if r := s.askValues(ctx, req.ID, pl, rec, reused); r != nil {
				return *r
			}
		}
		rec.Event, rec.Decision = audit.EventApproved, "approved"
	}
	// The prompts may have waited: check the TTL again, so that an
	// approval or a value landing after it runs nothing.
	if s.now().Sub(pl.created) > PlanTTL {
		rec.Event, rec.Decision = audit.EventTimeout, "expired"
		s.audit(rec)
		s.println(paint.Fail("plan expired while waiting for approval: not run"))
		return errResp(req.ID, ipc.CodeNoSuchPlan, "the plan expired while waiting for approval; plan the query again")
	}
	if pl.an != nil && len(pl.an.Values) > 0 {
		// The values are known now: analyse again, so that the statement
		// and its k-anonymity checks carry them. pl.st.SQL is the statement
		// as the agent wrote it, placeholders included: the audit keeps it.
		if reason, refused, err := s.analyzeRead(ctx, sess, pl, pl.st.SQL); err != nil || refused {
			if err != nil {
				// Approved already: the failure is audited like a run's.
				rec.Error = s.auditErrText(err, pl)
				s.audit(rec)
				return s.failedPlan(req.ID, "plan", err, pl)
			}
			return s.refuseWarned(req.ID, pl, class, reason)
		}
		if missing, _ := s.placeholders(pl); len(missing) > 0 {
			return s.refuseWarned(req.ID, pl, class, "a placeholder has no value")
		}
	}

	rctx := ctx
	if t := s.profile.Limits.StatementTimeout; t > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, t+runGrace)
		defer cancel()
	}
	start := time.Now()
	// Success or failure, the answer leaves on the next quantum.
	defer s.level(ctx, start)
	if reason, err := s.kCheck(rctx, sess, pl); err != nil || reason != "" {
		if err != nil {
			rec.Error = s.auditErrText(err, pl)
			s.audit(rec)
			return s.failedPlan(req.ID, "k-anonymity check", err, pl)
		}
		return s.refuseWarned(req.ID, pl, class, reason+" (approved, but not run)")
	}
	var res engine.Result
	var err error
	switch {
	case pl.isExplain:
		res = explainResult(pl.explain)
	case pl.an != nil:
		st := pl.st
		st.SQL = pl.runSQL
		res, err = sess.Run(rctx, pl.db, st, s.profile.Limits.MaxRows)
	default:
		res, err = sess.Run(rctx, pl.db, pl.st, s.profile.Limits.MaxRows)
	}
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		// The audit log never holds row data, even for an unmask run.
		rec.Error = s.auditErrText(err, pl)
		s.audit(rec)
		s.println(paint.Fail("failed: " + s.errText(err, pl.st.SQL, false, pl)))
		if errors.Is(err, engine.ErrConnLost) {
			return s.failed(req.ID, "statement failed", err)
		}
		if errors.Is(rctx.Err(), context.DeadlineExceeded) {
			return errResp(req.ID, ipc.CodeInternal, "statement timed out (limits.statement_timeout)")
		}
		// Never the server's message: it can quote values.
		return errResp(req.ID, ipc.CodeInternal, genericFailure)
	}
	var clear *engine.Result
	if s.cfg.ShowResults && !pl.unmask && len(res.Columns) > 0 {
		c := cloneResult(res)
		clear = &c
	}
	if !pl.unmask && pl.an != nil {
		if err := s.maskRead(&res, pl, sess); err != nil {
			s.println(paint.Fail("result dropped: " + err.Error()))
			return s.refuseWarned(req.ID, pl, class, "the result could not be masked with certainty and was dropped: "+err.Error())
		}
	} else if !pl.unmask {
		origin := sess.OriginColumns()
		if pii.NeedsAliasCheck(res, origin) {
			if err := pii.ResultAliasViolation(pl.st, s.rules, s.dialect, res.Columns); err != nil {
				return s.refuseWarned(req.ID, pl, class, err.Error()+" (the result was dropped)")
			}
		}
		pii.MaskResult(&res, s.rules, s.detectors, origin)
	}
	out, err := s.result(res)
	if err != nil {
		rec.Error = secrets.Sanitize(err)
		s.audit(rec)
		return errResp(req.ID, ipc.CodeInternal, "render: "+rec.Error)
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
	return okResp(req.ID, out)
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

// showTable prints a result in the console, under the profile's output
// caps, so that the human sees the clear values. With masked, the result
// as the client got it, each cell the client got masked is yellow and
// followed by its reference name when it has one. The audit log never
// holds row data.
func (s *Server) showTable(title string, res engine.Result, masked *engine.Result) {
	t := render.TSVTable(res, s.profile.Limits)
	var m render.Table
	if masked != nil {
		m = render.TSVTable(*masked, s.profile.Limits)
	}
	maskedAt := func(i, j int) (bool, string) {
		if i >= len(m.Rows) || j >= len(m.Rows[i]) || j >= len(t.Rows[i]) || m.Rows[i][j] == t.Rows[i][j] {
			return false, ""
		}
		mc := m.Rows[i][j]
		if strings.HasPrefix(mc, "<redacted:") && strings.HasSuffix(mc, ">") {
			return true, strings.TrimSuffix(strings.TrimPrefix(mc, "<redacted:"), ">")
		}
		return true, ""
	}
	col := make([]bool, len(t.Header))
	for i := range t.Rows {
		for j := range t.Rows[i] {
			if ok, _ := maskedAt(i, j); ok && j < len(col) {
				col[j] = true
			}
		}
	}
	s.println(title)
	head := make([]string, len(t.Header))
	for j, h := range t.Header {
		head[j] = safeText(h, false)
		if col[j] {
			head[j] = paint.Yellow(head[j])
		}
	}
	s.println("  " + strings.Join(head, " │ "))
	for i, r := range t.Rows {
		cells := make([]string, len(r))
		for j, c := range r {
			cells[j] = safeText(c, false)
			if ok, ref := maskedAt(i, j); ok {
				cells[j] = paint.Yellow(cells[j])
				if ref != "" {
					cells[j] += " " + paint.Dim("‹"+safeText(ref, false)+"›")
				}
			}
		}
		s.println("  " + strings.Join(cells, " │ "))
	}
	for _, f := range t.Footer {
		s.println("  " + safeText(f, false))
	}
}

// approve shows the prompt and waits for the human. It returns nil when
// approved, the error response otherwise (audited). retype reports that the
// human asked to type again the values the plan reuses.
func (s *Server) approve(ctx context.Context, id int64, pl *plan, rec audit.Record) (resp *ipc.Response, retype bool) {
	expected, prompt := "y", "Approve? [y/N] "
	if s.profile.Production {
		expected = s.profile.Name
		prompt = fmt.Sprintf("Type the profile name %q to approve: ", s.profile.Name)
	}
	_, reused := s.placeholders(pl)
	// "r" retypes, unless it is the approval answer itself (a production
	// profile named r).
	canRetype := len(reused) > 0 && expected != "r"
	if canRetype {
		prompt = "(r to retype ${" + strings.Join(reused, "}, ${") + "}) " + prompt
	}
	ans, ok := s.cfg.IO.Ask(ctx, s.frameEnd(paint.Bold(prompt)), ApprovalTimeout)
	if ok && canRetype && strings.TrimSpace(ans) == "r" {
		return nil, true
	}
	var r ipc.Response
	switch {
	case !ok && ctx.Err() != nil:
		rec.Event, rec.Decision = audit.EventAbandoned, "abandoned"
		s.println(paint.Fail("client gone: request cancelled"))
		r = errResp(id, ipc.CodeDenied, "the request was cancelled")
	case !ok:
		rec.Event, rec.Decision = audit.EventTimeout, "timeout"
		s.println(paint.Fail("no answer: denied"))
		r = errResp(id, ipc.CodeTimeout, "no answer from the human within the approval timeout; do not retry unless asked")
	case strings.TrimSpace(ans) != expected:
		rec.Event, rec.Decision = audit.EventDenied, "denied"
		s.println(paint.Fail("denied"))
		r = errResp(id, ipc.CodeDenied, "denied by the human; do not retry unless asked")
	default:
		return nil, false
	}
	s.audit(rec)
	return &r, false
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
	}
	dec := json.NewDecoder(&jb)
	dec.UseNumber() // keep 64-bit integers exact
	if err := dec.Decode(&j); err != nil {
		return ipc.RunResult{}, err
	}
	if j.Rows == nil {
		j.Rows = [][]any{}
	}
	return ipc.RunResult{Columns: j.Columns, Rows: j.Rows, Truncated: j.Truncated, Affected: res.Affected, Text: tb.String()}, nil
}

func (s *Server) piiAdd(req ipc.Request) ipc.Response {
	var p ipc.PIIAddParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	var probe pii.Rules
	if err := probe.Add(p.Pattern); err != nil {
		return errResp(req.ID, ipc.CodeInvalidParams, err.Error())
	}
	pattern := probe.Mask[0]
	// Add to the file as it is on disk, so that unconfirmed edits of the
	// human are neither lost nor applied.
	onDisk, err := pii.LoadRulesFile(s.cfg.RulesPath)
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	if err := onDisk.Add(pattern); err != nil {
		return errResp(req.ID, ipc.CodeInvalidParams, err.Error())
	}
	if err := pii.SaveRulesFile(s.cfg.RulesPath, onDisk); err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	next := s.approved
	next.PIIMask = append(append([]string(nil), next.PIIMask...), pattern)
	next = config.NewPolicy(next.Profile, next.PIIMask, next.PIIAllow).WithModes(next.PIIModes)
	if err := s.adopt(next, "tightened"); err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	if s.pending != nil {
		// The pending loosening was read before this rule reached the file:
		// applying it as is from :review would drop the rule.
		p := *s.pending
		p = config.NewPolicy(p.Profile, append(append([]string(nil), p.PIIMask...), pattern), p.PIIAllow).WithModes(p.PIIModes)
		s.pending = &p
	}
	s.println("PII rule added by a client: mask " + safeText(pattern, false))
	return okResp(req.ID, ipc.PIIListResult{Mask: nonNil(s.rules.Mask), Allow: nonNil(s.rules.Allow)})
}

func (s *Server) changeRequest(req ipc.Request) ipc.Response {
	var p ipc.ChangeParams
	if r := decode(req, &p); r != nil {
		return *r
	}
	change := strings.TrimSpace(p.Change)
	if change == "" || len(change) > maxRequestLen || !utf8.ValidString(change) {
		return errResp(req.ID, ipc.CodeInvalidParams, fmt.Sprintf("change must be 1 to %d bytes of text", maxRequestLen))
	}
	change = escapeControls(change)
	if len(s.requests) >= maxRequests {
		s.requests = s.requests[1:]
	}
	s.requests = append(s.requests, change)
	s.println("change requested by a client: " + change + " — type :review to see it")
	return okResp(req.ID, ipc.ChangeResult{Queued: true})
}
