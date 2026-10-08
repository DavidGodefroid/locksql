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
		Tier:            s.profile.Tier.String(),
		Databases:       nonNil(s.cfg.Databases),
		Limits:          s.profile.Limits,
		IdleTimeoutInS:  int(IdleTimeout / time.Second),
		SessionEndsInS:  int(left / time.Second),
	}
}

// session returns the live session, reconnecting after a lost connection.
func (s *Server) session(ctx context.Context, id int64) (engine.Session, *ipc.Response) {
	if s.sess != nil {
		return s.sess, nil
	}
	if s.cfg.Reconnect != nil {
		s.println("reconnecting to the database…")
		sess, err := s.cfg.Reconnect(ctx, s.profile) // the policy in force now, not the start-up one
		if err == nil {
			s.sess = sess
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
// so neither the rules nor the detectors would mask it otherwise.
func (s *Server) errText(err error, sql string, unmask bool) string {
	msg := secrets.Sanitize(err)
	if unmask || !s.masking() {
		return msg
	}
	return pii.RedactMessage(msg, sql, s.detectors)
}

// checkDB resolves the database of a request: the given one, or the
// profile's. A named database must be one the session listed.
func (s *Server) checkDB(id int64, db string) (string, *ipc.Response) {
	if db == "" {
		db = s.profile.Database
	}
	if db == "" || slices.Contains(s.cfg.Databases, db) {
		return db, nil
	}
	r := errResp(id, ipc.CodeRefused, fmt.Sprintf("unknown database %q; databases: %s", db, strings.Join(s.cfg.Databases, ", ")))
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
	s.audit(audit.Record{Event: audit.EventRefused, DB: db, SQL: sql, Class: class, Verdict: verdict, Error: reason})
	s.println("refused: " + reason)
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
	st, err := sqlclass.Classify(s.dialect, p.SQL, s.profile.Limits.MaxRows)
	if err != nil {
		return s.refuse(req.ID, db, auditSQL, "", "", err.Error())
	}
	class := st.Class.String()
	if int(st.Class) > int(s.profile.Tier) {
		return s.refuse(req.ID, db, st.SQL, class, "", fmt.Sprintf(
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier))
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	if !p.Unmask && !sess.OriginColumns() {
		if err := pii.AliasViolation(st, s.rules, s.dialect); err != nil {
			return s.refuse(req.ID, db, st.SQL, class, "", err.Error())
		}
	}

	pl := &plan{db: db, st: st, unmask: p.Unmask, created: s.now(), level: weight.OK.String()}
	if st.Class == sqlclass.Read && st.Kind == "select" {
		ep, err := sess.Explain(ctx, db, st.SQL)
		if err != nil {
			if errors.Is(err, engine.ErrConnLost) {
				return s.failed(req.ID, "explain", err)
			}
			// Before approval: redacted even for an unmask plan (MySQL and
			// MariaDB may run a constant subquery while planning).
			return s.refuse(req.ID, db, st.SQL, class, "", "EXPLAIN failed: "+s.errText(err, st.SQL, false))
		}
		v := weight.Assess(ep, s.profile.Limits, s.profile.Production)
		pl.level, pl.summary, pl.reasons = v.Level.String(), v.Summary, v.Reasons
		if v.Level == weight.Refuse {
			reason := "weight check: " + strings.Join(v.Reasons, "; ")
			if len(v.Reasons) == 0 {
				reason = "weight check: " + v.Summary
			}
			return s.refuse(req.ID, db, st.SQL, class, pl.level, reason)
		}
	} else {
		pl.summary = "no EXPLAIN for " + strings.ToUpper(st.Kind)
	}
	if s.refused != "" {
		pl.reasons = append(pl.reasons, "a policy change in the config files was refused by the human; the last approved policy applies")
	}

	s.prunePlans()
	pl.id = newID()
	s.plans[pl.id] = pl
	return okResp(req.ID, ipc.PlanResult{
		PlanID: pl.id, Profile: s.profile.Name, Host: s.host(), DB: db, SQL: st.SQL,
		Class: class, Verdict: pl.level, Summary: pl.summary, Reasons: pl.reasons, Unmask: pl.unmask,
	})
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
	rec := audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask}
	if int(pl.st.Class) > int(s.profile.Tier) {
		return s.refuse(req.ID, pl.db, pl.st.SQL, class, pl.level, fmt.Sprintf(
			"statement class %s is above the profile tier %s", strings.ToUpper(class), s.profile.Tier))
	}
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}

	s.screen(pl)
	if s.autoApprove() && !pl.unmask {
		rec.Event, rec.Decision = audit.EventAuto, "auto"
		s.println("auto-approved (--skip-permissions)")
	} else {
		if r := s.approve(ctx, req.ID, pl, rec); r != nil {
			return *r
		}
		// The prompt may have waited: check the TTL again, so that an
		// approval landing after it runs nothing.
		if s.now().Sub(pl.created) > PlanTTL {
			rec.Event, rec.Decision = audit.EventTimeout, "expired"
			s.audit(rec)
			s.println("plan expired while waiting for approval: not run")
			return errResp(req.ID, ipc.CodeNoSuchPlan, "the plan expired while waiting for approval; plan the query again")
		}
		rec.Event, rec.Decision = audit.EventApproved, "approved"
	}

	rctx := ctx
	if t := s.profile.Limits.StatementTimeout; t > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, t+runGrace)
		defer cancel()
	}
	start := time.Now()
	res, err := sess.Run(rctx, pl.db, pl.st, s.profile.Limits.MaxRows)
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		// The audit log never holds row data, even for an unmask run.
		rec.Error = s.errText(err, pl.st.SQL, false)
		s.audit(rec)
		s.println("failed: " + rec.Error)
		if errors.Is(err, engine.ErrConnLost) {
			return s.failed(req.ID, "statement failed", err)
		}
		return errResp(req.ID, ipc.CodeInternal, "statement failed: "+s.errText(err, pl.st.SQL, pl.unmask))
	}
	if !pl.unmask {
		origin := sess.OriginColumns()
		if pii.NeedsAliasCheck(res, origin) {
			if err := pii.AliasViolation(pl.st, s.rules, s.dialect); err != nil {
				return s.refuse(req.ID, pl.db, pl.st.SQL, class, pl.level, err.Error()+" (the result was dropped)")
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
	out.DurationMS = rec.DurationMS
	rec.Rows, rec.Affected, rec.Truncated = int64(len(out.Rows)), res.Affected, out.Truncated
	s.audit(rec)
	if len(res.Columns) == 0 {
		s.println(fmt.Sprintf("done: %d rows affected in %d ms", res.Affected, rec.DurationMS))
	} else {
		more := ""
		if out.Truncated {
			more = " (truncated)"
		}
		s.println(fmt.Sprintf("done: %d rows%s in %d ms", len(out.Rows), more, rec.DurationMS))
	}
	return okResp(req.ID, out)
}

// approve shows the prompt and waits for the human. It returns nil when
// approved, the error response otherwise (audited).
func (s *Server) approve(ctx context.Context, id int64, pl *plan, rec audit.Record) *ipc.Response {
	expected, prompt := "y", "Approve? [y/N] "
	if s.profile.Production {
		expected = s.profile.Name
		prompt = fmt.Sprintf("Type the profile name %q to approve: ", s.profile.Name)
	}
	ans, ok := s.cfg.IO.Ask(ctx, prompt, ApprovalTimeout)
	var r ipc.Response
	switch {
	case !ok && ctx.Err() != nil:
		rec.Event, rec.Decision = audit.EventAbandoned, "abandoned"
		s.println("client gone: request cancelled")
		r = errResp(id, ipc.CodeDenied, "the request was cancelled")
	case !ok:
		rec.Event, rec.Decision = audit.EventTimeout, "timeout"
		s.println("no answer: denied")
		r = errResp(id, ipc.CodeTimeout, "no answer from the human within the approval timeout; do not retry unless asked")
	case strings.TrimSpace(ans) != expected:
		rec.Event, rec.Decision = audit.EventDenied, "denied"
		s.println("denied")
		r = errResp(id, ipc.CodeDenied, "denied by the human; do not retry unless asked")
	default:
		return nil
	}
	s.audit(rec)
	return &r
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
	onDisk, err := pii.LoadRules(s.cfg.Root)
	if err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	if err := onDisk.Add(pattern); err != nil {
		return errResp(req.ID, ipc.CodeInvalidParams, err.Error())
	}
	if err := pii.SaveRules(s.cfg.Root, onDisk); err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	next := s.approved
	next.PIIMask = append(append([]string(nil), next.PIIMask...), pattern)
	next = config.NewPolicy(next.Profile, next.PIIMask, next.PIIAllow)
	if err := s.adopt(next, "tightened"); err != nil {
		return errResp(req.ID, ipc.CodeInternal, err.Error())
	}
	s.println("PII rule added by a client: mask " + pattern)
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
