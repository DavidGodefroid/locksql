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

	kaudit "github.com/DavidGodefroid/lockkit/audit"
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
	left := s.profile.Limits.MaxSession - s.now().Sub(s.started)
	if left < 0 {
		left = 0
	}
	return ipc.StatusResult{
		Profile:        s.profile.Name,
		Engine:         s.profile.Engine,
		Host:           s.host(),
		HostConfirmed:  true, // the host is part of the approved policy
		Production:     s.profile.Production,
		AutoApprove:    s.autoApprove(),
		AllowUnmask:    s.allowUnmask,
		ShowResults:    s.showResults,
		Tier:           s.profile.Tier.String(),
		Databases:      nonNil(s.cfg.Databases),
		Limits:         s.profile.Limits,
		IdleTimeoutInS: int(s.profile.Limits.IdleTimeout / time.Second),
		SessionEndsInS: int(left / time.Second),
		Health:         s.cfg.Health,
	}
}

// credentialsExpirer is a session whose login expires (vaultSession).
type credentialsExpirer interface{ CredentialsExpire() time.Time }

// session returns the live session, reconnecting after a lost connection.
func (s *Server) session(ctx context.Context, id int64) (engine.Session, *ipc.Response) {
	expired := ""
	if ttl := s.profile.CredentialsTTL; s.sess != nil && ttl > 0 && s.now().Sub(s.connected) >= ttl {
		// A short-lived secret (a vault lease) has expired: close the
		// connection and ask for a fresh one.
		expired = fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and the secret asked again", ttl)
		if s.profile.Credentials == config.CredentialsVault {
			expired = fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and a fresh login read from Vault", ttl)
		}
	} else if e, ok := s.sess.(credentialsExpirer); ok && !e.CredentialsExpire().IsZero() && !s.now().Before(e.CredentialsExpire()) {
		// The Vault lease of the login nears its end.
		expired = "the Vault lease of the login is ending: the connection is closed and a fresh login read from Vault"
	}
	if expired != "" {
		s.println(expired)
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
		// The reconnection may prompt (a password, a host key, the checks).
		s.waiting(true)
		sess, err := s.cfg.Reconnect(ctx, s.profile) // the policy in force now, not the start-up one
		s.waiting(false)
		if err == nil {
			s.sess = sess
			s.connected = s.now()
			return sess, nil
		}
		s.println("reconnect failed: " + safeText(secrets.Sanitize(err), false))
		if errors.Is(err, errPrivilegeAudit) {
			s.End("privilege audit failed after reconnect")
		}
		if errors.Is(err, errLockedOut) {
			s.End("fingerprint: three non-matching fingers")
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
		Values: s.typedNames(), PlanHash: pl.hash,
	})
}

// buildPlan checks and plans the statement of p: the plan, or the answer
// that refuses it (audited). query.plan stores the plan; a hub-mode run
// plans again from the stored statement (hubmode.go).
func (s *Server) buildPlan(ctx context.Context, id int64, p ipc.PlanParams) (*plan, *ipc.Response) {
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
	if p.Unmask && !s.allowUnmask {
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
	if st.Class != sqlclass.Read && sqlast.HasPlaceholder(s.dialect, st.SQL) {
		// A write is never analysed for placeholders: it would run with
		// the literal text '${...}'.
		return nil, ptr(s.refuse(ctx, id, p.Intent, db, st.SQL, class, "", p.SQL, refusal.New(refusal.Placeholder, "placeholders are only allowed in read statements, compared with a PII column: col = '${name}' or col IN ('${a}', '${b}')")))
	}
	sess, r := s.session(ctx, id)
	if r != nil {
		return nil, r
	}
	var shadow *shadowNames
	if s.profile.WriteFunctions == config.WriteFunctionsAllowlist {
		r, sn, err := s.strictWriteFunctions(ctx, sess, db, st)
		if err != nil {
			return nil, ptr(s.failed(id, "plan", err))
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
			return nil, ptr(s.failed(id, "plan", err))
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
			return nil, ptr(s.failed(id, "plan", err))
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
		return nil, ptr(s.failed(id, "plan", err))
	}
	pl.guarded = state != nil
	if state != nil && st.Class == sqlclass.Write {
		pl.sideEffects = sideEffects(*state)
	}
	if pl.hash, pl.inputs, err = s.planDigests(pl, state); err != nil {
		return nil, ptr(s.failed(id, "plan", err))
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
	pl.warnings = s.warnings(ctx, sess, pl)
	rec := withPeerRecord(ctx, audit.Record{DB: pl.db, SQL: pl.st.SQL, Class: class, Verdict: pl.level, Unmasked: pl.unmask, Warnings: pl.warnings, Intent: pl.intent})

	s.screen(ctx, pl)
	if s.cfg.Hub != nil {
		return s.hubSubmit(ctx, req.ID, sess, pl, rec, hiddenRefusal)
	}
	if hiddenRefusal != nil {
		return s.refuseOnScreen(ctx, req.ID, rec, hiddenRefusal)
	}
	// The values are asked before the approval, and asked even when the
	// approval is skipped: nothing runs while a placeholder has none.
	missing, _ := s.placeholders(pl)
	if r := s.askValues(ctx, req.ID, pl, rec, missing); r != nil {
		return *r
	}
	// The k-anonymity counts run before the approval, in auto mode too: a
	// count under k is a warning for the human, never a refusal, so the
	// agent's answer is the same whatever the counts say.
	base := pl.warnings
	kAlert := func() *ipc.Response {
		kw, refused, err := s.kCount(ctx, sess, pl)
		if refused != nil {
			r := s.refuseWarned(ctx, req.ID, pl, class, refused)
			return &r
		}
		if err != nil {
			s.auditRunFailed(rec, s.auditErrText(err, pl))
			r := s.failedPlan(req.ID, "k-anonymity check", err, pl)
			return &r
		}
		pl.warnings = append(slices.Clone(base), kw...)
		rec.Warnings = pl.warnings
		s.showKWarnings(kw)
		return nil
	}
	var start time.Time
	if s.autoApprove() && !pl.unmask {
		// No human waits in between: the response time is levelled from
		// the counts on, as it is from the statement on.
		start = time.Now()
		if r := kAlert(); r != nil {
			s.level(ctx, start)
			return *r
		}
		rec.Event, rec.Decision = audit.EventAuto, "auto"
		s.println(s.frameEnd(paint.Yellow("auto-approved") + paint.Dim(" (auto mode)")))
	} else {
		for {
			if r := kAlert(); r != nil {
				return *r
			}
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
		rec.Event, rec.Decision, rec.Approval = audit.EventApproved, "approved", s.approver.Mode()
	}
	return s.runApproved(ctx, req.ID, sess, pl, rec, class, start)
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
	if pl.unmask && !s.allowUnmask {
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
	rec.Event, rec.Decision = audit.EventRun, "ok"
	// The prompts may have waited: check the TTL again, so that an
	// approval or a value landing after it runs nothing.
	if s.now().Sub(pl.created) > PlanTTL {
		rec.Event, rec.Decision = audit.EventTimeout, "expired"
		s.audit(rec)
		s.println(paint.Fail("plan expired while waiting for approval: not run"))
		return errResp(id, ipc.CodeNoSuchPlan, "the plan expired while waiting for approval; plan the query again")
	}
	if pl.an != nil && len(pl.an.Values) > 0 {
		// The values are known now: analyse again, so that the statement
		// carries them. pl.st.SQL is the statement as the agent wrote it,
		// placeholders included: the audit keeps it.
		if r, err := s.analyzeRead(ctx, sess, pl, pl.st.SQL); err != nil || r != nil {
			if err != nil {
				// Approved already: the failure is audited like a run's.
				s.auditRunFailed(rec, s.auditErrText(err, pl))
				return s.failedPlan(id, "plan", err, pl)
			}
			return s.refuseWarned(ctx, id, pl, class, r)
		}
		if missing, _ := s.placeholders(pl); len(missing) > 0 {
			return s.refuseWarned(ctx, id, pl, class, refusal.New(refusal.Placeholder, "a placeholder has no value"))
		}
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
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		// The audit log never holds row data, even for an unmask run.
		s.auditRunFailed(rec, s.auditErrText(err, pl))
		s.println(paint.Fail("failed: " + safeText(s.errText(err, pl.st.SQL, false, pl), false)))
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
	if s.showResults && !pl.unmask && len(res.Columns) > 0 {
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

// approve closes the approval screen with the prompt and waits for the
// human (lockkit's console decides). It returns nil when approved, the
// error response otherwise (audited). retype reports that the human asked
// to type again the values the plan reuses. The approval itself is audited
// by queryRun, once the values are in.
func (s *Server) approve(ctx context.Context, id int64, pl *plan, rec audit.Record) (resp *ipc.Response, retype bool) {
	q := kconsole.Ask{Frame: s.frameColour(), Production: s.profile.Production}
	// "r" retypes, unless it is the approval answer itself (a production
	// profile named r): the Asker does not offer it then.
	if _, reused := s.placeholders(pl); len(reused) > 0 {
		q.Retype, q.RetypeNote = "r", " ${"+strings.Join(reused, "}, ${")+"}"
	}
	a := s.asker().Ask(ctx, id, q, func(b kaudit.Base) {
		if b.Event == audit.EventApproved {
			return
		}
		rec.Event, rec.Decision, rec.Reason, rec.Error, rec.Approval = b.Event, b.Decision, b.Reason, b.Error, b.Approval
		s.audit(rec)
	})
	switch {
	case a.Retype:
		return nil, true
	case a.Approved:
		return nil, false
	}
	return &a.Refusal, false
}

// unanswered audits and answers a prompt left without an answer: the
// client went away, or the approval timeout passed.
func (s *Server) unanswered(ctx context.Context, id int64, rec audit.Record) *ipc.Response {
	var r ipc.Response
	if ctx.Err() != nil {
		rec.Event, rec.Decision = audit.EventAbandoned, "abandoned"
		s.println(paint.Fail("client gone: request cancelled"))
		r = errResp(id, ipc.CodeDenied, "the request was cancelled")
	} else {
		rec.Event, rec.Decision = audit.EventTimeout, "timeout"
		s.println(paint.Fail("no answer: denied"))
		r = errResp(id, ipc.CodeTimeout, "no answer from the human within the approval timeout; do not retry unless asked")
	}
	s.audit(rec)
	return &r
}

// refuseOnScreen ends the approval screen of a plan refused by the weight
// check under a PII filter. The agent learns of the refusal only once the
// human has seen it and pressed Enter, so that answering it tells no more
// than a denial would; --skip-permissions does not skip this prompt.
//
// The client learns the code and its default hint only: the reason, its
// figures and any position stay on the console.
func (s *Server) refuseOnScreen(ctx context.Context, id int64, rec audit.Record, r *refusal.Error) ipc.Response {
	s.println(paint.Paint(s.frameColour(), "│ ") + red + "verdict REFUSE: this statement cannot be approved" + reset)
	bell(s.cfg.IO)
	// Kept when the prompt goes unanswered too.
	rec.Error, rec.Code = r.Reason, string(r.Code)
	s.waiting(true)
	_, ok := s.cfg.IO.Ask(ctx, s.frameEnd(paint.Bold("Press Enter to refuse ")), ApprovalTimeout)
	s.waiting(false)
	if !ok {
		return *s.unanswered(ctx, id, rec)
	}
	rec.Event = audit.EventRefused
	s.audit(rec)
	s.println(paint.Fail("refused [" + string(r.Code) + "]: " + safeText(r.Reason, false)))
	return refusedResp(id, hiddenWeightRefusal, refusal.New(refusal.Cost, hiddenWeightRefusal).Info("", 0))
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
