package console

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

// ResponseQuantum levels the time a statement takes, as the client sees
// it: the answer to query.run, success or failure, leaves at the next
// multiple of it after the run started. A query cannot turn the time it
// takes into a fine-grained signal (a timing side channel).
const ResponseQuantum = kconsole.ResponseQuantum

// genericFailure is what a client learns when the database rejects a
// statement: never the server's message, which can quote values.
const genericFailure = "statement refused by the database (the details are shown on the console)"

// catalog resolves table names for the analyser from the column catalog of
// the session, read once per database and refreshed when a name is
// unknown.
type catalog struct {
	ctx       context.Context
	sess      engine.Session
	db        string // the plan's database (MySQL, SQLite) or "" for the default
	flavor    engine.Flavor
	user      string
	databases []string
	cache     map[string][]engine.ColumnInfo // per database
	reloads   int
}

func (s *Server) newCatalog(ctx context.Context, sess engine.Session, db string) *catalog {
	if s.catalogCache == nil {
		s.catalogCache = map[string][]engine.ColumnInfo{}
	}
	return &catalog{ctx: ctx, sess: sess, db: db, flavor: sess.Flavor(), user: s.cfg.DBUser, databases: s.cfg.Databases, cache: s.catalogCache}
}

func (c *catalog) columns(db string, refresh bool) ([]engine.ColumnInfo, error) {
	if cols, ok := c.cache[db]; ok && !refresh {
		return cols, nil
	}
	cols, err := c.sess.Columns(c.ctx, db)
	if err != nil {
		return nil, err
	}
	c.cache[db] = cols
	return cols, nil
}

// Lookup implements sqlast.Catalog. For PostgreSQL the parts are [table],
// [schema, table] or [database, schema, table]; for MySQL [table] or
// [database, table]; for SQLite [table] or [schema, table].
func (c *catalog) Lookup(parts []string) ([]sqlast.Table, error) {
	tables, err := c.lookup(parts, false)
	if err != nil || len(tables) > 0 || c.reloads > 0 {
		return tables, err
	}
	// A table created since the catalog was read: read it again, once.
	c.reloads++
	return c.lookup(parts, true)
}

func (c *catalog) lookup(parts []string, refresh bool) ([]sqlast.Table, error) {
	var db, schema string
	name := parts[len(parts)-1]
	switch c.flavor {
	case engine.FlavorPostgres:
		switch len(parts) {
		case 3:
			if fold(parts[0]) != fold(c.db) && c.db != "" {
				return nil, nil
			}
			schema = parts[1]
		case 2:
			schema = parts[0]
		}
		db = c.db
	case engine.FlavorSQLite:
		db = "main"
		if len(parts) == 2 {
			db = strings.ToLower(parts[0])
			if db != "main" {
				return nil, nil
			}
		}
		if len(parts) > 2 {
			return nil, nil
		}
	default: // MySQL, MariaDB
		db = c.db
		if len(parts) > 2 {
			return nil, nil
		}
	}
	if c.flavor == engine.FlavorMySQL || c.flavor == engine.FlavorMariaDB {
		if len(parts) == 2 {
			db = ""
			for _, d := range c.databases {
				if fold(d) == parts[0] {
					db = d
				}
			}
			if db == "" {
				return nil, nil
			}
		}
	}
	cols, err := c.columns(db, refresh)
	if err != nil {
		return nil, err
	}
	byRel := map[string]*sqlast.Table{}
	var order []string
	for _, ci := range cols {
		if fold(ci.Table) != name {
			continue
		}
		if schema != "" && fold(ci.DB) != schema {
			continue
		}
		key := ci.DB + "." + ci.Table
		t, ok := byRel[key]
		if !ok {
			t = &sqlast.Table{DB: ci.DB, Name: ci.Table, View: ci.View}
			byRel[key] = t
			order = append(order, key)
		}
		t.Columns = append(t.Columns, ci.Column)
	}
	out := make([]sqlast.Table, 0, len(order))
	for _, k := range order {
		out = append(out, *byRel[k])
	}
	if c.flavor == engine.FlavorPostgres && schema == "" && len(out) > 1 {
		// search_path is "$user", public by default and SET search_path is
		// refused: prefer the user's schema, then public.
		for _, want := range []string{c.user, "public"} {
			for _, t := range out {
				if want != "" && t.DB == want {
					return []sqlast.Table{t}, nil
				}
			}
		}
	}
	return out, nil
}

func fold(s string) string { return strings.ToUpper(strings.ToLower(s)) }

// astEnv is the analyser's environment for one plan.
func (s *Server) astEnv(ctx context.Context, sess engine.Session, db string, unmask bool) sqlast.Env {
	return sqlast.Env{
		Catalog: s.newCatalog(ctx, sess, db),
		Rule: func(src sqlast.Source) (string, bool) {
			if src.View {
				return s.rules.ModeByName(src.Column)
			}
			return s.rules.Mode(src.DB, src.Table, src.Column)
		},
		Masking: !unmask,
		Value: func(kind sqlast.ValueKind, name string) (string, bool) {
			if kind == sqlast.ValueRef {
				return s.refs.get(name)
			}
			tv, ok := s.typed[name]
			return tv.value, ok
		},
	}
}

// splitExplain removes a leading EXPLAIN keyword. off is the offset of the
// statement returned in sql without its leading blanks.
func splitExplain(d sqlclass.Dialect, sql string) (inner string, explain bool, off int) {
	toks, err := sqlclass.Lex(d, strings.TrimSpace(sql))
	if err != nil || len(toks) < 2 || toks[0].Kind != sqlclass.TokWord || toks[0].Text != "EXPLAIN" {
		return sql, false, 0
	}
	text := strings.TrimSpace(sql)
	return text[toks[1].Pos:], true, toks[1].Pos
}

// readPlan parses and analyses a read statement, then weighs it and its
// k-anonymity checks with EXPLAIN. The plan keeps the analysis for the
// run. It returns the refusal, if any; an error is the engine's.
func (s *Server) readPlan(ctx context.Context, sess engine.Session, pl *plan, sql string) (*refusal.Error, error) {
	if r, err := s.analyzeRead(ctx, sess, pl, sql); err != nil || r != nil {
		return r, err
	}
	an := pl.an
	ep, err := sess.Explain(ctx, pl.db, pl.runSQL)
	if err != nil {
		if errors.Is(err, engine.ErrConnLost) {
			return nil, err
		}
		s.println("EXPLAIN failed: " + safeText(s.errText(err, pl.runSQL, false, pl), false))
		return refusal.New(refusal.Engine, "EXPLAIN failed: "+genericFailure), nil
	}
	pl.explain = &ep
	for _, k := range an.KChecks {
		kp, err := sess.Explain(ctx, pl.db, k.SQL)
		if err != nil {
			if errors.Is(err, engine.ErrConnLost) {
				return nil, err
			}
			s.println("EXPLAIN of the k-anonymity check failed: " + safeText(s.errText(err, k.SQL, false, pl), false))
			return refusal.New(refusal.Engine, "the k-anonymity check of this statement cannot be planned: "+genericFailure), nil
		}
		pl.kExplains = append(pl.kExplains, kp)
	}
	if r := s.assessK(pl); r != nil && !estimatesHidden(pl) {
		return r, nil
	}
	return nil, nil
}

// assessK weighs the k-anonymity counts of a plan under the limits in
// force. It returns the refusal of the first one refused.
func (s *Server) assessK(pl *plan) *refusal.Error {
	for _, kp := range pl.kExplains {
		if v := weight.Assess(kp, s.profile.Limits, s.profile.Production); v.Level == weight.Refuse {
			return refusal.New(refusal.Cost, "weight check of the k-anonymity count: "+strings.Join(v.Reasons, "; "))
		}
	}
	return nil
}

// analyzeRead parses and analyses a read statement and sets the plan's
// analysis and the statement that runs (placeholder values substituted).
// sql starts where the agent's statement does, pl.base bytes into pl.src.
// It returns the refusal, if any; an error is the engine's.
func (s *Server) analyzeRead(ctx context.Context, sess engine.Session, pl *plan, sql string) (*refusal.Error, error) {
	parsed, err := sqlast.Parse(s.dialect, sql)
	if err != nil {
		return shifted(err, pl.base), nil
	}
	an, err := sqlast.Analyze(parsed, s.astEnv(ctx, sess, pl.db, pl.unmask))
	if err != nil {
		var r *sqlclass.Refusal
		if errors.As(err, &r) {
			return shifted(err, pl.base), nil
		}
		return nil, err
	}
	pl.shadow = shadowNamesOf(an, parsed)
	if r, err := s.checkShadows(ctx, sess, pl.db, pl.shadow); err != nil || r != nil {
		return r, err
	}
	pl.an = an
	if len(s.rules.Mask) > 0 {
		for _, rel := range an.Relations {
			if pii.StatementTextRelation(s.dialect, rel) {
				return refusal.New(refusal.SystemObject, rel[strings.LastIndexByte(rel, '.')+1:]+" holds the text of past statements, substituted values included; it cannot be read while PII mask rules exist"), nil
			}
		}
	}
	pl.isExplain = parsed.Explain
	body := parsed.SQL
	if parsed.Explain {
		body = parsed.SQL[parsed.Query.Sp.Pos:parsed.Query.Sp.End]
	}
	pl.runSQL = an.RunSQL(body)
	return nil, nil
}

// strictWriteFunctions applies write_functions = "allowlist": a write may
// call allowlisted functions only (sqlast.CheckWriteFunctions), and CALL,
// which runs a stored procedure the classifier cannot see, is refused.
// DDL is not covered: a DDL tier can create functions and triggers.
//
// Every column of the write is also resolved against the catalog
// (sqlast.Analyze, PII usage rules off: writePlan applies them): in
// PostgreSQL, rel.name where rel has no column name calls name(rel).
// It returns the refusal, if any, and the names checkShadows looks up
// again at run time; an error is the engine's.
func (s *Server) strictWriteFunctions(ctx context.Context, sess engine.Session, db string, st sqlclass.Statement) (*refusal.Error, *shadowNames, error) {
	switch {
	case st.Kind == "call":
		return refusal.New(refusal.Function, `CALL is not allowed under write_functions = "allowlist" (a stored procedure runs code the classifier cannot see)`), nil, nil
	case st.Class != sqlclass.Write:
		return nil, nil, nil
	}
	if err := sqlast.CheckWriteFunctions(s.dialect, st.SQL); err != nil {
		return refusal.From(err), nil, nil
	}
	parsed, err := sqlast.ParseWrite(s.dialect, st.SQL)
	if err != nil {
		return refusal.From(err), nil, nil
	}
	env := s.astEnv(ctx, sess, db, true)
	env.WriteFuncs = true
	an, err := sqlast.Analyze(parsed, env)
	if err != nil {
		var r *sqlclass.Refusal
		if errors.As(err, &r) {
			return r, nil, nil
		}
		return nil, nil, err
	}
	sn := shadowNamesOf(an, parsed)
	r, err := s.checkShadows(ctx, sess, db, sn)
	return r, sn, err
}

// shadowNames are the functions and operators a statement calls, lower
// case, sorted and unique, as checkShadows looks them up.
type shadowNames struct{ funcs, ops []string }

// shadowNamesOf lists the functions an analysed statement calls (and
// COUNT and MIN, which its k-anonymity counts call) and its operators.
func shadowNamesOf(an *sqlast.Analysis, st *sqlast.Statement) *shadowNames {
	var funcs []string
	for _, f := range an.Funcs {
		funcs = append(funcs, strings.ToLower(f))
	}
	if len(an.KChecks) > 0 {
		funcs = append(funcs, "count", "min")
	}
	slices.Sort(funcs)
	return &shadowNames{funcs: slices.Compact(funcs), ops: sqlast.Operators(st)}
}

// checkShadows refuses a statement that calls an allowlisted function, or
// uses an operator, that a user-defined function or operator outside
// pg_catalog also names, on a server that resolves the best match over
// the search path (engine.FunctionShadows): an overload with a closer
// argument type would run instead. Only PostgreSQL resolves names that
// way; a PostgreSQL session that cannot look them up (a wrapper that does
// not pass the lookup on) fails the plan. The plan looks them up, and the
// run again just before the statement, so that one created in between is
// caught (what is created during the statement itself is not). It returns
// the refusal, if any; an error is the engine's.
func (s *Server) checkShadows(ctx context.Context, sess engine.Session, db string, sn *shadowNames) (*refusal.Error, error) {
	if sn == nil || sess.Flavor() != engine.FlavorPostgres {
		return nil, nil
	}
	if len(sn.funcs) > 0 {
		hit, err := engine.ShadowedFunctions(ctx, sess, db, sn.funcs)
		if err != nil {
			return nil, err
		}
		if len(hit) > 0 {
			return refusal.Newf(refusal.Function, "function %s is also defined outside pg_catalog in this database: a user-defined overload could run instead of the built-in, so the call is refused (ask the human to check that function)",
				strings.Join(hit, ", ")), nil
		}
	}
	hit, err := engine.ShadowedOperators(ctx, sess, db, sn.ops)
	if err != nil {
		return nil, err
	}
	if len(hit) > 0 {
		return refusal.Newf(refusal.Function, "operator %s is also defined outside pg_catalog in this database: a user-defined overload could run instead of the built-in, so the statement is refused (ask the human to check that operator)",
			strings.Join(hit, ", ")), nil
	}
	return nil, nil
}

// writePlan checks a write before it runs. While mask rules exist, a
// write whose rows come back or that stores a query's rows
// (sqlast.NeedsWriteAnalysis) is parsed and analysed like a read: its
// RETURNING list and the outer SELECT of its data-modifying CTEs are
// resolved to their base columns and masked by provenance when it runs,
// and anything the analysis cannot resolve is refused. Other writes pass
// the checks by column name (pii.PlanCheck).
func (s *Server) writePlan(ctx context.Context, sess engine.Session, pl *plan) (*refusal.Error, error) {
	st := pl.st
	if len(s.rules.Mask) == 0 || !sqlast.NeedsWriteAnalysis(s.dialect, st.SQL) {
		if err := pii.PlanCheck(st, s.rules, s.dialect, sess.OriginColumns()); err != nil {
			return shifted(err, pl.base), nil
		}
		return nil, nil
	}
	if err := pii.WriteValuesViolation(st, s.rules, s.dialect); err != nil {
		return shifted(err, pl.base), nil
	}
	parsed, err := sqlast.ParseWrite(s.dialect, st.SQL)
	if err != nil {
		return shifted(err, pl.base), nil
	}
	an, err := sqlast.Analyze(parsed, s.astEnv(ctx, sess, pl.db, false))
	if err != nil {
		var r *sqlclass.Refusal
		if errors.As(err, &r) {
			return shifted(err, pl.base), nil
		}
		return nil, err
	}
	for _, rel := range an.Relations {
		if pii.StatementTextRelation(s.dialect, rel) {
			return refusal.New(refusal.SystemObject, rel[strings.LastIndexByte(rel, '.')+1:]+" holds the text of past statements, substituted values included; it cannot be read while PII mask rules exist"), nil
		}
	}
	pl.an, pl.runSQL = an, st.SQL
	return nil, nil
}

// clientSummary is the plan summary a client may see: row estimates and
// costs are hidden when the statement filters on a PII column, since the
// planner's statistics would answer the question the k-anonymity check
// guards.
func clientSummary(pl *plan) (string, []string) {
	if estimatesHidden(pl) {
		return "estimates hidden: the statement filters on a PII column", nil
	}
	return pl.summary, pl.reasons
}

// estimatesHidden reports whether the plan's weight check stays on the
// console: its estimates, its reasons and its verdict. The verdict is then
// decided when the plan runs, so that query.plan answers the same whatever
// the planner's statistics say about the filtered value.
func estimatesHidden(pl *plan) bool {
	return pl.an != nil && pl.an.PIIFilter && !pl.unmask
}

// hiddenWeightRefusal is the client answer of a weight refusal whose
// details stay on the console.
const hiddenWeightRefusal = "refused by the weight check (the details are shown on the console)"

// kCount runs the k-anonymity row counts of a plan before its approval
// and returns a warning for each count under k. A count never refuses: it
// helps the human decide, and the agent learns nothing of it. A plan with
// placeholder values is counted with them substituted. The error is the
// connection's.
func (s *Server) kCount(ctx context.Context, sess engine.Session, pl *plan) ([]string, error) {
	k := s.profile.Limits.KAnonymity
	if pl.an == nil || pl.unmask || k <= 1 {
		return nil, nil
	}
	counted := pl
	if len(pl.an.Values) > 0 {
		// Analysed again once approved: a refusal or a failure here is
		// that analysis's to report.
		cp := *pl
		if r, err := s.analyzeRead(ctx, sess, &cp, pl.st.SQL); err != nil || r != nil {
			return nil, nil
		}
		counted = &cp
	}
	if t := s.profile.Limits.StatementTimeout; t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t+runGrace)
		defer cancel()
	}
	// The counts call COUNT and MIN and compare: a function or operator
	// created since the plan would run in them first.
	if r, err := s.checkShadows(ctx, sess, pl.db, counted.shadow); err != nil || r != nil {
		if err == nil {
			err = r
		}
		return nil, err
	}
	var out []string
	add := func(w string) {
		if !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	for _, c := range counted.an.KChecks {
		st := sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: c.SQL, Limit: 1}
		res, err := sess.Run(ctx, pl.db, st, 1)
		if err != nil {
			if errors.Is(err, engine.ErrConnLost) || ctx.Err() != nil {
				return nil, err
			}
			s.println("k-anonymity check failed: " + safeText(s.errText(err, c.SQL, false, counted), false))
			add("k-anonymity: a count could not run, so the rows this statement covers are unknown")
			continue
		}
		var v any = int64(0) // no row: nothing matches
		if len(res.Rows) > 0 && len(res.Rows[0]) > 0 {
			v = res.Rows[0][0]
		}
		if c.Grouped && (v == nil || len(res.Rows) == 0) {
			continue // no group: nothing to show
		}
		n, ok := toInt(v)
		if !ok {
			add("k-anonymity: a count returned no number, so the rows this statement covers are unknown")
			continue
		}
		if n < int64(k) {
			what := "the PII filter matches"
			if c.Grouped {
				what = "a group covers"
			}
			add(fmt.Sprintf("k-anonymity: %s fewer than k=%d rows (%d)", what, k, n))
		}
	}
	return out, nil
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case int:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(x), true
	case float64:
		return int64(x), true
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// level waits until the next multiple of ResponseQuantum after start.
func (s *Server) level(ctx context.Context, start time.Time) { kconsole.Level(ctx, s.quantum, start) }

// explainResult is the result of an approved EXPLAIN statement: the
// engine's plan, as the console read it.
func explainResult(ep *engine.Plan) engine.Result {
	return engine.Result{
		Columns: []engine.ResultColumn{{Label: "plan"}},
		Rows:    [][]any{{string(ep.Raw)}},
	}
}

// maskRead masks the result of a read plan. An error means the result
// cannot be masked with certainty and must be dropped.
func (s *Server) maskRead(res *engine.Result, pl *plan, sess engine.Session) error {
	if pl.unmask {
		return nil
	}
	if pl.isExplain {
		// The plan holds no rows, only the statement's own constants and
		// the planner's figures: the value detectors suffice.
		pii.MaskResult(res, pii.Rules{}, s.detectors, false)
		return nil
	}
	if pl.st.Class != sqlclass.Read && len(res.Columns) == 0 {
		return nil // a write that returned no rows (SQLite does not read them)
	}
	// A PII filter on a literal of the agent: the agent chose the value
	// behind every cell it selects, so no cell gets a reference. Nor does
	// a write's: it keeps no result in the reference store.
	var cell func(row, col int, v any) string
	if !pl.an.LitFilter && pl.st.Class == sqlclass.Read {
		n := s.refs.begin()
		cell = func(row, col int, v any) string { return s.refs.put(n, row, col, pii.CellText(v)) }
	}
	return pii.MaskOutputs(res, pl.an.Outputs, s.rules, s.detectors, cell, sess.OriginColumns())
}
