package console

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	"github.com/DavidGodefroid/locksql/internal/weight"
)

// ResponseQuantum levels the time a statement takes, as the client sees
// it: the answer to query.run, success or failure, leaves at the next
// multiple of it after the run started. A query cannot turn the time it
// takes into a fine-grained signal (a timing side channel).
const ResponseQuantum = 250 * time.Millisecond

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

// splitExplain removes a leading EXPLAIN keyword.
func splitExplain(d sqlclass.Dialect, sql string) (string, bool) {
	toks, err := sqlclass.Lex(d, strings.TrimSpace(sql))
	if err != nil || len(toks) < 2 || toks[0].Kind != sqlclass.TokWord || toks[0].Text != "EXPLAIN" {
		return sql, false
	}
	text := strings.TrimSpace(sql)
	return text[toks[1].Pos:], true
}

// readPlan parses and analyses a read statement, then weighs it and its
// k-anonymity checks with EXPLAIN. The plan keeps the analysis for the run.
func (s *Server) readPlan(ctx context.Context, sess engine.Session, pl *plan, sql string) (string, bool, error) {
	if reason, refused, err := s.analyzeRead(ctx, sess, pl, sql); err != nil || refused {
		return reason, refused, err
	}
	an := pl.an
	ep, err := sess.Explain(ctx, pl.db, pl.runSQL)
	if err != nil {
		if errors.Is(err, engine.ErrConnLost) {
			return "", false, err
		}
		s.println("EXPLAIN failed: " + s.errText(err, pl.runSQL, false, pl))
		return "EXPLAIN failed: " + genericFailure, true, nil
	}
	pl.explain = &ep
	for _, k := range an.KChecks {
		kp, err := sess.Explain(ctx, pl.db, k.SQL)
		if err != nil {
			if errors.Is(err, engine.ErrConnLost) {
				return "", false, err
			}
			s.println("EXPLAIN of the k-anonymity check failed: " + s.errText(err, k.SQL, false, pl))
			return "the k-anonymity check of this statement cannot be planned: " + genericFailure, true, nil
		}
		pl.kExplains = append(pl.kExplains, kp)
	}
	if reason, refused := s.assessK(pl); refused && !estimatesHidden(pl) {
		return reason, true, nil
	}
	return "", false, nil
}

// assessK weighs the k-anonymity counts of a plan under the limits in
// force. It reports the refusal reason of the first one refused.
func (s *Server) assessK(pl *plan) (string, bool) {
	for _, kp := range pl.kExplains {
		if v := weight.Assess(kp, s.profile.Limits, s.profile.Production); v.Level == weight.Refuse {
			return "weight check of the k-anonymity count: " + strings.Join(v.Reasons, "; "), true
		}
	}
	return "", false
}

// analyzeRead parses and analyses a read statement and sets the plan's
// analysis and the statement that runs (placeholder values substituted).
func (s *Server) analyzeRead(ctx context.Context, sess engine.Session, pl *plan, sql string) (string, bool, error) {
	parsed, err := sqlast.Parse(s.dialect, sql)
	if err != nil {
		return err.Error(), true, nil
	}
	an, err := sqlast.Analyze(parsed, s.astEnv(ctx, sess, pl.db, pl.unmask))
	if err != nil {
		var r *sqlclass.Refusal
		if errors.As(err, &r) {
			return err.Error(), true, nil
		}
		return "", false, err
	}
	pl.an = an
	if len(s.rules.Mask) > 0 {
		for _, rel := range an.Relations {
			if pii.StatementTextRelation(s.dialect, rel) {
				return rel[strings.LastIndexByte(rel, '.')+1:] + " holds the text of past statements, substituted values included; it cannot be read while PII mask rules exist", true, nil
			}
		}
	}
	pl.isExplain = parsed.Explain
	body := parsed.SQL
	if parsed.Explain {
		body = parsed.SQL[parsed.Query.Sp.Pos:parsed.Query.Sp.End]
	}
	pl.runSQL = an.RunSQL(body)
	return "", false, nil
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

// kCheck runs the k-anonymity row counts of an approved plan. It returns
// the refusal reason, if any.
func (s *Server) kCheck(ctx context.Context, sess engine.Session, pl *plan) (string, error) {
	k := s.profile.Limits.KAnonymity
	if pl.an == nil || pl.unmask || k <= 1 {
		return "", nil
	}
	for _, c := range pl.an.KChecks {
		st := sqlclass.Statement{Class: sqlclass.Read, Kind: "select", SQL: c.SQL, Limit: 1}
		res, err := sess.Run(ctx, pl.db, st, 1)
		if err != nil {
			if errors.Is(err, engine.ErrConnLost) || ctx.Err() != nil {
				return "", err
			}
			s.println("k-anonymity check failed: " + s.errText(err, c.SQL, false, pl))
			return "the k-anonymity check could not run: " + genericFailure, nil
		}
		if len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
			if c.Grouped {
				continue
			}
			return fmt.Sprintf("fewer than %d rows match the PII filter (k-anonymity)", k), nil
		}
		v := res.Rows[0][0]
		if v == nil && c.Grouped {
			continue // no group: nothing to show
		}
		n, ok := toInt(v)
		if !ok {
			return "the k-anonymity check returned no count", nil
		}
		if n < int64(k) {
			if c.Grouped {
				return fmt.Sprintf("a group would cover fewer than %d rows (k-anonymity)", k), nil
			}
			return fmt.Sprintf("fewer than %d rows match the PII filter (k-anonymity)", k), nil
		}
	}
	return "", nil
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
func (s *Server) level(ctx context.Context, start time.Time) {
	if s.quantum <= 0 {
		return
	}
	el := time.Since(start)
	wait := s.quantum - el%s.quantum
	if wait == s.quantum && el > 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

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
	// A PII filter on a literal of the agent: the agent chose the value
	// behind every cell it selects, so no cell gets a reference.
	var cell func(row, col int, v any) string
	if !pl.an.LitFilter {
		n := s.refs.begin()
		cell = func(row, col int, v any) string { return s.refs.put(n, row, col, pii.CellText(v)) }
	}
	return pii.MaskOutputs(res, pl.an.Outputs, s.rules, s.detectors, cell, sess.OriginColumns())
}
