package console

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// planHashVersion is the version of planInputs: a change of what the hash
// covers changes it.
const planHashVersion = 1

// planInputs is what a plan hash covers: the statement (normalised), where
// it runs, the policy in force and, on an engine that can read them
// (PostgreSQL), the effective search path and the definitions of every
// object the statement resolves to. Any change between the plan and the
// run, or during the run, changes the hash.
type planInputs struct {
	V        int    `json:"v"`
	Profile  string `json:"profile"`
	Engine   string `json:"engine"`
	Host     string `json:"host"`
	DB       string `json:"db"`
	SQL      string `json:"sql"`
	Unmask   bool   `json:"unmask"`
	PolicyFP string `json:"policy_fp"`
	// State is nil on an engine that cannot read definitions.
	State *engine.ObjectState `json:"state"`
}

// normalizedSQL is sql as its tokens: comments and spacing dropped, words
// in upper case, quoted names and literals as written.
func normalizedSQL(d sqlclass.Dialect, sql string) string {
	toks, err := sqlclass.Lex(d, sql)
	if err != nil {
		return strings.TrimSpace(sql)
	}
	texts := make([]string, len(toks))
	for i, t := range toks {
		texts[i] = t.Text
	}
	return strings.Join(texts, " ")
}

// objectRefs are the objects pl names, for the plan hash: every name of one
// or two parts as the statement writes it (the engine resolves the
// relations among them over the search path), the relations the analysis
// resolved, the names called as functions and the operators.
func objectRefs(d sqlclass.Dialect, pl *plan) engine.ObjectRefs {
	var refs engine.ObjectRefs
	toks, _ := sqlclass.Lex(d, pl.st.SQL)
	ident := func(t sqlclass.Token) (string, bool) {
		switch t.Kind {
		case sqlclass.TokWord:
			return strings.ToLower(t.Text), true
		case sqlclass.TokQuotedIdent:
			return t.Text, true
		}
		return "", false
	}
	dot := func(i int) bool { return i < len(toks) && toks[i].Kind == sqlclass.TokPunct && toks[i].Text == "." }
	for i := 0; i < len(toks); i++ {
		first, ok := ident(toks[i])
		if !ok || i > 0 && dot(i-1) {
			continue
		}
		name, last, end := first, first, i
		if dot(i+1) && i+2 < len(toks) {
			if second, ok := ident(toks[i+2]); ok && !dot(i+3) {
				name, last, end = first+"."+second, second, i+2
			}
		}
		if dot(end + 1) {
			continue // three parts or more: no relation of this database
		}
		refs.Relations = append(refs.Relations, name)
		if end+1 < len(toks) && toks[end+1].Kind == sqlclass.TokPunct && toks[end+1].Text == "(" {
			refs.Functions = append(refs.Functions, strings.Trim(strings.ToLower(last), `"`))
		}
	}
	if pl.an != nil {
		for _, r := range pl.an.Relations {
			schema, table, ok := strings.Cut(r, ".")
			if ok {
				refs.Relations = append(refs.Relations, quoteIdent(schema)+"."+quoteIdent(table))
			}
		}
		for _, f := range pl.an.Funcs {
			refs.Functions = append(refs.Functions, strings.ToLower(f))
		}
	}
	refs.Writes = pl.st.Class != sqlclass.Read
	if pl.shadow != nil {
		refs.Functions = append(refs.Functions, pl.shadow.funcs...)
		refs.Operators = append(refs.Operators, pl.shadow.ops...)
	}
	for _, l := range []*[]string{&refs.Relations, &refs.Functions, &refs.Operators} {
		slices.Sort(*l)
		*l = slices.Compact(*l)
		if *l == nil {
			*l = []string{}
		}
	}
	return refs
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// planState reads what pl resolves to on the server, nil on an engine
// that cannot read definitions. A PostgreSQL session that cannot (a
// wrapper that does not pass the read on) fails the plan.
func (s *Server) planState(ctx context.Context, sess engine.Session, pl *plan) (*engine.ObjectState, error) {
	st, err := engine.ObjectStateOf(ctx, sess, pl.db, pl.refs)
	if errors.Is(err, engine.ErrNoObjectGuard) && sess.Flavor() != engine.FlavorPostgres {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// planHash is the hash of pl's inputs under the policy in force, with
// state as read from the server.
func (s *Server) planHash(pl *plan, state *engine.ObjectState) (string, error) {
	fp, err := ticket.HashOf(s.approved)
	if err != nil {
		return "", err
	}
	return ticket.HashOf(planInputs{
		V: planHashVersion, Profile: s.profile.Name, Engine: s.profile.Engine, Host: s.host(), DB: pl.db,
		SQL: normalizedSQL(s.dialect, pl.st.SQL), Unmask: pl.unmask, PolicyFP: fp, State: state,
	})
}

// errStale is the check error of a guarded run whose plan hash no longer
// matches.
type errStale struct{ after bool }

func (e errStale) Error() string {
	if e.after {
		return "the database objects the statement uses changed while it ran: rolled back"
	}
	return "the policy or the database objects the statement uses changed since the plan"
}

// staleCheck is the check of a guarded run of pl: the hash of the state
// read in the statement's transaction must be the plan's, and a write must
// change no more rows than its bound (rowCheck). After a statement other
// than a read or a write (DDL changes what it names), only the check
// before it counts.
func (s *Server) staleCheck(pl *plan) engine.GuardCheck {
	return func(st engine.ObjectState, at engine.Step) error {
		if at.After && pl.st.Class != sqlclass.Read && pl.st.Class != sqlclass.Write {
			return nil
		}
		h, err := s.planHash(pl, &st)
		if err != nil {
			return err
		}
		if h != pl.hash {
			return errStale{after: at.After}
		}
		if at.After {
			return pl.rowCheck(at.Affected)
		}
		return nil
	}
}

// errRowcount is the check error of a write that changed more rows than
// its approval allows (plan.maxAffected): rolled back.
type errRowcount struct{ affected, max int64 }

func (e errRowcount) Error() string {
	return fmt.Sprintf("the write would have changed %d rows, more than the %d its approval allows: rolled back", e.affected, e.max)
}

// rowCheck is the rowcount check of a write's run, in its own transaction
// before the commit: no more rows than pl.maxAffected (0: no bound).
func (pl *plan) rowCheck(affected int64) error {
	if pl.maxAffected > 0 && pl.st.Class == sqlclass.Write && affected > pl.maxAffected {
		return errRowcount{affected: affected, max: pl.maxAffected}
	}
	return nil
}
