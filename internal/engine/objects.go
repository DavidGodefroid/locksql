package engine

import (
	"context"
	"errors"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// ObjectRefs are the objects a statement names: the relation names as SQL
// writes them (users, app.users, "Mixed".t: resolved over the search path,
// a name no relation bears is ignored), the functions it calls (lower case)
// and the operators it uses.
type ObjectRefs struct {
	Relations []string `json:"relations"`
	Functions []string `json:"functions"`
	Operators []string `json:"operators"`
	// Writes: the statement writes; the tables whose foreign keys
	// reference its relations with CASCADE, SET NULL or SET DEFAULT are
	// followed too (a cascade reaches them); with DDL, every referencing
	// table (TRUNCATE ... CASCADE).
	Writes bool `json:"writes,omitempty"`
	// DDL: the statement changes the schema; the event triggers that fire
	// on it are read too.
	DDL bool `json:"ddl,omitempty"`
}

// ObjectDef is the definition of one object a statement resolves to, as
// the server holds it: whatever would change what the statement does.
type ObjectDef struct {
	// Kind is relation, rule, trigger, policy or function.
	Kind string `json:"kind"`
	// Name identifies the object ("public.users", "public.f(integer)").
	Name string `json:"name"`
	// Def is its definition and the settings that change what it does.
	Def string `json:"def"`
}

// ObjectState is what a statement resolves to on the server: the effective
// search path and the definitions of the objects it names, followed
// through views, rules, triggers and row-level policies. Sorted by kind
// and name.
type ObjectState struct {
	SearchPath string      `json:"search_path"`
	Objects    []ObjectDef `json:"objects"`
}

// ObjectGuard is implemented by an engine that can read the definitions a
// statement resolves to (PostgreSQL), and check them around the statement:
// RunGuarded runs st like Run, calling check with the state read in the
// statement's own transaction just before the statement (after false) and
// again just after it, before the commit (after true). A check error ends the transaction with a
// ROLLBACK and is returned as is.
type ObjectGuard interface {
	ObjectState(ctx context.Context, db string, refs ObjectRefs) (ObjectState, error)
	RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs ObjectRefs, check func(st ObjectState, after bool) error) (Result, error)
}

// ErrNoObjectGuard is the error of a session wrapper whose session does not
// implement ObjectGuard.
var ErrNoObjectGuard = errors.New("engine: this session cannot read object definitions")

// ObjectStateOf passes the read on to s, for session wrappers.
func ObjectStateOf(ctx context.Context, s Session, db string, refs ObjectRefs) (ObjectState, error) {
	g, ok := s.(ObjectGuard)
	if !ok {
		return ObjectState{}, ErrNoObjectGuard
	}
	return g.ObjectState(ctx, db, refs)
}

// RunGuarded passes the guarded run on to s, for session wrappers.
func RunGuarded(ctx context.Context, s Session, db string, st sqlclass.Statement, maxRows int, refs ObjectRefs, check func(st ObjectState, after bool) error) (Result, error) {
	g, ok := s.(ObjectGuard)
	if !ok {
		return Result{}, ErrNoObjectGuard
	}
	return g.RunGuarded(ctx, db, st, maxRows, refs, check)
}
