package engine

import (
	"context"
	"errors"
	"strings"

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
// statement's own transaction just before the statement (Step.After false)
// and again just after it, before the commit (Step.After true, with the
// rows a write changed). A check error ends the transaction with a
// ROLLBACK and is returned as is.
type ObjectGuard interface {
	ObjectState(ctx context.Context, db string, refs ObjectRefs) (ObjectState, error)
	RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs ObjectRefs, check GuardCheck) (Result, error)
}

// Step is where a guarded run calls its check: before the statement, or
// after it (After), before the commit, with the rows a write-class
// statement changed (Affected).
type Step struct {
	After    bool
	Affected int64
}

// GuardCheck is the check of a guarded run (ObjectGuard.RunGuarded).
type GuardCheck func(st ObjectState, at Step) error

// RowChecker is implemented by an engine that can check the rows a
// write-class statement changed in its own transaction: RunCounted runs st
// like Run and calls check with Result.Affected once the statement ran,
// before the commit. A check error ends the transaction with a ROLLBACK
// and is returned as is. A statement that runs outside a transaction is
// refused.
type RowChecker interface {
	RunCounted(ctx context.Context, db string, st sqlclass.Statement, maxRows int, check func(affected int64) error) (Result, error)
}

// ErrUncounted is matched (errors.Is) by the refusal of a counted run
// (RowChecker) whose rows cannot be checked before a commit: a statement
// that runs outside a transaction or commits implicitly, or a write a
// ROLLBACK may not undo. Nothing ran; the same statement is refused again.
var ErrUncounted = errors.New("engine: the rows this statement changes cannot be checked before a commit")

// Uncounted marks err as such a refusal (ErrUncounted); its message is
// err's.
func Uncounted(err error) error { return uncounted{err} }

type uncounted struct{ error }

func (e uncounted) Is(target error) bool { return target == ErrUncounted }
func (e uncounted) Unwrap() error        { return e.error }

// TriggerLister is implemented by an engine without an ObjectGuard that
// can list the triggers of the tables a write names: what changes rows
// beside the statement itself, which a rowcount bound does not count.
// names are the names as the statement writes them (one or two parts,
// quoted or not); a name no table bears is ignored. Each trigger is
// "trigger <schema>.<table>.<name> (<timing> <event>)".
type TriggerLister interface {
	Triggers(ctx context.Context, db string, names []string) ([]string, error)
}

// ErrNoTriggerList is the error of a session that does not implement
// TriggerLister.
var ErrNoTriggerList = errors.New("engine: this session cannot list triggers")

// TriggersOf passes the listing on to s, for session wrappers.
func TriggersOf(ctx context.Context, s Session, db string, names []string) ([]string, error) {
	g, ok := s.(TriggerLister)
	if !ok {
		return nil, ErrNoTriggerList
	}
	return g.Triggers(ctx, db, names)
}

// SplitName splits a one- or two-part SQL name as a statement writes it
// ("t", "app.t", "`app`.`t`", "\"T\"", "[t]") into its schema ("" for
// one part) and its name, quotes removed and folded to lower case.
func SplitName(name string) (schema, table string) {
	unquote := func(p string) string {
		p = strings.TrimSpace(p)
		if len(p) >= 2 {
			switch {
			case p[0] == '`' && p[len(p)-1] == '`':
				p = strings.ReplaceAll(p[1:len(p)-1], "``", "`")
			case p[0] == '"' && p[len(p)-1] == '"':
				p = strings.ReplaceAll(p[1:len(p)-1], `""`, `"`)
			case p[0] == '[' && p[len(p)-1] == ']':
				p = p[1 : len(p)-1]
			}
		}
		return strings.ToLower(p)
	}
	if i := lastDot(name); i >= 0 {
		return unquote(name[:i]), unquote(name[i+1:])
	}
	return "", unquote(name)
}

// lastDot is the index of the dot that separates the parts of name,
// outside quotes, or -1.
func lastDot(name string) int {
	var quote byte
	at := -1
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '`' || c == '"':
			quote = c
		case c == '[':
			quote = ']'
		case c == '.':
			at = i
		}
	}
	return at
}

// ErrNoRowCheck is the error of a session wrapper whose session does not
// implement RowChecker.
var ErrNoRowCheck = errors.New("engine: this session cannot check the rows a write changes before its commit")

// RunCounted passes the counted run on to s, for session wrappers.
func RunCounted(ctx context.Context, s Session, db string, st sqlclass.Statement, maxRows int, check func(affected int64) error) (Result, error) {
	g, ok := s.(RowChecker)
	if !ok {
		return Result{}, ErrNoRowCheck
	}
	return g.RunCounted(ctx, db, st, maxRows, check)
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
func RunGuarded(ctx context.Context, s Session, db string, st sqlclass.Statement, maxRows int, refs ObjectRefs, check GuardCheck) (Result, error) {
	g, ok := s.(ObjectGuard)
	if !ok {
		return Result{}, ErrNoObjectGuard
	}
	return g.RunGuarded(ctx, db, st, maxRows, refs, check)
}
