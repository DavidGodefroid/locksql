package postgres

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// maxObjectDepth bounds how far objectState follows views, rules,
// triggers and policies to the objects they use in turn.
const maxObjectDepth = 8

// fieldSep separates the fields of an object definition.
const fieldSep = "\x1f"

// ObjectState implements engine.ObjectGuard: it reads, in a read-only
// transaction, what the statement naming refs resolves to. Relation names
// are SQL names ("users", "app.users", "\"Mixed\".t"), one to three
// parts.
func (s *session) ObjectState(ctx context.Context, db string, refs engine.ObjectRefs) (engine.ObjectState, error) {
	var st engine.ObjectState
	err := s.catalog(ctx, db, func(ctx context.Context, c *pgx.Conn) error {
		var err error
		st, err = objectState(ctx, c, refs)
		return err
	})
	return st, err
}

// RunGuarded implements engine.ObjectGuard: Run, with check called on the
// state read in the statement's transaction just before the statement and
// just after it, before the commit. A statement PostgreSQL only runs
// outside a transaction is checked before and after all the same, without
// a ROLLBACK to undo it.
func (s *session) RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs engine.ObjectRefs, check engine.GuardCheck) (engine.Result, error) {
	guard := func(ctx context.Context, c *pgx.Conn, at engine.Step) error {
		os, err := objectState(ctx, c, refs)
		if err != nil {
			return err
		}
		return check(os, at)
	}
	return s.run(ctx, db, st, maxRows, guard)
}

// RunCounted implements engine.RowChecker.
func (s *session) RunCounted(ctx context.Context, db string, st sqlclass.Statement, maxRows int, check func(int64) error) (engine.Result, error) {
	if needsNoTx(st) {
		return engine.Result{}, fmt.Errorf("postgres: %s runs outside a transaction: its rows cannot be checked before a commit", strings.ToUpper(st.Kind))
	}
	return s.run(ctx, db, st, maxRows, func(_ context.Context, _ *pgx.Conn, at engine.Step) error {
		if !at.After {
			return nil
		}
		return check(at.Affected)
	})
}

// objectState reads the effective search path and the definitions of the
// objects refs names, followed through the views, rules, triggers and
// row-level policies to the relations and functions they use. Objects of
// pg_catalog and information_schema are left out: the server's own, they
// change only with the server.
func objectState(ctx context.Context, c *pgx.Conn, refs engine.ObjectRefs) (engine.ObjectState, error) {
	var st engine.ObjectState
	var path, schemas string
	if err := c.QueryRow(ctx, `SELECT pg_catalog.current_setting('search_path'), pg_catalog.current_schemas(true)::text`).Scan(&path, &schemas); err != nil {
		return st, err
	}
	st.SearchPath = path + fieldSep + schemas

	// The names as the statement writes them, resolved over the search
	// path in force; a name no relation bears resolves to nothing.
	rels, err := oids(ctx, c, `SELECT DISTINCT c.oid FROM unnest($1::text[]) x
		JOIN pg_catalog.pg_class c ON c.oid = pg_catalog.to_regclass(x)
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE `+userObject("n"), refs.Relations)
	if err != nil {
		return st, err
	}
	funcs, err := oids(ctx, c, `SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE p.proname = ANY($1::text[]) AND `+userObject("n"), refs.Functions)
	if err != nil {
		return st, err
	}
	if len(refs.Operators) > 0 {
		ops, err := defs(ctx, c, `SELECT 'operator', o.oid::regoperator::text,
				concat(o.oprcode::regprocedure::text, E'\x1f', o.oprkind, E'\x1f', o.oprcom::regoperator::text, E'\x1f', o.oprnegate::regoperator::text)
			FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
			WHERE o.oprname = ANY($1::text[]) AND `+userObject("n"), refs.Operators)
		if err != nil {
			return st, err
		}
		st.Objects = append(st.Objects, ops...)
		codes, err := oids(ctx, c, `SELECT o.oprcode::oid FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
			WHERE o.oprname = ANY($1::text[]) AND `+userObject("n"), refs.Operators)
		if err != nil {
			return st, err
		}
		funcs = append(funcs, codes...)
	}

	seenRel, seenFunc := map[uint32]bool{}, map[uint32]bool{}
	for depth := 0; depth < maxObjectDepth && (len(rels) > 0 || len(funcs) > 0); depth++ {
		rels, funcs = fresh(rels, seenRel), fresh(funcs, seenFunc)
		var nextRels, nextFuncs []uint32
		if len(rels) > 0 {
			d, err := relationDefs(ctx, c, rels)
			if err != nil {
				return st, err
			}
			st.Objects = append(st.Objects, d...)
			r, f, err := relationUses(ctx, c, rels, refs.Writes)
			if err != nil {
				return st, err
			}
			nextRels, nextFuncs = append(nextRels, r...), append(nextFuncs, f...)
		}
		if len(funcs) > 0 {
			d, err := defs(ctx, c, `SELECT 'function', p.oid::regprocedure::text,
					concat(p.provolatile, E'\x1f', p.prosrc, E'\x1f', p.probin, E'\x1f', p.proconfig::text, E'\x1f', p.prosecdef, E'\x1f', p.proleakproof, E'\x1f', (SELECT l.lanname FROM pg_catalog.pg_language l WHERE l.oid = p.prolang), E'\x1f', pg_catalog.pg_get_function_result(p.oid), E'\x1f', pg_catalog.pg_get_function_arguments(p.oid), E'\x1f', p.proacl::text, E'\x1f', pg_catalog.pg_get_userbyid(p.proowner))
				FROM pg_catalog.pg_proc p WHERE p.oid = ANY($1::oid[])`, funcs)
			if err != nil {
				return st, err
			}
			st.Objects = append(st.Objects, d...)
			// A function body in BEGIN ATOMIC records what it uses.
			r, f, err := uses(ctx, c, `d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = ANY($1::oid[])`, funcs)
			if err != nil {
				return st, err
			}
			nextRels, nextFuncs = append(nextRels, r...), append(nextFuncs, f...)
		}
		rels, funcs = nextRels, nextFuncs
	}
	// Objects still to follow past the bound would go unhashed: fail
	// closed rather than approve what was not read.
	if unseen(rels, seenRel) || unseen(funcs, seenFunc) {
		return st, fmt.Errorf("postgres: the objects the statement uses nest deeper than %d levels (views, rules, triggers, policies, defaults, constraints): it cannot be bound to a plan hash", maxObjectDepth)
	}
	slices.SortFunc(st.Objects, func(a, b engine.ObjectDef) int {
		if k := strings.Compare(a.Kind, b.Kind); k != 0 {
			return k
		}
		return strings.Compare(a.Name, b.Name)
	})
	st.Objects = slices.Compact(st.Objects)
	if st.Objects == nil {
		st.Objects = []engine.ObjectDef{}
	}
	return st, nil
}

// userObject is the condition on the namespace alias n that leaves out the
// server's own schemas.
func userObject(n string) string {
	return n + ".nspname NOT IN ('pg_catalog', 'information_schema') AND " + n + ".nspname NOT LIKE 'pg\\_toast%'"
}

// relationDefs are the definitions of relations: kind, columns, row-level
// security, grants, owner and, for a view, its query; their rules,
// triggers and policies.
func relationDefs(ctx context.Context, c *pgx.Conn, rels []uint32) ([]engine.ObjectDef, error) {
	var out []engine.ObjectDef
	for _, q := range []string{
		`SELECT 'relation', c.oid::regclass::text,
			concat(c.relkind, E'\x1f', c.relrowsecurity, E'\x1f', c.relforcerowsecurity, E'\x1f', c.relacl::text, E'\x1f', pg_catalog.pg_get_userbyid(c.relowner), E'\x1f', c.reloptions::text, E'\x1f', CASE WHEN c.relkind IN ('v', 'm') THEN pg_catalog.pg_get_viewdef(c.oid) END, E'\x1f', (SELECT string_agg(concat(a.attname, ' ', pg_catalog.format_type(a.atttypid, a.atttypmod), ' ', a.attnotnull, a.attidentity, a.attgenerated, ' ', a.attacl::text), ', ' ORDER BY a.attnum)
					FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped))
		FROM pg_catalog.pg_class c WHERE c.oid = ANY($1::oid[])`,
		`SELECT 'rule', r.ev_class::regclass::text || '.' || r.rulename,
			concat(r.ev_enabled, E'\x1f', pg_catalog.pg_get_ruledef(r.oid))
		FROM pg_catalog.pg_rewrite r WHERE r.ev_class = ANY($1::oid[]) AND r.rulename <> '_RETURN'`,
		`SELECT 'trigger', t.tgrelid::regclass::text || '.' || t.tgname,
			concat(t.tgenabled, E'\x1f', pg_catalog.pg_get_triggerdef(t.oid))
		FROM pg_catalog.pg_trigger t WHERE t.tgrelid = ANY($1::oid[]) AND NOT t.tgisinternal`,
		`SELECT 'default', d.adrelid::regclass::text || '.' || a.attname, pg_catalog.pg_get_expr(d.adbin, d.adrelid)
		FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
		WHERE d.adrelid = ANY($1::oid[])`,
		// Constraints of the relations, and the foreign keys of other
		// tables that reference them (ON DELETE CASCADE, SET NULL, ...).
		`SELECT 'constraint', c.conrelid::regclass::text || '.' || c.conname,
			concat(c.contype, E'\x1f', c.condeferrable, E'\x1f', c.condeferred, E'\x1f', c.convalidated, E'\x1f', pg_catalog.pg_get_constraintdef(c.oid))
		FROM pg_catalog.pg_constraint c WHERE c.conrelid = ANY($1::oid[]) OR c.confrelid = ANY($1::oid[])`,
		`SELECT 'inherits', i.inhrelid::regclass::text || ' < ' || i.inhparent::regclass::text, i.inhseqno::text
		FROM pg_catalog.pg_inherits i WHERE i.inhrelid = ANY($1::oid[]) OR i.inhparent = ANY($1::oid[])`,
		`SELECT 'policy', p.polrelid::regclass::text || '.' || p.polname,
			concat(p.polcmd, E'\x1f', p.polpermissive, E'\x1f', p.polroles::regrole[]::text, E'\x1f', pg_catalog.pg_get_expr(p.polqual, p.polrelid), E'\x1f', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
		FROM pg_catalog.pg_policy p WHERE p.polrelid = ANY($1::oid[])`,
	} {
		d, err := defs(ctx, c, q, rels)
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	return out, nil
}

// relationUses are the relations and functions that the views, rules,
// triggers, policies, defaults and constraints of rels use, their
// partitions and inheritance relatives and, for a write, the tables whose
// foreign keys reference them. A PL/pgSQL body records nothing in
// pg_depend: the functions it calls are not followed (only its own source
// is hashed), nor are the objects dynamic SQL reaches.
func relationUses(ctx context.Context, c *pgx.Conn, rels []uint32, writes bool) (relOut, funcOut []uint32, err error) {
	r, f, err := uses(ctx, c, `(d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_rewrite WHERE ev_class = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_policy'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_policy WHERE polrelid = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_trigger'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_trigger WHERE tgrelid = ANY($1::oid[]) AND NOT tgisinternal))
		OR (d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = ANY($1::oid[]))
		OR (d.classid = 'pg_catalog.pg_attrdef'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_attrdef WHERE adrelid = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_constraint'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_constraint WHERE conrelid = ANY($1::oid[])))`, rels)
	if err != nil {
		return nil, nil, err
	}
	// The tables a statement on rels reaches too: their partitions and
	// inheritance children and parents, and the tables whose foreign keys
	// reference them (a cascade runs their triggers).
	q := `SELECT i.inhrelid FROM pg_catalog.pg_inherits i WHERE i.inhparent = ANY($1::oid[])
		UNION SELECT i.inhparent FROM pg_catalog.pg_inherits i WHERE i.inhrelid = ANY($1::oid[])`
	if writes {
		q += ` UNION SELECT c.conrelid FROM pg_catalog.pg_constraint c WHERE c.contype = 'f' AND c.confrelid = ANY($1::oid[])`
	}
	more, err := oidsOf(ctx, c, q, rels)
	return append(r, more...), f, err
}

func oidsOf(ctx context.Context, c *pgx.Conn, q string, arg []uint32) ([]uint32, error) {
	rows, err := c.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uint32])
}

// uses are the relations and functions outside the server's own schemas
// that the pg_depend rows matching cond (on alias d) refer to.
func uses(ctx context.Context, c *pgx.Conn, cond string, arg []uint32) (rels, funcs []uint32, err error) {
	rows, err := c.Query(ctx, `SELECT DISTINCT d.refclassid = 'pg_catalog.pg_proc'::regclass, d.refobjid
		FROM pg_catalog.pg_depend d
		LEFT JOIN pg_catalog.pg_class rc ON d.refclassid = 'pg_catalog.pg_class'::regclass AND rc.oid = d.refobjid
		LEFT JOIN pg_catalog.pg_proc rp ON d.refclassid = 'pg_catalog.pg_proc'::regclass AND rp.oid = d.refobjid
		JOIN pg_catalog.pg_namespace n ON n.oid = coalesce(rc.relnamespace, rp.pronamespace)
		WHERE (`+cond+`) AND d.refclassid IN ('pg_catalog.pg_class'::regclass, 'pg_catalog.pg_proc'::regclass)
		  AND `+userObject("n"), arg)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fn bool
		var oid uint32
		if err := rows.Scan(&fn, &oid); err != nil {
			return nil, nil, err
		}
		if fn {
			funcs = append(funcs, oid)
		} else {
			rels = append(rels, oid)
		}
	}
	return rels, funcs, rows.Err()
}

func oids(ctx context.Context, c *pgx.Conn, q string, arg []string) ([]uint32, error) {
	if len(arg) == 0 {
		return nil, nil
	}
	rows, err := c.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uint32])
}

func defs[T any](ctx context.Context, c *pgx.Conn, q string, arg []T) ([]engine.ObjectDef, error) {
	rows, err := c.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("postgres: object definitions: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (engine.ObjectDef, error) {
		var d engine.ObjectDef
		err := r.Scan(&d.Kind, &d.Name, &d.Def)
		return d, err
	})
}

// unseen reports whether in holds an oid not seen yet.
func unseen(in []uint32, seen map[uint32]bool) bool {
	return slices.ContainsFunc(in, func(o uint32) bool { return !seen[o] })
}

// fresh are the oids of in not seen yet, marked seen.
func fresh(in []uint32, seen map[uint32]bool) []uint32 {
	var out []uint32
	for _, o := range in {
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}
