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
		named := operatorClosure(`SELECT o.oid FROM pg_catalog.pg_operator o WHERE o.oprname = ANY($1::text[])`)
		ops, err := defs(ctx, c, operatorDef+`
			WHERE o.oid IN `+named+` AND `+userObject("n"), refs.Operators)
		if err != nil {
			return st, err
		}
		st.Objects = append(st.Objects, ops...)
		codes, err := oids(ctx, c, `SELECT o.oprcode::oid FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
			WHERE o.oid IN `+named+` AND o.oprcode <> 0 AND `+userObject("n"), refs.Operators)
		if err != nil {
			return st, err
		}
		funcs = append(funcs, codes...)
	}

	if refs.Cascade && len(rels) > 0 {
		// DROP ... CASCADE and ALTER TABLE ... DROP COLUMN ... CASCADE drop
		// what depends on the relations too (cascadeDependents), and in
		// turn what depends on those. (Without CASCADE such a statement
		// fails rather than drop them.)
		dep, err := oidsOf(ctx, c, cascadeDependents, rels)
		if err != nil {
			return st, err
		}
		rels = append(rels, dep...)
	}
	if refs.DDL {
		// Event triggers run on the DDL itself (ddl_command_start, ..., and
		// sql_drop, table_rewrite): their definitions and functions.
		d, err := defs(ctx, c, `SELECT 'event trigger', e.evtname,
				concat(e.evtevent, E'\x1f', e.evtenabled, E'\x1f', e.evttags::text, E'\x1f', e.evtfoid::regprocedure::text, E'\x1f', pg_catalog.pg_get_userbyid(e.evtowner))
			FROM pg_catalog.pg_event_trigger e WHERE $1::int[] IS NOT NULL`, []int{0})
		if err != nil {
			return st, err
		}
		st.Objects = append(st.Objects, d...)
		f, err := oidsOf(ctx, c, `SELECT e.evtfoid FROM pg_catalog.pg_event_trigger e WHERE $1::oid[] IS NOT NULL`, []uint32{})
		if err != nil {
			return st, err
		}
		funcs = append(funcs, f...)
	}

	err = follow(rels, funcs, maxObjectDepth, func(rels, funcs []uint32) (nextRels, nextFuncs []uint32, err error) {
		if len(rels) > 0 {
			d, err := relationDefs(ctx, c, rels)
			if err != nil {
				return nil, nil, err
			}
			st.Objects = append(st.Objects, d...)
			r, f, o, err := relationUses(ctx, c, rels, refs)
			if err != nil {
				return nil, nil, err
			}
			st.Objects = append(st.Objects, o...)
			nextRels, nextFuncs = append(nextRels, r...), append(nextFuncs, f...)
		}
		if len(funcs) > 0 {
			d, err := defs(ctx, c, `SELECT 'function', p.oid::regprocedure::text,
					concat(p.provolatile, E'\x1f', p.prosrc, E'\x1f', p.probin, E'\x1f', p.proconfig::text, E'\x1f', p.prosecdef, E'\x1f', p.proleakproof, E'\x1f', (SELECT l.lanname FROM pg_catalog.pg_language l WHERE l.oid = p.prolang), E'\x1f', pg_catalog.pg_get_function_result(p.oid), E'\x1f', pg_catalog.pg_get_function_arguments(p.oid), E'\x1f', p.proacl::text, E'\x1f', pg_catalog.pg_get_userbyid(p.proowner))
				FROM pg_catalog.pg_proc p WHERE p.oid = ANY($1::oid[])`, funcs)
			if err != nil {
				return nil, nil, err
			}
			st.Objects = append(st.Objects, d...)
			// A function body in BEGIN ATOMIC records what it uses.
			r, f, o, err := uses(ctx, c, `d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = ANY($1::oid[])`, funcs)
			if err != nil {
				return nil, nil, err
			}
			st.Objects = append(st.Objects, o...)
			nextRels, nextFuncs = append(nextRels, r...), append(nextFuncs, f...)
		}
		return nextRels, nextFuncs, nil
	})
	if err != nil {
		return st, err
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

// columnTypes selects the types the columns of the relations $1 are of
// (directly, through an array, a range or multirange, the attributes of a
// composite type, or a domain over another one), outside the server's own
// schemas; it ends with "t.typtype ", for a condition on it to follow. (rngmultitypid is read through to_jsonb: the column exists from
// PostgreSQL 14 on.)
const columnTypes = `WITH RECURSIVE ty(oid) AS (
		SELECT a.atttypid FROM pg_catalog.pg_attribute a WHERE a.attrelid = ANY($1::oid[]) AND a.attnum > 0 AND NOT a.attisdropped
		UNION SELECT v.t FROM ty JOIN pg_catalog.pg_type t ON t.oid = ty.oid
			LEFT JOIN pg_catalog.pg_range r ON r.rngtypid = t.oid OR (pg_catalog.to_jsonb(r) ->> 'rngmultitypid')::oid = t.oid
			LEFT JOIN pg_catalog.pg_attribute ca ON t.typrelid <> 0 AND ca.attrelid = t.typrelid AND ca.attnum > 0 AND NOT ca.attisdropped,
			LATERAL (VALUES (t.typbasetype), (t.typelem), (r.rngsubtype), (ca.atttypid)) v(t) WHERE v.t <> 0
	)
	SELECT t.oid FROM ty JOIN pg_catalog.pg_type t ON t.oid = ty.oid JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
	WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND t.typtype `

// columnDomains selects the domains the columns of the relations $1 are
// of (columnTypes).
const columnDomains = columnTypes + `= 'd'`

// cascadeDependents selects the relations a DDL statement with CASCADE on
// the relations $1 drops or changes along with them: pg_depend is walked
// in reverse, recursively, over every object that depends on them
// (normally, automatically or as an internal part: inheritance children
// and partitions, owned sequences, the row type, its array type and the
// domains over it, functions, ...; an object dropped with a column only
// when it depends on that column), with the object an internal part
// belongs to (the view of a _RETURN rule). Each object found maps to its
// relation: itself, the relation of a rule, policy, constraint, default or
// trigger, the table of a column. Objects of the server's own schemas are
// left out.
const cascadeDependents = `WITH RECURSIVE obj(classid, objid, objsubid) AS (
		SELECT 'pg_catalog.pg_class'::regclass::oid, x, 0 FROM unnest($1::oid[]) x
		UNION SELECT y.classid, y.objid, y.objsubid FROM obj
			JOIN pg_catalog.pg_depend d ON d.refclassid = obj.classid AND d.refobjid = obj.objid
				AND (obj.objsubid = 0 OR d.refobjsubid = obj.objsubid) AND d.deptype IN ('n', 'a', 'i'),
			LATERAL (SELECT d.classid, d.objid, d.objsubid
				UNION ALL SELECT o.refclassid, o.refobjid, 0 FROM pg_catalog.pg_depend o
					WHERE o.classid = d.classid AND o.objid = d.objid AND o.deptype = 'i') y(classid, objid, objsubid)
	)
	SELECT DISTINCT r.oid FROM obj,
		LATERAL (SELECT obj.objid WHERE obj.classid = 'pg_catalog.pg_class'::regclass
			UNION ALL SELECT w.ev_class FROM pg_catalog.pg_rewrite w WHERE obj.classid = 'pg_catalog.pg_rewrite'::regclass AND w.oid = obj.objid
			UNION ALL SELECT p.polrelid FROM pg_catalog.pg_policy p WHERE obj.classid = 'pg_catalog.pg_policy'::regclass AND p.oid = obj.objid
			UNION ALL SELECT k.conrelid FROM pg_catalog.pg_constraint k WHERE obj.classid = 'pg_catalog.pg_constraint'::regclass AND k.oid = obj.objid AND k.conrelid <> 0
			UNION ALL SELECT a.adrelid FROM pg_catalog.pg_attrdef a WHERE obj.classid = 'pg_catalog.pg_attrdef'::regclass AND a.oid = obj.objid
			UNION ALL SELECT g.tgrelid FROM pg_catalog.pg_trigger g WHERE obj.classid = 'pg_catalog.pg_trigger'::regclass AND g.oid = obj.objid) r(oid)
		JOIN pg_catalog.pg_class c ON c.oid = r.oid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
	WHERE NOT r.oid = ANY($1::oid[]) AND ` + "n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%'"

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
		// The domains of their columns: base type, NOT NULL, default and
		// CHECK constraints (ALTER DOMAIN changes them in place).
		`SELECT 'domain', t.oid::regtype::text,
			concat(pg_catalog.format_type(t.typbasetype, t.typtypmod), E'\x1f', t.typnotnull, E'\x1f', t.typdefault, E'\x1f', t.typcollation, E'\x1f',
				(SELECT string_agg(concat(c.conname, ' ', c.convalidated, ' ', pg_catalog.pg_get_constraintdef(c.oid)), ', ' ORDER BY c.conname) FROM pg_catalog.pg_constraint c WHERE c.contypid = t.oid))
		FROM pg_catalog.pg_type t WHERE t.oid IN (` + columnDomains + `)`,
		// Their enum and composite types: an enum's labels in their sort
		// order (ALTER TYPE ... ADD/RENAME VALUE changes comparisons), a
		// composite's attributes (ALTER TYPE ... ADD/ALTER/DROP ATTRIBUTE).
		`SELECT 'type', t.oid::regtype::text,
			concat(t.typtype, E'\x1f', CASE t.typtype
				WHEN 'e' THEN (SELECT string_agg(e.enumlabel, E'\x1f' ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e WHERE e.enumtypid = t.oid)
				ELSE (SELECT string_agg(concat(a.attname, ' ', pg_catalog.format_type(a.atttypid, a.atttypmod), ' ', a.attcollation), ', ' ORDER BY a.attnum)
					FROM pg_catalog.pg_attribute a WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped) END)
		FROM pg_catalog.pg_type t WHERE t.oid IN (` + columnTypes + `IN ('e', 'c'))`,
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
// foreign keys reference them with an action that changes their rows (for
// DDL, every referencing table). A PL/pgSQL body records nothing in
// pg_depend: the functions it calls are not followed (only its own source
// is hashed), nor are the objects dynamic SQL reaches.
func relationUses(ctx context.Context, c *pgx.Conn, rels []uint32, refs engine.ObjectRefs) (relOut, funcOut []uint32, ops []engine.ObjectDef, err error) {
	r, f, ops, err := uses(ctx, c, `(d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_rewrite WHERE ev_class = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_policy'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_policy WHERE polrelid = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_trigger'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_trigger WHERE tgrelid = ANY($1::oid[]) AND NOT tgisinternal))
		OR (d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = ANY($1::oid[]))
		OR (d.classid = 'pg_catalog.pg_attrdef'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_attrdef WHERE adrelid = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_constraint'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_constraint WHERE conrelid = ANY($1::oid[])))
		OR (d.classid = 'pg_catalog.pg_constraint'::regclass AND d.objid IN (SELECT oid FROM pg_catalog.pg_constraint WHERE contypid IN (`+columnDomains+`)))
		OR (d.classid = 'pg_catalog.pg_type'::regclass AND d.objid IN (`+columnDomains+`))`, rels)
	if err != nil {
		return nil, nil, nil, err
	}
	// The tables a statement on rels reaches too: their partitions and
	// inheritance children and parents, and the tables whose foreign keys
	// reference them with an action that changes their rows (CASCADE, SET
	// NULL, SET DEFAULT: a cascade runs their triggers). A NO ACTION or
	// RESTRICT key only refuses the write: the referencing table is not
	// followed (the key itself is hashed with the relation's constraints),
	// so an unrelated change in a wide graph of such keys does not make
	// the plan stale.
	q := `SELECT i.inhrelid FROM pg_catalog.pg_inherits i WHERE i.inhparent = ANY($1::oid[])
		UNION SELECT i.inhparent FROM pg_catalog.pg_inherits i WHERE i.inhrelid = ANY($1::oid[])`
	switch {
	case refs.DDL:
		// TRUNCATE ... CASCADE empties every referencing table whatever
		// the key's action (and runs its ON TRUNCATE triggers): all of
		// them, and the keys onto them.
		q += ` UNION SELECT c.conrelid FROM pg_catalog.pg_constraint c WHERE c.contype = 'f' AND c.confrelid = ANY($1::oid[])`
	case refs.Writes:
		q += ` UNION SELECT c.conrelid FROM pg_catalog.pg_constraint c WHERE c.contype = 'f' AND c.confrelid = ANY($1::oid[])
			AND (c.confdeltype NOT IN ('a', 'r') OR c.confupdtype NOT IN ('a', 'r'))`
	}
	more, err := oidsOf(ctx, c, q, rels)
	return append(r, more...), f, ops, err
}

func oidsOf(ctx context.Context, c *pgx.Conn, q string, arg []uint32) ([]uint32, error) {
	rows, err := c.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uint32])
}

// uses are the relations, functions and operators outside the server's
// own schemas that the pg_depend rows matching cond (on alias d) refer to.
// An operator a view, rule, policy, default or CHECK uses is recorded
// against pg_operator, not its function: its definition is hashed and its
// function (oprcode) followed, with its commutator's and negator's (the
// planner may run them instead: operatorClosure).
func uses(ctx context.Context, c *pgx.Conn, cond string, arg []uint32) (rels, funcs []uint32, ops []engine.ObjectDef, err error) {
	used := operatorClosure(`SELECT d.refobjid FROM pg_catalog.pg_depend d WHERE (` + cond + `) AND d.refclassid = 'pg_catalog.pg_operator'::regclass`)
	rows, err := c.Query(ctx, `SELECT DISTINCT d.refclassid = 'pg_catalog.pg_class'::regclass, d.refobjid
		FROM pg_catalog.pg_depend d
		LEFT JOIN pg_catalog.pg_class rc ON d.refclassid = 'pg_catalog.pg_class'::regclass AND rc.oid = d.refobjid
		LEFT JOIN pg_catalog.pg_proc rp ON d.refclassid = 'pg_catalog.pg_proc'::regclass AND rp.oid = d.refobjid
		JOIN pg_catalog.pg_namespace n ON n.oid = coalesce(rc.relnamespace, rp.pronamespace)
		WHERE (`+cond+`) AND d.refclassid IN ('pg_catalog.pg_class'::regclass, 'pg_catalog.pg_proc'::regclass)
		  AND `+userObject("n")+`
		UNION SELECT false, ro.oprcode::oid
		FROM pg_catalog.pg_operator ro JOIN pg_catalog.pg_namespace n ON n.oid = ro.oprnamespace
		WHERE ro.oid IN `+used+` AND ro.oprcode <> 0 AND `+userObject("n"), arg)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rel bool
		var oid uint32
		if err := rows.Scan(&rel, &oid); err != nil {
			return nil, nil, nil, err
		}
		if rel {
			rels = append(rels, oid)
		} else {
			funcs = append(funcs, oid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	ops, err = defs(ctx, c, operatorDef+`
		WHERE o.oid IN `+used+` AND `+userObject("n"), arg)
	return rels, funcs, ops, err
}

// operatorClosure is the subquery of the operators base selects with,
// recursively, their commutators and negators: the planner rewrites
// NOT (a === b) into a !== b and b === a into a === b with the other
// operand order, and then runs that operator's function.
func operatorClosure(base string) string {
	return `(WITH RECURSIVE op(oid) AS (` + base + `
		UNION SELECT x.oid FROM op JOIN pg_catalog.pg_operator o ON o.oid = op.oid,
			LATERAL (VALUES (o.oprcom), (o.oprnegate)) x(oid) WHERE x.oid <> 0)
	SELECT oid FROM op)`
}

// operatorDef selects the definition of the operators o (namespace n).
const operatorDef = `SELECT 'operator', o.oid::regoperator::text,
		concat(o.oprcode::regprocedure::text, E'\x1f', o.oprkind, E'\x1f', o.oprcom::regoperator::text, E'\x1f', o.oprnegate::regoperator::text)
	FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace`

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

// errTooDeep is the error of objects nested deeper than the bound.
var errTooDeep = fmt.Errorf("postgres: the objects the statement uses nest deeper than %d levels (views, rules, triggers, policies, defaults, constraints, domains): it cannot be bound to a plan hash", maxObjectDepth)

// follow walks from rels and funcs, at most depth levels: step reads the
// relations and functions of one level not seen yet and returns those
// they use. Objects still to follow past the bound would go unhashed: it
// fails closed (errTooDeep) rather than approve what was not read.
func follow(rels, funcs []uint32, depth int, step func(rels, funcs []uint32) ([]uint32, []uint32, error)) error {
	seenRel, seenFunc := map[uint32]bool{}, map[uint32]bool{}
	for d := 0; d < depth; d++ {
		rels, funcs = fresh(rels, seenRel), fresh(funcs, seenFunc)
		if len(rels) == 0 && len(funcs) == 0 {
			return nil
		}
		var err error
		if rels, funcs, err = step(rels, funcs); err != nil {
			return err
		}
	}
	if unseen(rels, seenRel) || unseen(funcs, seenFunc) {
		return errTooDeep
	}
	return nil
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
