package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// userSchemas filters out the system schemas (pg_catalog, pg_toast, the
// temporary schemas, information_schema) of a query aliasing pg_namespace
// as n.
const userSchemas = `n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'`

// relKinds are the relations the catalog lists: tables, partitioned tables,
// views, materialized views and foreign tables.
const relKinds = `c.relkind IN ('r', 'p', 'v', 'm', 'f')`

type originKey struct {
	table  uint32
	attnum uint16
}

// origin is a resolved column.
type origin struct {
	schema, table, column string
}

// originRel maps the relation p a result column comes from to the relation
// c its origin names, and originKinds keeps only trusted origins:
//
//   - A partition (relispartition, at any level) maps to the root of its
//     partition tree (pg_partition_root): the PII scan proposes rules on the
//     root only, and a partition has the same column names as its root
//     (attribute numbers may differ, so the partition's attname is used).
//   - Tables and partitioned tables keep their own origin, unless they take
//     part in classic inheritance (INHERITS): a parent's rows include its
//     children's, and a child is a separate table a rule on the parent does
//     not name, so their columns get no origin.
//   - A view, a materialized view or a foreign table reports itself, not the
//     relation behind it, and may rename a PII column (a foreign table's
//     column_name option), so its columns get no origin.
//
// Columns without an origin are masked by name and checked by
// pii.AliasViolation. Derived tables and CTEs resolve to the base table.
const originRel = `JOIN pg_catalog.pg_class p ON p.oid = a.attrelid
		JOIN pg_catalog.pg_class c ON c.oid = CASE WHEN p.relispartition
			THEN pg_catalog.pg_partition_root(p.oid) ELSE p.oid END`

const originKinds = `c.relkind IN ('r', 'p') AND (p.relispartition OR p.relkind = 'p' OR p.relkind = 'r'
		AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid = p.oid OR i.inhparent = p.oid))`

// resolveOrigins fills in the origin of each result column from the table
// OID and attribute number the server reported, with one catalog query per
// statement, in the statement's own transaction. Nothing is cached: a
// column renamed by another session must not keep its old name. Called
// with mu held.
func (s *session) resolveOrigins(ctx context.Context, dc *dbConn, cols []engine.ResultColumn, keys []originKey) error {
	var rels, atts []int64
	seen := map[originKey]bool{}
	for i, k := range keys {
		if k.table == 0 || k.attnum == 0 || i >= len(cols) || seen[k] {
			continue
		}
		seen[k] = true
		rels, atts = append(rels, int64(k.table)), append(atts, int64(k.attnum))
	}
	if len(rels) == 0 {
		return nil
	}
	rows, err := dc.conn.Query(ctx, `
		SELECT a.attrelid::int8, a.attnum::int8, n.nspname, c.relname, a.attname
		FROM ROWS FROM (pg_catalog.unnest($1::int8[]), pg_catalog.unnest($2::int8[])) AS k(rel, att)
		JOIN pg_catalog.pg_attribute a ON a.attrelid = k.rel::oid AND a.attnum = k.att::int2
		`+originRel+`
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE NOT a.attisdropped AND `+originKinds, rels, atts)
	if err != nil {
		return err
	}
	found := map[originKey]origin{}
	var rel, att int64
	var o origin
	_, err = pgx.ForEachRow(rows, []any{&rel, &att, &o.schema, &o.table, &o.column}, func() error {
		found[originKey{uint32(rel), uint16(att)}] = o
		return nil
	})
	if err != nil {
		return err
	}
	for i, k := range keys {
		if i >= len(cols) {
			break
		}
		if o, ok := found[k]; ok {
			cols[i].OriginDB, cols[i].OriginTable, cols[i].OriginColumn = o.schema, o.table, o.column
		}
	}
	return nil
}

// catalog runs fn on the connection to db under the statement timeout, in
// a read-only transaction that is rolled back. Catalog SQL is built by the
// engine; values only travel as parameters.
func (s *session) catalog(ctx context.Context, db string, fn func(ctx context.Context, c *pgx.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, err := s.conn(ctx, db)
	if err != nil {
		return err
	}
	_, err = s.inTx(ctx, dc, "BEGIN READ ONLY", false, func(ctx context.Context) (engine.Result, error) {
		return engine.Result{}, local(ctx, dc, fn(ctx, dc.conn))
	})
	return err
}

// Databases lists the databases one can connect to, templates excluded.
func (s *session) Databases(ctx context.Context) ([]string, error) {
	var out []string
	err := s.catalog(ctx, "", func(ctx context.Context, c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT datname FROM pg_catalog.pg_database
			WHERE NOT datistemplate AND datallowconn ORDER BY datname`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return out, err
}

// tableName is how Tables names a relation: bare in schema public,
// schema-qualified elsewhere.
func tableName(schema, table string) string {
	if schema == "public" {
		return table
	}
	return schema + "." + table
}

// Tables lists the tables, views, materialized views and foreign tables of
// database db, outside the system schemas (partitions are left out: their
// parent is listed).
func (s *session) Tables(ctx context.Context, db string) ([]string, error) {
	var out []string
	err := s.catalog(ctx, db, func(ctx context.Context, c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT n.nspname, c.relname
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE `+relKinds+` AND NOT c.relispartition AND `+userSchemas+`
			ORDER BY n.nspname <> 'public', n.nspname, c.relname`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
			var schema, table string
			err := r.Scan(&schema, &table)
			return tableName(schema, table), err
		})
		return err
	})
	if out == nil && err == nil {
		out = []string{}
	}
	return out, err
}

var errNoTable = errors.New("no such table")

// findTable resolves a table name as Tables spells it: "schema.table", or
// "table" looked up through the search path. Returns the table OID.
func findTable(ctx context.Context, c *pgx.Conn, name string) (oid uint32, info engine.TableInfo, err error) {
	try := func(schema, table string) error {
		var kind string
		var tuples float64
		err := c.QueryRow(ctx, `SELECT c.oid, n.nspname, c.relname, c.relkind::text, c.reltuples::float8
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relname = $2::text AND `+relKinds+`
			  AND (($1::text = '' AND n.nspname = ANY (pg_catalog.current_schemas(false))) OR n.nspname = $1::text)
			ORDER BY pg_catalog.array_position(pg_catalog.current_schemas(false), n.nspname) NULLS LAST
			LIMIT 1`, schema, table).Scan(&oid, &info.DB, &info.Table, &kind, &tuples)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoTable
		}
		if err != nil {
			return err
		}
		info.EstRows = -1
		if kind != "v" && tuples >= 0 {
			info.EstRows = int64(tuples)
		}
		return nil
	}
	err = try("", name)
	if errors.Is(err, errNoTable) {
		if schema, table, ok := strings.Cut(name, "."); ok {
			err = try(schema, table)
		}
	}
	return oid, info, err
}

// Describe returns the columns, indexes and row estimate of a table. The
// TableInfo's DB is the table's schema.
func (s *session) Describe(ctx context.Context, db, table string) (engine.TableInfo, error) {
	var info engine.TableInfo
	err := s.catalog(ctx, db, func(ctx context.Context, c *pgx.Conn) error {
		oid, ti, err := findTable(ctx, c, table)
		if err != nil {
			return err
		}
		info = ti
		rows, err := c.Query(ctx, `SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
				pg_catalog.pg_get_expr(d.adbin, d.adrelid),
				EXISTS (SELECT 1 FROM pg_catalog.pg_index i
				        WHERE i.indrelid = a.attrelid AND i.indisprimary AND a.attnum = ANY (i.indkey))
			FROM pg_catalog.pg_attribute a
			LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped
			ORDER BY a.attnum`, int64(oid))
		if err != nil {
			return err
		}
		info.Columns, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (engine.ColumnDesc, error) {
			var cd engine.ColumnDesc
			err := r.Scan(&cd.Name, &cd.Type, &cd.Nullable, &cd.Default, &cd.PrimaryKey)
			return cd, err
		})
		if err != nil {
			return err
		}
		rows, err = c.Query(ctx, `SELECT ic.relname, i.indisunique, i.indisprimary,
				ARRAY(SELECT pg_catalog.pg_get_indexdef(i.indexrelid, k, true)
				      FROM pg_catalog.generate_series(1, i.indnkeyatts) AS k ORDER BY k)
			FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
			WHERE i.indrelid = $1::oid
			ORDER BY i.indisprimary DESC, ic.relname`, int64(oid))
		if err != nil {
			return err
		}
		info.Indexes, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (engine.IndexDesc, error) {
			var id engine.IndexDesc
			err := r.Scan(&id.Name, &id.Unique, &id.Primary, &id.Columns)
			return id, err
		})
		return err
	})
	if errors.Is(err, errNoTable) {
		return engine.TableInfo{}, fmt.Errorf("postgres: table %q not found", table)
	}
	return info, err
}

// Columns lists every column of the user tables and views of database db,
// for PII detection. ColumnInfo.DB is the schema.
func (s *session) Columns(ctx context.Context, db string) ([]engine.ColumnInfo, error) {
	var out []engine.ColumnInfo
	err := s.catalog(ctx, db, func(ctx context.Context, c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)
			FROM pg_catalog.pg_attribute a
			JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE `+relKinds+` AND NOT c.relispartition AND `+userSchemas+`
			  AND a.attnum > 0 AND NOT a.attisdropped
			ORDER BY n.nspname, c.relname, a.attnum`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (engine.ColumnInfo, error) {
			var ci engine.ColumnInfo
			err := r.Scan(&ci.DB, &ci.Table, &ci.Column, &ci.Type)
			return ci, err
		})
		return err
	})
	if out == nil && err == nil {
		out = []engine.ColumnInfo{}
	}
	return out, err
}

// tierAllows lists what each tier may hold beyond SELECT. Admin allows
// everything.
var tierAllows = map[config.Tier]map[string]bool{
	config.TierRead:  {},
	config.TierWrite: {"INSERT": true, "UPDATE": true, "DELETE": true, "pg_write_all_data": true},
	config.TierDDL: {"INSERT": true, "UPDATE": true, "DELETE": true, "pg_write_all_data": true,
		"TRUNCATE": true, "REFERENCES": true, "TRIGGER": true, "MAINTAIN": true,
		"CREATE": true, "OWNER": true, "CREATEDB": true},
}

// predefinedRoles are the built-in roles that grant more than reading.
const predefinedRoles = `'pg_write_all_data', 'pg_read_server_files', 'pg_write_server_files',
	'pg_execute_server_program', 'pg_signal_backend', 'pg_checkpoint', 'pg_create_subscription'`

// ExtraPrivileges reports what the connected role can do beyond the tier,
// in the profile's database: role attributes (SUPERUSER, CREATEROLE,
// CREATEDB, REPLICATION, BYPASSRLS), membership of powerful predefined
// roles, table privileges on any user table or view (INSERT, UPDATE,
// DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN), ownership of a user
// table or schema (OWNER), and CREATE on a schema or the database.
func (s *session) ExtraPrivileges(ctx context.Context, tier config.Tier) ([]string, error) {
	if tier >= config.TierAdmin {
		return nil, nil
	}
	allowed := tierAllows[tier]
	var found []string
	err := s.catalog(ctx, "", func(ctx context.Context, c *pgx.Conn) error {
		var super, createRole, createDB, repl, bypass bool
		if err := c.QueryRow(ctx, `SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
			FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&super, &createRole, &createDB, &repl, &bypass); err != nil {
			return err
		}
		for _, a := range []struct {
			on   bool
			name string
		}{{super, "SUPERUSER"}, {createRole, "CREATEROLE"}, {createDB, "CREATEDB"}, {repl, "REPLICATION"}, {bypass, "BYPASSRLS"}} {
			if a.on {
				found = append(found, a.name)
			}
		}
		if super { // a superuser bypasses every check below
			return nil
		}
		rows, err := c.Query(ctx, `SELECT r.rolname FROM pg_catalog.pg_roles r
			WHERE r.rolname IN (`+predefinedRoles+`) AND pg_catalog.pg_has_role(current_user, r.oid, 'USAGE')
			ORDER BY r.rolname`)
		if err != nil {
			return err
		}
		roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		found = append(found, roles...)

		privs := `('INSERT', 1), ('UPDATE', 2), ('DELETE', 3), ('TRUNCATE', 4), ('REFERENCES', 5), ('TRIGGER', 6)`
		if s.major >= 17 {
			privs += `, ('MAINTAIN', 7)`
		}
		rows, err = c.Query(ctx, `SELECT p.priv FROM (VALUES `+privs+`) AS p(priv, ord)
			WHERE EXISTS (
			  SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			  WHERE `+relKinds+` AND `+userSchemas+`
			    AND CASE WHEN p.priv IN ('INSERT', 'UPDATE', 'REFERENCES')
			             THEN pg_catalog.has_any_column_privilege(c.oid, p.priv)
			             ELSE pg_catalog.has_table_privilege(c.oid, p.priv) END)
			ORDER BY p.ord`)
		if err != nil {
			return err
		}
		tablePrivs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		found = append(found, tablePrivs...)

		var owner, create bool
		if err := c.QueryRow(ctx, `SELECT
			  EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			          WHERE `+relKinds+` AND `+userSchemas+` AND pg_catalog.pg_has_role(c.relowner, 'USAGE'))
			  OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
			             WHERE `+userSchemas+` AND pg_catalog.pg_has_role(n.nspowner, 'USAGE')),
			  EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
			          WHERE `+userSchemas+` AND pg_catalog.has_schema_privilege(n.oid, 'CREATE'))
			  OR pg_catalog.has_database_privilege(current_database(), 'CREATE')`).Scan(&owner, &create); err != nil {
			return err
		}
		if owner {
			found = append(found, "OWNER")
		}
		if create {
			found = append(found, "CREATE")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, f := range found {
		if !allowed[f] {
			out = append(out, f)
		}
	}
	return out, nil
}
