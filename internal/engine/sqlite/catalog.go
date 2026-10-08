package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// Catalog queries are built here only; names reach them as bound
// parameters or as double-quoted identifiers of a schema checked against
// PRAGMA database_list.

// userObjects filters sqlite_schema down to user tables and views.
func userObjects(alias string) string {
	return alias + `type IN ('table', 'view') AND ` + alias + `name NOT LIKE 'sqlite\_%' ESCAPE '\'`
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Databases lists the schemas: "main" plus the attached ones ("temp" is left
// out).
func (s *session) Databases(ctx context.Context) ([]string, error) {
	return s.strings(ctx, `SELECT name FROM pragma_database_list WHERE name <> 'temp' ORDER BY seq`)
}

// checkDB accepts "" (the main schema) or a schema of this connection.
func (s *session) checkDB(ctx context.Context, db string) error {
	if db == "" {
		return nil
	}
	dbs, err := s.Databases(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(dbs, db) {
		return fmt.Errorf("sqlite: unknown database %q", db)
	}
	return nil
}

func orMain(db string) string {
	if db == "" {
		return "main"
	}
	return db
}

func (s *session) Tables(ctx context.Context, db string) ([]string, error) {
	if err := s.checkDB(ctx, db); err != nil {
		return nil, err
	}
	return s.strings(ctx, `SELECT name FROM `+quoteIdent(orMain(db))+`.sqlite_schema WHERE `+userObjects("")+` ORDER BY name`)
}

func (s *session) Describe(ctx context.Context, db, table string) (engine.TableInfo, error) {
	if err := s.checkDB(ctx, db); err != nil {
		return engine.TableInfo{}, err
	}
	db = orMain(db)
	var name string
	err := s.conn.QueryRowContext(ctx,
		`SELECT name FROM `+quoteIdent(db)+`.sqlite_schema WHERE `+userObjects("")+` AND name = ? COLLATE NOCASE`, table).Scan(&name)
	if err == sql.ErrNoRows {
		return engine.TableInfo{}, fmt.Errorf("sqlite: unknown table %s.%s", db, table)
	}
	if err != nil {
		return engine.TableInfo{}, wrap(ctx, err)
	}
	info := engine.TableInfo{DB: db, Table: name, EstRows: -1}

	rows, err := s.conn.QueryContext(ctx,
		`SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?, ?) ORDER BY cid`, name, db)
	if err != nil {
		return engine.TableInfo{}, wrap(ctx, err)
	}
	for rows.Next() {
		var c engine.ColumnDesc
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&c.Name, &c.Type, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return engine.TableInfo{}, wrap(ctx, err)
		}
		c.Nullable = notNull == 0 && pk == 0
		c.PrimaryKey = pk > 0
		if dflt.Valid {
			c.Default = &dflt.String
		}
		info.Columns = append(info.Columns, c)
	}
	if err := closeRows(rows); err != nil {
		return engine.TableInfo{}, wrap(ctx, err)
	}

	type idx struct {
		name           string
		unique, origin string
	}
	var idxs []idx
	rows, err = s.conn.QueryContext(ctx, `SELECT name, "unique", origin FROM pragma_index_list(?, ?) ORDER BY name`, name, db)
	if err != nil {
		return engine.TableInfo{}, wrap(ctx, err)
	}
	for rows.Next() {
		var i idx
		if err := rows.Scan(&i.name, &i.unique, &i.origin); err != nil {
			rows.Close()
			return engine.TableInfo{}, wrap(ctx, err)
		}
		idxs = append(idxs, i)
	}
	if err := closeRows(rows); err != nil {
		return engine.TableInfo{}, wrap(ctx, err)
	}
	for _, i := range idxs {
		rows, err := s.conn.QueryContext(ctx, `SELECT coalesce(name, '<expression>') FROM pragma_index_info(?, ?) ORDER BY seqno`, i.name, db)
		if err != nil {
			return engine.TableInfo{}, wrap(ctx, err)
		}
		cols, err := scanStrings(rows)
		if err != nil {
			return engine.TableInfo{}, wrap(ctx, err)
		}
		info.Indexes = append(info.Indexes, engine.IndexDesc{
			Name: i.name, Columns: cols, Unique: i.unique == "1", Primary: i.origin == "pk",
		})
	}

	st, err := s.loadStats(ctx, []string{db})
	if err != nil {
		return engine.TableInfo{}, err
	}
	if n, ok := st.tables[strings.ToLower(name)]; ok {
		info.EstRows = n
	}
	return info, nil
}

func (s *session) Columns(ctx context.Context, db string) ([]engine.ColumnInfo, error) {
	if err := s.checkDB(ctx, db); err != nil {
		return nil, err
	}
	db = orMain(db)
	rows, err := s.conn.QueryContext(ctx,
		`SELECT m.name, p.name, p.type, m.type = 'view' FROM `+quoteIdent(db)+`.sqlite_schema AS m, pragma_table_info(m.name, ?) AS p
		 WHERE `+userObjects("m.")+` ORDER BY m.name, p.cid`, db)
	if err != nil {
		return nil, wrap(ctx, err)
	}
	var out []engine.ColumnInfo
	for rows.Next() {
		c := engine.ColumnInfo{DB: db}
		if err := rows.Scan(&c.Table, &c.Column, &c.Type, &c.View); err != nil {
			rows.Close()
			return nil, wrap(ctx, err)
		}
		out = append(out, c)
	}
	if err := closeRows(rows); err != nil {
		return nil, wrap(ctx, err)
	}
	return out, nil
}

// stats holds sqlite_stat1: the row count per table and the per-index
// "rows per distinct prefix" figures, keyed by lower-cased name.
type stats struct {
	tables  map[string]int64
	indexes map[string][]int64
}

// loadStats reads sqlite_stat1 from the given schemas, where it exists.
// The first schema wins on a name clash.
func (s *session) loadStats(ctx context.Context, schemas []string) (stats, error) {
	st := stats{tables: map[string]int64{}, indexes: map[string][]int64{}}
	for _, db := range schemas {
		q := quoteIdent(db)
		var n int
		if err := s.conn.QueryRowContext(ctx,
			`SELECT count(*) FROM `+q+`.sqlite_schema WHERE type = 'table' AND name = 'sqlite_stat1'`).Scan(&n); err != nil {
			return st, wrap(ctx, err)
		}
		if n == 0 {
			continue
		}
		rows, err := s.conn.QueryContext(ctx, `SELECT tbl, idx, stat FROM `+q+`.sqlite_stat1`)
		if err != nil {
			return st, wrap(ctx, err)
		}
		for rows.Next() {
			var tbl string
			var idx, stat sql.NullString
			if err := rows.Scan(&tbl, &idx, &stat); err != nil {
				rows.Close()
				return st, wrap(ctx, err)
			}
			nums := statNumbers(stat.String)
			if len(nums) == 0 {
				continue
			}
			tbl = strings.ToLower(tbl)
			if _, seen := st.tables[tbl]; !seen {
				st.tables[tbl] = nums[0]
			}
			if idx.Valid {
				if k := strings.ToLower(idx.String); st.indexes[k] == nil {
					st.indexes[k] = nums
				}
			}
		}
		if err := closeRows(rows); err != nil {
			return st, wrap(ctx, err)
		}
	}
	return st, nil
}

// statNumbers parses the leading integers of a sqlite_stat1 stat value
// ("N a b ... [unordered] [sz=..]").
func statNumbers(stat string) []int64 {
	var out []int64
	for _, f := range strings.Fields(stat) {
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// objectNames returns the lower-cased names of the tables and views of the
// given schemas.
func (s *session) objectNames(ctx context.Context, schemas []string) (map[string]string, error) {
	out := map[string]string{}
	for _, db := range schemas {
		names, err := s.strings(ctx, `SELECT name FROM `+quoteIdent(db)+`.sqlite_schema WHERE type IN ('table', 'view')`)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if _, seen := out[strings.ToLower(n)]; !seen {
				out[strings.ToLower(n)] = n
			}
		}
	}
	return out, nil
}

func (s *session) strings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap(ctx, err)
	}
	out, err := scanStrings(rows)
	if err != nil {
		return nil, wrap(ctx, err)
	}
	return out, nil
}

func scanStrings(rows *sql.Rows) ([]string, error) {
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	return out, closeRows(rows)
}

func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}
