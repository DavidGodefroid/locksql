package mysql

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// Catalog queries are built here only. Names reach them as prepared
// statement parameters, never spliced into the SQL.

var systemSchemas = []string{"information_schema", "performance_schema", "mysql", "sys"}

// query runs a console-built catalog query, with parameters, in a READ ONLY
// transaction. Rows are not capped.
func (s *session) query(ctx context.Context, q string, args ...any) ([][]any, error) {
	res, err := s.inTx(ctx, "", readOnlyTx, func() (engine.Result, error) {
		if len(args) == 0 {
			return s.stream(q, 0)
		}
		r, err := s.conn.Execute(q, args...)
		if err != nil {
			return engine.Result{}, err
		}
		defer r.Close()
		out := engine.Result{Rows: make([][]any, 0, len(r.Values))}
		for _, row := range r.Values {
			vals := make([]any, len(row))
			for i := range row {
				vals[i] = value(row[i], r.Fields[i])
			}
			out.Rows = append(out.Rows, vals)
		}
		return out, nil
	}, false)
	return res.Rows, err
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

func num(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case uint64:
		return int64(min(x, 1<<63-1))
	case float64:
		return int64(x)
	}
	n, err := strconv.ParseInt(str(v), 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func (s *session) orDefault(db string) (string, error) {
	if db != "" {
		return db, nil
	}
	if s.defDB == "" {
		return "", errors.New("mysql: no database given and the profile has none")
	}
	return s.defDB, nil
}

// Databases lists the visible databases without the system schemas.
func (s *session) Databases(ctx context.Context) ([]string, error) {
	rows, err := s.query(ctx, "SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range rows {
		if name := str(r[0]); !slices.Contains(systemSchemas, strings.ToLower(name)) {
			out = append(out, name)
		}
	}
	return out, nil
}

// Tables lists the tables and views of db ("" is the profile's database).
func (s *session) Tables(ctx context.Context, db string) ([]string, error) {
	db, err := s.orDefault(db)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx,
		"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME", db)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, str(r[0]))
	}
	return out, nil
}

// Describe returns the columns, indexes and row estimate of one table or
// view. EstRows comes from information_schema.TABLES.TABLE_ROWS, an InnoDB
// estimate; -1 for views.
func (s *session) Describe(ctx context.Context, db, table string) (engine.TableInfo, error) {
	db, err := s.orDefault(db)
	if err != nil {
		return engine.TableInfo{}, err
	}
	rows, err := s.query(ctx,
		"SELECT TABLE_NAME, TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?", db, table)
	if err != nil {
		return engine.TableInfo{}, err
	}
	if len(rows) == 0 {
		return engine.TableInfo{}, fmt.Errorf("mysql: unknown table %s.%s", db, table)
	}
	info := engine.TableInfo{DB: db, Table: str(rows[0][0]), EstRows: -1}
	if rows[0][1] != nil {
		info.EstRows = num(rows[0][1])
	}

	rows, err = s.query(ctx, `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT
		FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, db, info.Table)
	if err != nil {
		return engine.TableInfo{}, err
	}
	for _, r := range rows {
		c := engine.ColumnDesc{
			Name: str(r[0]), Type: str(r[1]),
			Nullable: strings.EqualFold(str(r[2]), "YES"), PrimaryKey: str(r[3]) == "PRI",
		}
		// MariaDB spells "no default" as the literal NULL.
		if d := r[4]; d != nil && !(s.flavor == engine.FlavorMariaDB && str(d) == "NULL") {
			def := str(d)
			c.Default = &def
		}
		info.Columns = append(info.Columns, c)
	}

	rows, err = s.query(ctx, `SELECT INDEX_NAME, COLUMN_NAME, NON_UNIQUE
		FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
		ORDER BY INDEX_NAME <> 'PRIMARY', INDEX_NAME, SEQ_IN_INDEX`, db, info.Table)
	if err != nil {
		return engine.TableInfo{}, err
	}
	for _, r := range rows {
		name, col := str(r[0]), str(r[1])
		if r[1] == nil {
			col = "(expression)"
		}
		if n := len(info.Indexes); n > 0 && info.Indexes[n-1].Name == name {
			info.Indexes[n-1].Columns = append(info.Indexes[n-1].Columns, col)
			continue
		}
		info.Indexes = append(info.Indexes, engine.IndexDesc{
			Name: name, Columns: []string{col}, Unique: num(r[2]) == 0, Primary: name == "PRIMARY",
		})
	}
	return info, nil
}

// Columns lists every column of db, for PII detection.
func (s *session) Columns(ctx context.Context, db string) ([]engine.ColumnInfo, error) {
	db, err := s.orDefault(db)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, `SELECT c.TABLE_NAME, c.COLUMN_NAME, c.COLUMN_TYPE, t.TABLE_TYPE
		FROM information_schema.COLUMNS c
		JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
		WHERE c.TABLE_SCHEMA = ? ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION`, db)
	if err != nil {
		return nil, err
	}
	out := make([]engine.ColumnInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, engine.ColumnInfo{DB: db, Table: str(r[0]), Column: str(r[1]), Type: str(r[2]), View: str(r[3]) == "VIEW"})
	}
	return out, nil
}

// ExtraPrivileges reads SHOW GRANTS FOR CURRENT_USER() and lists what goes
// beyond the tier, plus a warning when the server is not the flavour the
// profile names.
func (s *session) ExtraPrivileges(ctx context.Context, tier config.Tier) ([]string, error) {
	rows, err := s.query(ctx, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		lines = append(lines, str(r[0]))
	}
	extras := parseGrants(lines, tier)
	if string(s.flavor) != s.engine {
		extras = append(extras, fmt.Sprintf("profile engine is %s but the server is %s", s.engine, s.flavor))
	}
	return extras, nil
}

var (
	tierPrivileges = map[config.Tier][]string{
		config.TierRead:  {"USAGE", "SELECT", "SHOW VIEW", "SHOW DATABASES"},
		config.TierWrite: {"INSERT", "UPDATE", "DELETE"},
		config.TierDDL:   {"CREATE", "ALTER", "DROP", "INDEX", "REFERENCES"},
	}
	grantRe   = regexp.MustCompile(`(?is)^GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+`)
	columnsRe = regexp.MustCompile(`\([^)]*\)`)
	spacesRe  = regexp.MustCompile(`\s+`)
)

// allowed reports whether priv is within tier: each tier adds to the one
// below it, and admin allows everything.
func allowed(priv string, tier config.Tier) bool {
	if tier >= config.TierAdmin {
		return true
	}
	for t := config.TierRead; t <= tier; t++ {
		if slices.Contains(tierPrivileges[t], priv) {
			return true
		}
	}
	return false
}

// parseGrants lists the privileges, roles, proxies and grant options of
// SHOW GRANTS lines that exceed tier. Its output never carries the
// IDENTIFIED BY part of a line.
func parseGrants(lines []string, tier config.Tier) []string {
	var extras []string
	add := func(e string) {
		if !slices.Contains(extras, e) {
			extras = append(extras, e)
		}
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "REVOKE ") { // MySQL partial revokes only take away
			continue
		}
		m := grantRe.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(upper, "GRANT PROXY") {
			if tier >= config.TierAdmin {
				continue
			}
			head, _, _ := strings.Cut(line, " TO ")
			head, _, _ = strings.Cut(head, " IDENTIFIED")
			add("ROLE/PROXY: " + head)
			continue
		}
		for _, p := range strings.Split(columnsRe.ReplaceAllString(m[1], ""), ",") {
			p = strings.ToUpper(spacesRe.ReplaceAllString(strings.TrimSpace(p), " "))
			if p != "" && !allowed(p, tier) {
				add(p)
			}
		}
		if strings.Contains(upper, "WITH GRANT OPTION") && tier < config.TierAdmin {
			add("GRANT OPTION")
		}
	}
	return extras
}
