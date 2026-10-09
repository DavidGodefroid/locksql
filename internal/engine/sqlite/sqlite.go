// Package sqlite is the SQLite engine, on the pure-Go modernc.org/sqlite
// driver. It registers itself as "sqlite" with the engine registry.
//
// Tier read opens the file with mode=ro and PRAGMA query_only=1, so a write
// fails twice over. Write tiers open it with mode=rw; neither mode creates a
// missing file. A context deadline interrupts a running statement through
// sqlite3_interrupt.
package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	msqlite "modernc.org/sqlite"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func init() { engine.Register(config.EngineSQLite, Engine{}) }

// Engine opens SQLite sessions.
type Engine struct{}

type session struct {
	db      *sql.DB
	conn    *sql.Conn
	fsPath  string // the database file, "" for :memory: and file: URIs
	tier    config.Tier
	timeout time.Duration
	version string
}

// Connect opens the profile's database file. secret is unused: SQLite has
// no credentials.
func (Engine) Connect(ctx context.Context, p config.Profile, _ []byte, _ engine.DialFunc) (engine.Session, error) {
	if p.Engine != config.EngineSQLite {
		return nil, fmt.Errorf("sqlite: profile engine is %q", p.Engine)
	}
	dsn, fsPath, err := buildDSN(p.Path, p.Tier)
	if err != nil {
		return nil, err
	}
	if fsPath != "" {
		if fi, err := os.Stat(fsPath); err != nil || fi.IsDir() {
			return nil, fmt.Errorf("sqlite: database file %s not found", fsPath)
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	s := &session{db: db, conn: conn, fsPath: fsPath, tier: p.Tier, timeout: p.Limits.StatementTimeout}
	if err := s.init(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// buildDSN returns the driver DSN for a profile path, and the file system
// path when there is one. Tier read gets mode=ro and query_only; the other
// tiers get mode=rw. trusted_schema=0 keeps functions with side effects out
// of views and triggers.
func buildDSN(path string, tier config.Tier) (dsn, fsPath string, err error) {
	var base string
	switch {
	case path == "":
		return "", "", errors.New("sqlite: profile has no path")
	case path == ":memory:":
		base = "file::memory:"
	case strings.HasPrefix(path, "file:"):
		if strings.ContainsAny(path, "?#") {
			return "", "", errors.New("sqlite: file: URIs with parameters are not supported; use a plain path")
		}
		base = path
	default:
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", "", fmt.Errorf("sqlite: %w", err)
		}
		slashed := filepath.ToSlash(abs)
		if !strings.HasPrefix(slashed, "/") {
			slashed = "/" + slashed // C:/x -> /C:/x
		}
		base = (&url.URL{Scheme: "file", Path: slashed}).String()
		fsPath = abs
	}
	params := []string{"mode=rw"}
	if tier == config.TierRead {
		params = []string{"mode=ro", "_pragma=query_only(1)"}
	}
	if base == "file::memory:" {
		params = params[1:] // mode does not apply to a memory database
	}
	params = append(params, "_pragma=busy_timeout(2000)", "_pragma=trusted_schema(0)")
	return base + "?" + strings.Join(params, "&"), fsPath, nil
}

func (s *session) init(ctx context.Context) error {
	if err := s.conn.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&s.version); err != nil {
		return fmt.Errorf("sqlite: open: %w", err)
	}
	if s.tier == config.TierRead {
		var on int
		if err := s.conn.QueryRowContext(ctx, "PRAGMA query_only").Scan(&on); err != nil || on != 1 {
			return errors.New("sqlite: could not enable query_only on a read tier")
		}
	}
	return nil
}

func (s *session) ServerVersion() string { return s.version }

func (s *session) Flavor() engine.Flavor { return engine.FlavorSQLite }

// OriginColumns is true: the driver reports sqlite3_column_{database,table,
// origin}_name. Run leaves the origin empty for compound selects, where
// SQLite reports only one arm, and for statements that name a view (see
// readsView).
func (s *session) OriginColumns() bool { return true }

// ExtraPrivileges warns, on tier read, when the OS user can write the file:
// locksql opens it read-only, but the file itself is not protected.
func (s *session) ExtraPrivileges(_ context.Context, tier config.Tier) ([]string, error) {
	if tier != config.TierRead || s.fsPath == "" {
		return nil, nil
	}
	f, err := os.OpenFile(s.fsPath, os.O_WRONLY, 0)
	if err != nil {
		return nil, nil
	}
	f.Close()
	return []string{"database file is writable by this OS user (locksql opens it read-only)"}, nil
}

func (s *session) Ping(ctx context.Context) error {
	if err := s.conn.PingContext(ctx); err != nil {
		return wrap(ctx, err)
	}
	return nil
}

func (s *session) Close() error {
	err := s.conn.Close()
	if e := s.db.Close(); err == nil {
		err = e
	}
	return err
}

func (s *session) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.timeout > 0 {
		return context.WithTimeout(ctx, s.timeout)
	}
	return context.WithCancel(ctx)
}

// wrap turns a driver error into a session error: the context error when
// the statement was interrupted, ErrConnLost when the connection is gone.
func wrap(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("sqlite: statement interrupted: %w", ctx.Err())
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) {
		return fmt.Errorf("sqlite: %w: %w", engine.ErrConnLost, err)
	}
	return fmt.Errorf("sqlite: %w", err)
}

// lexSingle lexes a statement and refuses ';' chaining: the driver would run
// every statement of a script.
func lexSingle(q string) ([]sqlclass.Token, error) {
	toks, err := sqlclass.Lex(sqlclass.SQLite, q)
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokPunct && t.Text == ";" {
			return nil, errors.New("sqlite: exactly one statement is allowed (no ';' chaining)")
		}
	}
	return toks, nil
}

func isCompound(toks []sqlclass.Token) bool {
	for _, t := range toks {
		if t.Kind == sqlclass.TokWord && (t.Text == "UNION" || t.Text == "INTERSECT" || t.Text == "EXCEPT") {
			return true
		}
	}
	return false
}

// readsView reports whether a name of the statement is a view of any
// attached schema. SQLite resolves origins through views, but for a view
// whose body is compound it reports one arm only, while the values come
// from every arm; and a view may rename a column. Origins are therefore
// trusted only for statements that name no view: a view's columns are then
// masked by name and checked by pii.AliasViolation, as on the other
// engines. A name matching a view in any role (column, alias) counts: a
// false match only drops origins.
func (s *session) readsView(ctx context.Context, toks []sqlclass.Token) (bool, error) {
	names := map[string]bool{}
	for _, t := range toks {
		if n := t.Name(); n != "" {
			names[n] = true
		}
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT name FROM pragma_database_list")
	if err != nil {
		return false, err
	}
	schemas, err := collect(rows)
	if err != nil {
		return false, err
	}
	for _, db := range schemas {
		master := `"` + strings.ReplaceAll(db, `"`, `""`) + `".sqlite_master`
		rows, err := s.conn.QueryContext(ctx, "SELECT name FROM "+master+" WHERE type = 'view'")
		if err != nil {
			return false, err
		}
		views, err := collect(rows)
		if err != nil {
			return false, err
		}
		for _, v := range views {
			if names[strings.ToUpper(strings.ToLower(v))] {
				return true, nil
			}
		}
	}
	return false, nil
}

// collect reads a single text column and closes rows.
func collect(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Run executes one classified statement. Reads stream at most maxRows rows;
// write classes run in a transaction that rolls back on error.
func (s *session) Run(ctx context.Context, db string, st sqlclass.Statement, maxRows int) (engine.Result, error) {
	if int(st.Class) > int(s.tier) {
		return engine.Result{}, fmt.Errorf("sqlite: a %s statement exceeds tier %s", st.Class, s.tier)
	}
	toks, err := lexSingle(st.SQL)
	if err != nil {
		return engine.Result{}, err
	}
	if err := s.checkDB(ctx, db); err != nil {
		return engine.Result{}, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	if st.Class == sqlclass.Read {
		withOrigins := !isCompound(toks)
		if withOrigins {
			view, err := s.readsView(ctx, toks)
			if err != nil {
				return engine.Result{}, wrap(ctx, err)
			}
			withOrigins = !view
		}
		return s.query(ctx, st.SQL, withOrigins, maxRows)
	}
	return s.exec(ctx, st)
}

func (s *session) query(ctx context.Context, q string, withOrigins bool, maxRows int) (engine.Result, error) {
	var info []msqlite.ColumnInfo
	if withOrigins {
		var err error
		if info, err = s.columnInfo(q); err != nil {
			return engine.Result{}, wrap(ctx, err)
		}
		if info, err = s.baseTablesOnly(ctx, info); err != nil {
			return engine.Result{}, wrap(ctx, err)
		}
	}
	rows, err := s.conn.QueryContext(ctx, q)
	if err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	defer rows.Close()
	labels, err := rows.Columns()
	if err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	res := engine.Result{Columns: make([]engine.ResultColumn, len(labels)), Rows: [][]any{}}
	for i, l := range labels {
		res.Columns[i].Label = l
		if len(info) == len(labels) && info[i].TableName != "" && info[i].OriginName != "" {
			res.Columns[i].OriginDB = info[i].DatabaseName
			res.Columns[i].OriginTable = info[i].TableName
			res.Columns[i].OriginColumn = info[i].OriginName
		}
	}
	for rows.Next() {
		if maxRows > 0 && len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		vals := make([]any, len(labels))
		ptrs := make([]any, len(labels))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return engine.Result{}, wrap(ctx, err)
		}
		res.Rows = append(res.Rows, vals)
	}
	if err := rows.Err(); err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	if ctx.Err() != nil {
		return engine.Result{}, wrap(ctx, ctx.Err())
	}
	return res, nil
}

// baseTablesOnly blanks every origin whose table is not an ordinary table
// of its schema: SQLite also names table-valued functions (json_each,
// json_tree, pragma_*) and virtual tables as origins, and their values can
// be anything, a rule-matched column included.
func (s *session) baseTablesOnly(ctx context.Context, info []msqlite.ColumnInfo) ([]msqlite.ColumnInfo, error) {
	real := map[[2]string]bool{}
	for i, c := range info {
		if c.TableName == "" {
			continue
		}
		key := [2]string{c.DatabaseName, c.TableName}
		ok, seen := real[key]
		if !seen {
			db := c.DatabaseName
			if db == "" {
				db = "main"
			}
			schema := `"` + strings.ReplaceAll(db, `"`, `""`) + `".sqlite_master`
			var n int // a virtual table has rootpage 0
			err := s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+schema+
				" WHERE type = 'table' AND name = ? AND rootpage > 0", c.TableName).Scan(&n)
			if err != nil {
				return nil, err
			}
			ok = n == 1
			real[key] = ok
		}
		if !ok {
			info[i].DatabaseName, info[i].TableName, info[i].OriginName = "", "", ""
		}
	}
	return info, nil
}

// columnInfo prepares q, without running it, to read each result column's
// origin.
func (s *session) columnInfo(q string) ([]msqlite.ColumnInfo, error) {
	var info []msqlite.ColumnInfo
	err := s.conn.Raw(func(dc any) error {
		c, ok := dc.(interface {
			ColumnInfo(string) ([]msqlite.ColumnInfo, error)
		})
		if !ok {
			return nil
		}
		var err error
		info, err = c.ColumnInfo(q)
		return err
	})
	return info, err
}

func (s *session) exec(ctx context.Context, st sqlclass.Statement) (engine.Result, error) {
	if st.Kind == "vacuum" { // VACUUM cannot run inside a transaction
		if _, err := s.conn.ExecContext(ctx, st.SQL); err != nil {
			return engine.Result{}, wrap(ctx, err)
		}
		return engine.Result{}, nil
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	r, err := tx.ExecContext(ctx, st.SQL)
	if err != nil {
		tx.Rollback()
		return engine.Result{}, wrap(ctx, err)
	}
	var res engine.Result
	if st.Class == sqlclass.Write {
		if res.Affected, err = r.RowsAffected(); err != nil {
			tx.Rollback()
			return engine.Result{}, wrap(ctx, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return engine.Result{}, wrap(ctx, err)
	}
	return res, nil
}
