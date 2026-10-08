// Package postgres is the PostgreSQL engine, on pgx v5. It registers itself
// as "postgres".
//
// User SQL only ever goes through the extended protocol (pgconn.ExecParams),
// which takes exactly one statement: the server refuses "SELECT 1; SELECT 2"
// even if it got past the classifier. The simple protocol is used for the
// console's own constant statements (BEGIN, COMMIT, SET) only.
//
// Tier read sets SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY and
// runs every statement inside BEGIN READ ONLY, so a write fails on the server
// even if it got past the classifier. The statement timeout is the server's
// statement_timeout and, as a backstop, a client deadline that sends a
// cancel request (which keeps the connection usable).
//
// Names: a PostgreSQL connection is bound to one database, and tables live
// in schemas inside it. The db argument of Run, Explain and the catalog
// methods is the database ("" is the profile's); the session keeps one
// connection per database, opened on first use. Table names from Tables are
// "table" for schema public and "schema.table" otherwise. In ColumnInfo,
// TableInfo and result column origins, the DB field holds the schema, which
// is the namespace PII rules match ("public.users.email").
package postgres

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func init() {
	engine.Register(config.EnginePostgres, Engine{})
}

// Engine opens PostgreSQL sessions.
type Engine struct{}

const (
	connectTimeout = 10 * time.Second
	// controlTimeout bounds the console's own statements run after a
	// cancelled context (ROLLBACK).
	controlTimeout = 5 * time.Second
	// deadlineGrace lets statement_timeout fire, with its clearer error,
	// before the client deadline cancels the query.
	deadlineGrace = 500 * time.Millisecond
	// cancelDeadline is how long a cancelled query may take to stop before
	// pgx gives up on the connection (which is then reported lost).
	cancelDeadline = 5 * time.Second
)

type dbConn struct {
	name string
	conn *pgx.Conn
}

type session struct {
	mu sync.Mutex // serialises use of the connections
	// cfg is the template of every connection. It holds the password:
	// pgx keeps it in each connection's config anyway, and a connection to
	// another database cannot be opened without it.
	cfg     *pgx.ConnConfig
	conns   map[string]*dbConn
	defDB   string // the current database of the first connection
	dead    atomic.Bool
	version string
	major   int
	tier    config.Tier
	timeout time.Duration
	plain   bool // TCP without TLS (sslmode=prefer fell back)
}

// Notices reports a TCP connection that is not encrypted.
func (s *session) Notices() []string {
	if s.plain {
		return []string{"the connection is NOT encrypted: the server offers no TLS (use an SSH tunnel for a remote server)"}
	}
	return nil
}

// Connect opens the connection to the profile's database and applies the
// session settings of the profile's tier.
func (Engine) Connect(ctx context.Context, p config.Profile, secret []byte) (engine.Session, error) {
	if p.Engine != config.EnginePostgres {
		return nil, fmt.Errorf("postgres: profile engine is %q", p.Engine)
	}
	cfg, err := connConfig(p, secret)
	if err != nil {
		return nil, err
	}
	s := &session{cfg: cfg, conns: map[string]*dbConn{}, tier: p.Tier, timeout: p.Limits.StatementTimeout}
	dc, err := s.open(ctx, p.Database)
	if err != nil {
		return nil, err
	}
	s.defDB = dc.name
	s.conns[dc.name] = dc
	if _, tlsOn := dc.conn.PgConn().Conn().(*tls.Conn); !tlsOn && !strings.HasPrefix(p.Host, "/") {
		s.plain = true
	}
	s.version = dc.conn.PgConn().ParameterStatus("server_version")
	s.major, _ = strconv.Atoi(strings.SplitN(s.version, ".", 2)[0])
	return s, nil
}

// connConfig builds the pgx configuration from the profile alone. The
// libpq environment (PGPASSWORD, PGOPTIONS, PGSSLMODE, ~/.pgpass,
// target_session_attrs, ...) is neutralised: the console's profile and
// secret are the only inputs.
func connConfig(p config.Profile, secret []byte) (*pgx.ConnConfig, error) {
	port, db := p.Port, p.Database
	if port <= 0 {
		port = 5432
	}
	if db == "" {
		db = p.User // PostgreSQL's own default
	}
	settings := []string{
		kv("host", p.Host),
		kv("port", strconv.Itoa(port)),
		kv("user", p.User),
		kv("dbname", db),
		kv("passfile", ""),
		// prefer, as libpq's default: TLS when the server offers it. An
		// active attacker can strip it, read the queries and results, and
		// ask for the password in clear (AuthenticationCleartextPassword,
		// which pgx honours); a profile setting to require verified TLS is
		// a follow-up, the spec has none.
		"sslmode=prefer",
	}
	cfg, err := pgx.ParseConfig(strings.Join(settings, " "))
	if err != nil {
		return nil, fmt.Errorf("postgres: invalid connection settings: %s", redact(err.Error(), string(secret)))
	}
	cfg.Password = string(secret)
	cfg.ConnectTimeout = connectTimeout
	cfg.RuntimeParams = map[string]string{"application_name": "locksql", "client_encoding": "UTF8"}
	cfg.ValidateConnect = nil
	cfg.AfterConnect = nil
	cfg.OnNotice = nil
	cfg.OnNotification = nil
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	cfg.StatementCacheCapacity = 0
	cfg.DescriptionCacheCapacity = 0
	cfg.BuildContextWatcherHandler = func(pc *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{Conn: pc, DeadlineDelay: cancelDeadline}
	}
	return cfg, nil
}

// kv is one keyword/value connection setting, quoted.
func kv(k, v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return k + "='" + v + "'"
}

func redact(msg, secret string) string {
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "***")
	}
	return msg
}

// open connects to database db ("" is the profile's) and applies the
// session settings.
func (s *session) open(ctx context.Context, db string) (*dbConn, error) {
	cfg := s.cfg.Copy()
	if db != "" {
		cfg.Database = db
	}
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(cctx, cfg)
	if err != nil {
		return nil, connectError(err, s.cfg.Password)
	}
	var stmts []string
	if s.tier == config.TierRead {
		stmts = append(stmts, "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
	}
	stmts = append(stmts, "SET statement_timeout = "+strconv.FormatInt(max(s.timeout.Milliseconds(), 0), 10))
	for _, q := range stmts {
		if _, err := conn.Exec(cctx, q); err != nil {
			conn.Close(context.Background())
			return nil, fmt.Errorf("postgres: session setup: %s", pgMessage(err))
		}
	}
	name := cfg.Database
	if err := conn.QueryRow(cctx, "SELECT current_database()").Scan(&name); err != nil {
		conn.Close(context.Background())
		return nil, fmt.Errorf("postgres: session setup: %s", pgMessage(err))
	}
	return &dbConn{name: name, conn: conn}, nil
}

// connectError keeps the server's reason and drops anything that could
// echo the secret.
func connectError(err error, pw string) error {
	msg := err.Error()
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		msg = fmt.Sprintf("%s %s: %s", pe.Severity, pe.Code, pe.Message)
	}
	return fmt.Errorf("postgres: connect: %s", redact(msg, pw))
}

// pgMessage is the server's error without its DETAIL (which can quote row
// values), or the error text.
func pgMessage(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return fmt.Sprintf("%s %s: %s", pe.Severity, pe.Code, pe.Message)
	}
	return err.Error()
}

func (s *session) ServerVersion() string { return s.version }

func (s *session) Flavor() engine.Flavor { return engine.FlavorPostgres }

// OriginColumns is true: the protocol reports each column's table OID and
// attribute number, resolved through pg_attribute. Only base-table columns
// keep an origin (see originKinds); a view's columns get none.
func (s *session) OriginColumns() bool { return true }

func (s *session) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead.Load() {
		return s.lost(nil)
	}
	for _, dc := range s.conns {
		if err := dc.conn.Ping(ctx); err != nil {
			return s.fail(ctx, dc, err)
		}
	}
	return nil
}

func (s *session) Close() error {
	s.dead.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeAll()
	s.cfg.Password = ""
	return nil
}

// closeAll closes every connection. Called with mu held.
func (s *session) closeAll() {
	for name, dc := range s.conns {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		dc.conn.Close(ctx)
		cancel()
		delete(s.conns, name)
	}
}

// markDead closes the session after a lost connection: the console
// reconnects instead of retrying. Called with mu held.
func (s *session) markDead() {
	if s.dead.CompareAndSwap(false, true) {
		s.closeAll()
	}
}

func (s *session) lost(err error) error {
	if err == nil {
		return fmt.Errorf("postgres: %w", engine.ErrConnLost)
	}
	return fmt.Errorf("postgres: %w: %v", engine.ErrConnLost, err)
}

// fail turns a driver error into a session error: ErrConnLost when the
// connection is gone, the context error when the statement was cancelled,
// statement_timeout as an interruption, the server's error otherwise.
// Called with mu held.
func (s *session) fail(ctx context.Context, dc *dbConn, err error) error {
	var le localError
	if errors.As(err, &le) {
		return le.err
	}
	var pe *pgconn.PgError
	isPg := errors.As(err, &pe)
	if dc.conn.IsClosed() || !isPg && ctx.Err() == nil {
		s.markDead()
		return s.lost(errors.New(pgMessage(err)))
	}
	if ctx.Err() != nil {
		return fmt.Errorf("postgres: statement interrupted: %w", ctx.Err())
	}
	if pe.Code == "57014" && strings.Contains(pe.Message, "statement timeout") {
		return fmt.Errorf("postgres: statement interrupted: %s (%s): %w", pe.Message, s.timeout, context.DeadlineExceeded)
	}
	return fmt.Errorf("postgres: %s", pgMessage(err))
}

// localError marks an error raised by the engine's own work in a
// transaction (decoding a plan, scanning a catalog row) while the
// connection is still sound: fail returns it as is instead of reporting
// the connection lost.
type localError struct{ err error }

func (e localError) Error() string { return e.err.Error() }
func (e localError) Unwrap() error { return e.err }

// local wraps err as a localError unless it comes from the server, the
// connection is gone or ctx is done, which fail must see. Called with mu
// held.
func local(ctx context.Context, dc *dbConn, err error) error {
	var pe *pgconn.PgError
	if err == nil || errors.As(err, &pe) || dc.conn.IsClosed() || ctx.Err() != nil {
		return err
	}
	return localError{err}
}

// conn returns the connection to database db ("" is the default one),
// opening it on first use. Called with mu held.
func (s *session) conn(ctx context.Context, db string) (*dbConn, error) {
	if s.dead.Load() {
		return nil, s.lost(nil)
	}
	if db == "" {
		db = s.defDB
	}
	if dc, ok := s.conns[db]; ok {
		return dc, nil
	}
	dc, err := s.open(ctx, db)
	if err != nil {
		return nil, err
	}
	s.conns[db] = dc
	return dc, nil
}

func (s *session) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.timeout > 0 {
		return context.WithTimeout(ctx, s.timeout+deadlineGrace)
	}
	return context.WithCancel(ctx)
}

// lexSingle refuses ';' chaining. The extended protocol refuses it too, but
// the check does not depend on it.
func lexSingle(q string) error {
	toks, err := sqlclass.Lex(sqlclass.Postgres, q)
	if err != nil {
		return err
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokPunct && t.Text == ";" {
			return errors.New("postgres: exactly one statement is allowed (no ';' chaining)")
		}
	}
	return nil
}

// noTxWords are statements PostgreSQL refuses to run inside a transaction
// block, when they follow CREATE/DROP/ALTER.
var noTxWords = map[string]bool{"DATABASE": true, "TABLESPACE": true, "SYSTEM": true, "SUBSCRIPTION": true}

// reindexNoTx are the REINDEX targets that cannot run in a transaction
// block.
var reindexNoTx = map[string]bool{"SCHEMA": true, "DATABASE": true, "SYSTEM": true}

// needsNoTx reports a statement that cannot run in a transaction block:
// VACUUM, CREATE/DROP DATABASE or TABLESPACE, ALTER SYSTEM, REINDEX
// SCHEMA/DATABASE/SYSTEM, CLUSTER without a table, and anything
// CONCURRENTLY. (DISCARD ALL is refused by the classifier.)
func needsNoTx(st sqlclass.Statement) bool {
	if st.Class == sqlclass.Read || st.Class == sqlclass.Write {
		return false
	}
	toks, err := sqlclass.Lex(sqlclass.Postgres, st.SQL)
	if err != nil || len(toks) == 0 {
		return false
	}
	if toks[0].Kind == sqlclass.TokWord && toks[0].Text == "VACUUM" {
		return true
	}
	// The words after the leading one, outside the option list "( ... )".
	var words []string
	for _, t := range toks[1:] {
		if t.Depth == 0 && t.Kind != sqlclass.TokPunct {
			words = append(words, t.Text)
		}
	}
	switch toks[0].Text {
	case "REINDEX":
		if len(words) > 0 && reindexNoTx[words[0]] {
			return true
		}
	case "CLUSTER":
		if len(words) == 0 || len(words) == 1 && words[0] == "VERBOSE" {
			return true
		}
	}
	if len(toks) > 1 && toks[1].Kind == sqlclass.TokWord && noTxWords[toks[1].Text] &&
		(toks[0].Text == "CREATE" || toks[0].Text == "DROP" || toks[0].Text == "ALTER") {
		return true
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokWord && t.Text == "CONCURRENTLY" {
			return true
		}
	}
	return false
}

// Run executes one classified statement: inside BEGIN READ ONLY for the
// read class, inside BEGIN … COMMIT (ROLLBACK on error) for the others,
// except the few statements PostgreSQL only runs outside a transaction.
func (s *session) Run(ctx context.Context, db string, st sqlclass.Statement, maxRows int) (engine.Result, error) {
	if int(st.Class) > int(s.tier) {
		return engine.Result{}, fmt.Errorf("postgres: a %s statement exceeds tier %s", st.Class, s.tier)
	}
	if err := lexSingle(st.SQL); err != nil {
		return engine.Result{}, err
	}
	begin := "BEGIN"
	switch {
	case st.Class == sqlclass.Read:
		begin = "BEGIN READ ONLY"
	case needsNoTx(st):
		begin = ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return engine.Result{}, fmt.Errorf("postgres: statement interrupted: %w", err)
	}
	dc, err := s.conn(ctx, db)
	if err != nil {
		return engine.Result{}, err
	}
	res, err := s.inTx(ctx, dc, begin, true, func(ctx context.Context) (engine.Result, error) {
		res, keys, err := s.stream(ctx, dc, st.SQL, maxRows)
		if err != nil {
			return res, err
		}
		return res, local(ctx, dc, s.resolveOrigins(ctx, dc, res.Columns, keys))
	})
	if err != nil {
		return engine.Result{}, err
	}
	if st.Class != sqlclass.Write {
		res.Affected = 0
	}
	return res, nil
}

// inTx runs fn under the statement timeout, between begin and COMMIT
// (ROLLBACK when commit is false or on error). An empty begin runs fn
// alone. Called with mu held.
func (s *session) inTx(ctx context.Context, dc *dbConn, begin string, commit bool,
	fn func(ctx context.Context) (engine.Result, error)) (engine.Result, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	if begin != "" {
		if _, err := dc.conn.Exec(ctx, begin); err != nil {
			return engine.Result{}, s.fail(ctx, dc, err)
		}
	}
	res, err := fn(ctx)
	if begin == "" {
		if err != nil {
			return engine.Result{}, s.fail(ctx, dc, err)
		}
		return res, nil
	}
	if err != nil || !commit {
		if rerr := s.rollback(dc); rerr != nil && err == nil {
			err = rerr
		}
		if err != nil {
			return engine.Result{}, s.fail(ctx, dc, err)
		}
		return res, nil
	}
	if _, err := dc.conn.Exec(ctx, "COMMIT"); err != nil {
		return engine.Result{}, s.fail(ctx, dc, err)
	}
	return res, nil
}

// rollback ends the transaction with its own deadline, since the caller's
// context may be the one that was cancelled.
func (s *session) rollback(dc *dbConn) error {
	if dc.conn.IsClosed() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	_, err := dc.conn.Exec(ctx, "ROLLBACK")
	return err
}

// stream runs q through the extended protocol in text format and keeps at
// most maxRows rows (all when maxRows <= 0); the rest of the result is read
// and dropped. Called with mu held.
func (s *session) stream(ctx context.Context, dc *dbConn, q string, maxRows int) (engine.Result, []originKey, error) {
	rr := dc.conn.PgConn().ExecParams(ctx, q, nil, nil, nil, nil)
	fds := rr.FieldDescriptions()
	out := engine.Result{Columns: make([]engine.ResultColumn, len(fds)), Rows: [][]any{}}
	oids := make([]uint32, len(fds))
	for i, fd := range fds {
		out.Columns[i] = engine.ResultColumn{Label: fd.Name}
		oids[i] = fd.DataTypeOID
	}
	keys := make([]originKey, len(fds))
	for i, fd := range fds {
		keys[i] = originKey{fd.TableOID, fd.TableAttributeNumber}
	}
	for rr.NextRow() {
		if maxRows > 0 && len(out.Rows) >= maxRows {
			out.Truncated = true
			continue
		}
		raw := rr.Values()
		row := make([]any, len(raw))
		for i, v := range raw {
			var oid uint32
			if i < len(oids) {
				oid = oids[i]
			}
			row[i] = value(v, oid)
		}
		out.Rows = append(out.Rows, row)
	}
	tag, err := rr.Close()
	if err != nil {
		return engine.Result{}, nil, err
	}
	out.Affected = tag.RowsAffected()
	return out, keys, nil
}

// value converts a text-format value: nil, int64 for integer types,
// float64 for float types (NaN and infinities included), bool, []byte for
// bytea, and the server's text for everything else (numeric, dates, json,
// arrays, ...).
func value(v []byte, oid uint32) any {
	if v == nil {
		return nil
	}
	switch oid {
	case pgtype.Int2OID, pgtype.Int4OID, pgtype.Int8OID, pgtype.OIDOID:
		if n, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			return n
		}
	case pgtype.Float4OID, pgtype.Float8OID:
		if f, err := strconv.ParseFloat(string(v), 64); err == nil || errors.Is(err, strconv.ErrRange) {
			return f
		}
		switch string(v) {
		case "Infinity":
			return math.Inf(1)
		case "-Infinity":
			return math.Inf(-1)
		}
	case pgtype.BoolOID:
		switch string(v) {
		case "t":
			return true
		case "f":
			return false
		}
	case pgtype.ByteaOID:
		if len(v) >= 2 && v[0] == '\\' && v[1] == 'x' {
			b := make([]byte, hex.DecodedLen(len(v)-2))
			if _, err := hex.Decode(b, v[2:]); err == nil {
				return b
			}
		}
		return append([]byte{}, v...)
	}
	if !utf8.Valid(v) {
		return append([]byte{}, v...)
	}
	return string(v)
}
