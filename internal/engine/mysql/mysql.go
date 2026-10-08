// Package mysql is the MariaDB and MySQL engine, on the go-mysql-org
// client (chosen because it reports each result column's origin schema,
// table and column). It registers itself as "mariadb" and "mysql".
//
// A session holds two connections: the main one, which runs everything,
// and a control one, opened at the same time, whose only job is to send
// KILL QUERY for the main one when a context is cancelled (the driver's
// Execute takes no context). Keeping it open means the secret is not needed
// again after Connect.
//
// Tier read sets SET SESSION TRANSACTION READ ONLY and runs every statement
// inside START TRANSACTION READ ONLY, so a write fails on the server even if
// it got past the classifier. The statement timeout is enforced by the
// server (max_statement_time on MariaDB, max_execution_time for SELECT on
// MySQL) and, as a backstop, by a client deadline that kills the query.
package mysql

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func init() {
	engine.Register(config.EngineMariaDB, Engine{})
	engine.Register(config.EngineMySQL, Engine{})
}

// Engine opens MariaDB and MySQL sessions.
type Engine struct{}

const (
	connectTimeout = 10 * time.Second
	// killTimeout bounds every exchange on the control connection.
	killTimeout = 5 * time.Second
	// deadlineGrace lets the server's own timeout fire, with its clearer
	// error, before the client deadline kills the query.
	deadlineGrace = 500 * time.Millisecond

	readOnlyTx = "START TRANSACTION READ ONLY"
)

type session struct {
	mu      sync.Mutex // serialises use of conn
	conn    *client.Conn
	connID  uint32
	ctlMu   sync.Mutex
	ctl     *client.Conn
	dead    atomic.Bool
	flavor  engine.Flavor
	engine  string // the profile's engine name
	version string
	tier    config.Tier
	timeout time.Duration
	defDB   string
	// plain is set when a TCP connection fell back to no TLS.
	plain bool
}

// DriverOptions are the client options of every connection locksql opens:
// no multi-statements and no LOCAL INFILE. Exported so that integration
// tests can check what the driver itself accepts.
func DriverOptions() []client.Option {
	return []client.Option{func(c *client.Conn) error {
		c.UnsetCapability(gomysql.CLIENT_MULTI_STATEMENTS)
		c.UnsetCapability(gomysql.CLIENT_LOCAL_FILES)
		c.SetAttributes(map[string]string{"program_name": "locksql"})
		return nil
	}}
}

// Connect opens the main and the control connections, detects the server
// flavour and applies the session settings of the profile's tier.
func (Engine) Connect(ctx context.Context, p config.Profile, secret []byte) (engine.Session, error) {
	if p.Engine != config.EngineMariaDB && p.Engine != config.EngineMySQL {
		return nil, fmt.Errorf("mysql: profile engine is %q", p.Engine)
	}
	addr := p.Host
	if !strings.HasPrefix(p.Host, "/") { // a path is a Unix socket
		addr = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	}
	pw := string(secret)
	// TLS as PostgreSQL's sslmode=prefer: encrypted whenever the server
	// offers it (certificate not verified), plain otherwise. A Unix socket
	// stays plain.
	useTLS := !strings.HasPrefix(p.Host, "/")
	conn, err := dial(ctx, addr, p.User, pw, p.Database, 0, useTLS)
	if err != nil && useTLS && noServerTLS(err) {
		useTLS = false
		conn, err = dial(ctx, addr, p.User, pw, p.Database, 0, false)
	}
	if err != nil {
		return nil, connectError(err, pw)
	}
	ctl, err := dial(ctx, addr, p.User, pw, "", killTimeout, useTLS)
	if err != nil {
		conn.Close()
		return nil, connectError(err, pw)
	}
	s := &session{
		conn: conn, connID: conn.GetConnectionID(), ctl: ctl, engine: p.Engine,
		tier: p.Tier, timeout: p.Limits.StatementTimeout, defDB: p.Database,
		plain: !useTLS && !strings.HasPrefix(p.Host, "/"),
	}
	if err := s.setup(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Notices reports a TCP connection that is not encrypted: the server
// offers no TLS (or an attacker stripped it), so queries and results travel
// in clear.
func (s *session) Notices() []string {
	if s.plain {
		return []string{"the connection is NOT encrypted: the server offers no TLS (use an SSH tunnel for a remote server)"}
	}
	return nil
}

// dial connects with a deadline covering the TCP connect and the handshake
// (the driver has none for the handshake). readTimeout > 0 bounds every
// later read and write too.
func dial(ctx context.Context, addr, user, pw, db string, ioTimeout time.Duration, useTLS bool) (*client.Conn, error) {
	deadline := time.Now().Add(connectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var guard *clearTextGuard
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		nc, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := nc.SetDeadline(deadline); err != nil {
			nc.Close()
			return nil, err
		}
		if !useTLS && network != "unix" {
			guard = &clearTextGuard{Conn: nc}
			guard.armed.Store(true)
			return guard, nil
		}
		return nc, nil
	}
	opts := DriverOptions()
	if ioTimeout > 0 {
		opts = append(opts, func(c *client.Conn) error {
			c.ReadTimeout, c.WriteTimeout = ioTimeout, ioTimeout
			return nil
		})
	}
	if useTLS {
		opts = append(opts, func(c *client.Conn) error {
			c.SetTLSConfig(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // prefer: encrypt, do not verify
			return nil
		})
	}
	c, err := client.ConnectWithDialer(ctx, "", addr, user, pw, db, dialer, opts...)
	if guard != nil {
		guard.armed.Store(false) // authenticated: later reads are row data
		if guard.refused.Load() {
			if c != nil {
				c.Close()
			}
			return nil, guard.why
		}
	}
	if err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// errClearText refuses a server that asks for the password in clear text
// on an unencrypted TCP connection.
var errClearText = errors.New("the server asks for the password in clear text (mysql_clear_password) on an unencrypted connection; refused: use a server with TLS, an SSH tunnel or a Unix socket")

// errPublicKey refuses a server that asks for the password encrypted with
// an RSA key it sends itself, on an unencrypted TCP connection.
var errPublicKey = errors.New("the server asks for the password encrypted with a public key it sends itself (caching_sha2_password full authentication or sha256_password) on an unencrypted connection; refused, since an attacker who removed TLS could send its own key: use a server with TLS, an SSH tunnel or a Unix socket")

// clearTextMarker is the name of the plugin that sends the password as is.
var clearTextMarker = []byte(gomysql.AUTH_CLEAR_PASSWORD)

// clearTextGuard wraps an unencrypted TCP connection during the handshake.
// An active attacker who strips TLS can ask go-mysql for the password in
// three ways: an auth switch to mysql_clear_password (the raw password), and
// an auth switch to sha256_password or a caching_sha2_password full
// authentication (the password encrypted with an RSA key the "server"
// sends, which the attacker holds). The guard reads the handshake packets
// and fails the read that brings such a request, before the driver can
// answer: an auth switch to either plugin, and any auth-more-data packet
// other than the caching_sha2_password fast-auth success. It stops looking
// at the first OK or ERR packet, which ends the authentication.
type clearTextGuard struct {
	net.Conn
	armed   atomic.Bool
	refused atomic.Bool
	tail    []byte
	pkt     []byte // bytes of the packets not yet complete
	npkt    int    // packets seen
	authed  bool   // an OK or ERR packet ended the authentication
	why     error
}

func (g *clearTextGuard) Read(b []byte) (int, error) {
	n, err := g.Conn.Read(b)
	if n > 0 && g.armed.Load() {
		buf := append(g.tail, b[:n]...)
		if !g.authed && bytes.Contains(buf, clearTextMarker) {
			return g.refuse(errClearText)
		}
		if keep := len(clearTextMarker) - 1; len(buf) > keep {
			buf = buf[len(buf)-keep:]
		}
		g.tail = append(g.tail[:0], buf...)
		if why := g.inspect(b[:n]); why != nil {
			return g.refuse(why)
		}
	}
	return n, err
}

func (g *clearTextGuard) refuse(why error) (int, error) {
	g.why = why
	g.refused.Store(true)
	g.Conn.Close()
	return 0, why
}

// inspect feeds the handshake packets read so far and returns the reason to
// refuse, if any.
func (g *clearTextGuard) inspect(b []byte) error {
	if g.authed {
		return nil
	}
	g.pkt = append(g.pkt, b...)
	for len(g.pkt) >= 4 {
		size := int(g.pkt[0]) | int(g.pkt[1])<<8 | int(g.pkt[2])<<16
		if len(g.pkt) < 4+size {
			return nil
		}
		payload := g.pkt[4 : 4+size]
		g.npkt++
		if g.npkt > 1 && size > 0 { // the first packet is the server greeting
			switch payload[0] {
			case 0x00, 0xff: // OK, ERR: authentication is over
				g.authed = true
				g.pkt = nil
				return nil
			case 0xfe: // auth switch
				name := payload[1:]
				if i := bytes.IndexByte(name, 0); i >= 0 {
					name = name[:i]
				}
				switch string(name) {
				case gomysql.AUTH_CLEAR_PASSWORD:
					return errClearText
				case gomysql.AUTH_SHA256_PASSWORD:
					return errPublicKey
				}
			case 0x01: // auth more data: only the fast-auth success is safe
				if !(size == 2 && payload[1] == gomysql.CACHE_SHA2_FAST_AUTH) {
					return errPublicKey
				}
			}
		}
		g.pkt = g.pkt[4+size:]
	}
	return nil
}

// noServerTLS reports whether a handshake failed because the server does
// not offer TLS (go-mysql checks the server's CLIENT_SSL capability before
// sending anything, the secret included).
func noServerTLS(err error) bool {
	return err != nil && strings.Contains(err.Error(), "does not support TLS")
}

// connectError keeps the server's reason and drops anything that could
// echo the secret.
func connectError(err error, pw string) error {
	msg := err.Error()
	var me *gomysql.MyError
	if errors.As(err, &me) {
		msg = fmt.Sprintf("error %d (%s): %s", me.Code, me.State, me.Message)
	}
	if pw != "" {
		msg = strings.ReplaceAll(msg, pw, "***")
	}
	return fmt.Errorf("mysql: connect: %s", msg)
}

func (s *session) setup() error {
	r, err := s.conn.Execute("SELECT VERSION(), @@version_comment")
	if err != nil {
		return s.fail(context.Background(), err)
	}
	if r.RowNumber() != 1 {
		return errors.New("mysql: cannot read the server version")
	}
	s.version, _ = r.GetString(0, 0)
	comment, _ := r.GetString(0, 1)
	s.flavor = engine.FlavorMySQL
	if strings.Contains(strings.ToLower(s.version+" "+comment), "mariadb") {
		s.flavor = engine.FlavorMariaDB
	}
	var stmts []string
	if s.tier == config.TierRead {
		stmts = append(stmts, "SET SESSION TRANSACTION READ ONLY")
	}
	if q := timeoutSQL(s.flavor, s.timeout); q != "" {
		stmts = append(stmts, q)
	}
	for _, q := range stmts {
		if _, err := s.conn.Execute(q); err != nil {
			return s.fail(context.Background(), err)
		}
	}
	return nil
}

// timeoutSQL is the statement setting the server-side timeout, "" when
// there is none.
func timeoutSQL(f engine.Flavor, d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if f == engine.FlavorMariaDB {
		return "SET SESSION max_statement_time = " + strconv.FormatFloat(d.Seconds(), 'f', 3, 64)
	}
	return "SET SESSION max_execution_time = " + strconv.FormatInt(max(d.Milliseconds(), 1), 10)
}

func (s *session) ServerVersion() string { return s.version }

func (s *session) Flavor() engine.Flavor { return s.flavor }

// OriginColumns is true: the protocol reports each column's schema, table
// and column. Views, and on MariaDB derived tables and CTEs, report
// themselves as the origin, so Run keeps an origin only when it is trusted,
// see trustOrigins.
func (s *session) OriginColumns() bool { return true }

func (s *session) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead.Load() {
		return s.lost(nil)
	}
	if err := s.conn.Ping(); err != nil {
		return s.fail(ctx, err)
	}
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if err := s.ctl.Ping(); err != nil {
		s.markDead()
		return s.lost(err)
	}
	return nil
}

func (s *session) Close() error {
	s.dead.Store(true)
	s.ctlMu.Lock()
	s.ctl.Close()
	s.ctlMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

func (s *session) markDead() {
	if s.dead.CompareAndSwap(false, true) {
		s.conn.Close()
	}
}

func (s *session) lost(err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", s.flavor, engine.ErrConnLost)
	}
	return fmt.Errorf("%s: %w: %v", s.flavor, engine.ErrConnLost, err)
}

// lostCodes are server errors after which the connection is gone.
var lostCodes = map[uint16]bool{
	1053: true, // server shutdown in progress
	1152: true, // aborted connection
	1927: true, // MariaDB: connection was killed
	2006: true, // server has gone away
	2013: true, // lost connection during query
	3169: true, // MySQL: session was killed
	4031: true, // MySQL: disconnected by the server (inactivity)
}

// fail turns a driver error into a session error: the context error when
// the statement was cancelled (MySQL can answer a killed SLEEP() with a
// value and no error, so the context is the reference), the server's error
// as is, and ErrConnLost for everything else, which is I/O or protocol
// trouble that leaves the connection unusable.
func (s *session) fail(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: statement interrupted: %w", s.flavor, ctx.Err())
	}
	var me *gomysql.MyError
	if errors.As(err, &me) {
		if lostCodes[me.Code] {
			s.markDead()
			return s.lost(fmt.Errorf("error %d: %s", me.Code, me.Message))
		}
		return fmt.Errorf("%s: error %d (%s): %s", s.flavor, me.Code, me.State, me.Message)
	}
	s.markDead()
	return s.lost(err)
}

func (s *session) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.timeout > 0 {
		return context.WithTimeout(ctx, s.timeout+deadlineGrace)
	}
	return context.WithCancel(ctx)
}

// watch kills the running query when ctx ends. The returned stop function
// must be called before the next statement on the connection: it waits for
// a KILL in flight to finish, so that the KILL never hits a later statement.
func (s *session) watch(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	quit := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			s.kill()
		case <-quit:
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}

// kill sends KILL QUERY for the main connection on the control one. If that
// fails, it closes the main connection, which unblocks the driver.
func (s *session) kill() {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if s.dead.Load() {
		return
	}
	if _, err := s.ctl.Execute("KILL QUERY " + strconv.FormatUint(uint64(s.connID), 10)); err != nil {
		s.markDead()
	}
}

// lexSingle refuses ';' chaining. The driver has multi-statements off, but
// the check does not depend on it.
func lexSingle(q string) error {
	toks, err := sqlclass.Lex(sqlclass.MySQL, q)
	if err != nil {
		return err
	}
	for _, t := range toks {
		if t.Kind == sqlclass.TokPunct && t.Text == ";" {
			return errors.New("mysql: exactly one statement is allowed (no ';' chaining)")
		}
	}
	return nil
}

// useDB switches the main connection's database through COM_INIT_DB ("" is
// the profile's database). Called with mu held.
func (s *session) useDB(ctx context.Context, db string) error {
	if db == "" {
		db = s.defDB
	}
	if db == "" || db == s.conn.GetDB() {
		return nil
	}
	if err := s.conn.UseDB(db); err != nil {
		return s.fail(ctx, err)
	}
	return nil
}

// Run executes one classified statement inside a transaction: READ ONLY
// for the read class, a plain one rolled back on error for the others.
func (s *session) Run(ctx context.Context, db string, st sqlclass.Statement, maxRows int) (engine.Result, error) {
	if int(st.Class) > int(s.tier) {
		return engine.Result{}, fmt.Errorf("mysql: a %s statement exceeds tier %s", st.Class, s.tier)
	}
	if err := lexSingle(st.SQL); err != nil {
		return engine.Result{}, err
	}
	begin := "START TRANSACTION"
	if st.Class == sqlclass.Read {
		begin = readOnlyTx
	}
	res, err := s.inTx(ctx, db, begin, func() (engine.Result, error) {
		r, err := s.stream(st.SQL, maxRows)
		if err == nil {
			s.trustOrigins(st.SQL, r.Columns)
		}
		return r, err
	}, true)
	if err != nil {
		return engine.Result{}, err
	}
	if st.Class != sqlclass.Write {
		res.Affected = 0
	}
	return res, nil
}

// inTx runs fn between begin and COMMIT (ROLLBACK when commit is false or
// on error), under the statement timeout and the KILL watcher.
func (s *session) inTx(ctx context.Context, db, begin string, fn func() (engine.Result, error), commit bool) (engine.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead.Load() {
		return engine.Result{}, s.lost(nil)
	}
	if err := ctx.Err(); err != nil {
		return engine.Result{}, s.fail(ctx, err)
	}
	if err := s.useDB(ctx, db); err != nil {
		return engine.Result{}, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	stop := s.watch(ctx)
	if _, err := s.conn.Execute(begin); err != nil {
		stop()
		return engine.Result{}, s.fail(ctx, err)
	}
	start := time.Now()
	res, err := fn()
	stop()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	// MySQL answers a SLEEP() stopped by max_execution_time with a value
	// and no error: a read that ran for the whole timeout is reported as
	// interrupted whatever the server said. (Not a write: DDL commits
	// implicitly, so its outcome must not be reported wrongly.)
	if err == nil && begin == readOnlyTx && s.timeout > 0 && time.Since(start) >= s.timeout {
		_, _ = s.conn.Execute("ROLLBACK")
		return engine.Result{}, fmt.Errorf("%s: statement interrupted: timeout of %s reached: %w",
			s.flavor, s.timeout, context.DeadlineExceeded)
	}
	if err != nil || !commit {
		if _, rerr := s.conn.Execute("ROLLBACK"); rerr != nil && err == nil {
			err = rerr
		}
		if err != nil {
			return engine.Result{}, s.fail(ctx, err)
		}
		return res, nil
	}
	if _, err := s.conn.Execute("COMMIT"); err != nil {
		return engine.Result{}, s.fail(ctx, err)
	}
	return res, nil
}

// stream runs q and keeps at most maxRows rows (all when maxRows <= 0); the
// rest of the result is read and dropped, which leaves the connection in
// sync. Called with mu held.
func (s *session) stream(q string, maxRows int) (engine.Result, error) {
	var r gomysql.Result
	out := engine.Result{Rows: [][]any{}}
	err := s.conn.ExecuteSelectStreaming(q, &r, func(row []gomysql.FieldValue) error {
		if maxRows > 0 && len(out.Rows) >= maxRows {
			out.Truncated = true
			return nil
		}
		vals := make([]any, len(row))
		for i := range row {
			var f *gomysql.Field
			if i < len(r.Fields) {
				f = r.Fields[i]
			}
			vals[i] = value(row[i], f)
		}
		out.Rows = append(out.Rows, vals)
		return nil
	}, nil)
	if err != nil {
		return engine.Result{}, err
	}
	if r.Resultset != nil {
		out.Columns = make([]engine.ResultColumn, len(r.Fields))
		for i, f := range r.Fields {
			out.Columns[i] = column(f)
		}
	}
	if out.Columns == nil {
		out.Columns = []engine.ResultColumn{}
	}
	out.Affected = int64(min(r.AffectedRows, math.MaxInt64))
	return out, nil
}

// column is a result column with its origin when the server reports a
// table column (expressions have no OrgTable/OrgName).
func column(f *gomysql.Field) engine.ResultColumn {
	c := engine.ResultColumn{Label: string(f.Name)}
	if len(f.OrgTable) > 0 && len(f.OrgName) > 0 {
		c.OriginDB = string(f.Schema)
		c.OriginTable = string(f.OrgTable)
		c.OriginColumn = string(f.OrgName)
	}
	return c
}

// value converts a driver value: nil, int64 (uint64 above MaxInt64),
// float64, []byte for binary strings, string otherwise (including DECIMAL,
// dates and JSON, as the server spells them).
func value(v gomysql.FieldValue, f *gomysql.Field) any {
	switch v.Type {
	case gomysql.FieldValueTypeNull:
		return nil
	case gomysql.FieldValueTypeUnsigned:
		if u := v.AsUint64(); u <= math.MaxInt64 {
			return int64(u)
		} else {
			return u
		}
	case gomysql.FieldValueTypeSigned:
		return v.AsInt64()
	case gomysql.FieldValueTypeFloat:
		return v.AsFloat64()
	}
	b := bytes.Clone(v.AsString())
	if b == nil {
		b = []byte{}
	}
	if f != nil && isBinary(f) {
		return b
	}
	return string(b)
}

const binaryCharset = 63

func isBinary(f *gomysql.Field) bool {
	if f.Charset != binaryCharset {
		return false
	}
	switch f.Type {
	case gomysql.MYSQL_TYPE_TINY_BLOB, gomysql.MYSQL_TYPE_MEDIUM_BLOB, gomysql.MYSQL_TYPE_LONG_BLOB,
		gomysql.MYSQL_TYPE_BLOB, gomysql.MYSQL_TYPE_VAR_STRING, gomysql.MYSQL_TYPE_STRING,
		gomysql.MYSQL_TYPE_VARCHAR, gomysql.MYSQL_TYPE_BIT, gomysql.MYSQL_TYPE_GEOMETRY:
		return true
	}
	return false
}

// Explain runs EXPLAIN FORMAT=JSON inside a transaction that is always
// rolled back, since the optimiser may evaluate constant expressions. The
// transaction is READ ONLY for a read statement; the servers refuse to
// EXPLAIN a write in one, so a write gets a plain transaction (which tier
// read's SET SESSION TRANSACTION READ ONLY still makes read-only).
func (s *session) Explain(ctx context.Context, db, q string) (engine.Plan, error) {
	if err := lexSingle(q); err != nil {
		return engine.Plan{}, err
	}
	begin := "START TRANSACTION"
	if st, err := sqlclass.Classify(sqlclass.MySQL, q, 0); err == nil && st.Class == sqlclass.Read {
		begin = readOnlyTx
	}
	res, err := s.inTx(ctx, db, begin, func() (engine.Result, error) {
		return s.stream("EXPLAIN FORMAT=JSON "+q, 1)
	}, false)
	if err != nil {
		return engine.Plan{}, err
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) < 1 {
		return engine.Plan{}, errors.New("mysql: EXPLAIN returned no plan")
	}
	var raw []byte
	switch v := res.Rows[0][0].(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		return engine.Plan{}, errors.New("mysql: EXPLAIN returned no plan")
	}
	return ParsePlan(raw)
}

// untrustedWords make every origin of a statement untrusted: they bring in
// a derived table, a CTE, a table function or a compound select, whose
// columns MariaDB (and MySQL, for a materialised derived table) report
// under the alias the statement chose. That alias may also name a real
// base table, so the catalog check alone cannot catch it.
var untrustedWords = map[string]bool{
	"WITH": true, "TABLE": true, "VALUES": true, "JSON_TABLE": true, "LATERAL": true,
	"UNION": true, "INTERSECT": true, "EXCEPT": true,
}

// originsTrustable reports whether the result origins of q can be trusted
// at all: q holds at most one SELECT and none of untrustedWords. A
// statement that does not lex is never trusted.
func originsTrustable(q string) bool {
	toks, err := sqlclass.Lex(sqlclass.MySQL, q)
	if err != nil {
		return false
	}
	selects := 0
	for _, t := range toks {
		if t.Kind != sqlclass.TokWord {
			continue
		}
		if t.Text == "SELECT" {
			selects++
		}
		if selects > 1 || untrustedWords[t.Text] {
			return false
		}
	}
	return true
}

// trustOrigins blanks every origin that does not name a column of a base
// table: all of them when the statement's shape makes them untrusted (see
// originsTrustable), otherwise those whose table the catalog does not list
// as a base table with that column (a view, a temporary table). Masking then
// matches such a column by name and refuses renamed uses (pii.AliasViolation).
// It runs in the statement's own transaction; if the catalog cannot be read,
// every origin is blanked. Called with mu held.
func (s *session) trustOrigins(q string, cols []engine.ResultColumn) {
	type table struct{ db, name string }
	tables := map[table]map[string]bool{}
	for _, c := range cols {
		if c.HasOrigin() {
			tables[table{c.OriginDB, c.OriginTable}] = nil
		}
	}
	if len(tables) == 0 {
		return
	}
	trusted := originsTrustable(q)
	for t := range tables {
		if !trusted {
			break
		}
		names, err := s.baseColumns(t.db, t.name)
		if err != nil {
			trusted = false
			break
		}
		tables[t] = names
	}
	for i, c := range cols {
		if !c.HasOrigin() {
			continue
		}
		if trusted && tables[table{c.OriginDB, c.OriginTable}][strings.ToLower(c.OriginColumn)] {
			continue
		}
		cols[i].OriginDB, cols[i].OriginTable, cols[i].OriginColumn = "", "", ""
	}
}

// baseColumns returns the lower-cased column names of db.name when the
// catalog lists it as a base table, an empty set otherwise. Called with mu
// held, inside a transaction.
func (s *session) baseColumns(db, name string) (map[string]bool, error) {
	r, err := s.conn.Execute(`SELECT c.COLUMN_NAME FROM information_schema.TABLES t
		JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
		WHERE t.TABLE_SCHEMA = ? AND t.TABLE_NAME = ? AND t.TABLE_TYPE IN ('BASE TABLE', 'SYSTEM VERSIONED')`, db, name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := map[string]bool{}
	for _, row := range r.Values {
		out[strings.ToLower(str(value(row[0], r.Fields[0])))] = true
	}
	return out, nil
}
