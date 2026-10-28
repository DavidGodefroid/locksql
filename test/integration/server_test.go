//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Server-side behaviour: what the server would do with a statement or a
// value that locksql must stop or cut first.

// agentRun plans and runs q through call, as an agent would: the error
// message of the plan or of the run, or the result.
func agentRun(t *testing.T, call func(string, any) ipc.Response, db, q string) (ipc.RunResult, string) {
	t.Helper()
	resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: db, SQL: q})
	if resp.Error != nil {
		return ipc.RunResult{}, "plan: " + resp.Error.Message
	}
	var pr ipc.PlanResult
	if err := json.Unmarshal(resp.Result, &pr); err != nil {
		t.Fatal(err)
	}
	resp = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if resp.Error != nil {
		return ipc.RunResult{}, "run: " + resp.Error.Message
	}
	var rr ipc.RunResult
	if err := json.Unmarshal(resp.Result, &rr); err != nil {
		t.Fatal(err)
	}
	return rr, ""
}

// fileExists reports whether path exists inside the container.
func fileExists(srv Server, path string) bool {
	return Exec(srv, "", "test", "-e", path) == nil
}

// TestMySQLIntoOutfile: rw holds FILE (ALL PRIVILEGES ON *.*) and the
// console runs at tier admin, the most a profile allows; INTO OUTFILE and
// INTO DUMPFILE are still refused before the server, which would write the
// file if they reached it.
func TestMySQLIntoOutfile(t *testing.T) {
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) {
			srv := startMySQL(t, m)
			s := connectMySQL(t, m, srv, "rw", config.TierAdmin, 10*time.Second)
			show := sqlclass.Statement{Class: sqlclass.Admin, Kind: "show", SQL: "SHOW VARIABLES LIKE 'secure_file_priv'", Limit: -1}
			r, err := s.Run(context.Background(), "app", show, 10)
			if err != nil || len(r.Rows) != 1 {
				t.Fatalf("secure_file_priv: %v %v", r.Rows, err)
			}
			if v := r.Rows[0][1]; v == nil || fmt.Sprint(v) == "NULL" {
				t.Skip("secure_file_priv is NULL: the server writes no file")
			}
			dir := fmt.Sprint(r.Rows[0][1])
			if dir == "" {
				dir = "/tmp/"
			}
			dir = strings.TrimSuffix(dir, "/") + "/"
			tag := fmt.Sprintf("ls-it-%d-%d", os.Getpid(), time.Now().UnixNano())

			// Control: sent directly, the statement writes the file.
			control := dir + tag + "-control.txt"
			st := sqlclass.Statement{Class: sqlclass.Admin, Kind: "select", SQL: "SELECT label FROM small INTO OUTFILE '" + control + "'", Limit: -1}
			if _, err := s.Run(context.Background(), "app", st, 10); err != nil {
				t.Fatalf("control INTO OUTFILE: %v", err)
			}
			if !fileExists(srv, control) {
				t.Fatalf("control: %s not written; the test proves nothing", control)
			}

			call := consoleServer(t, s, "app", pii.Rules{}, config.TierAdmin, []string{})
			for _, c := range []struct{ into, file string }{
				{"OUTFILE", dir + tag + "-outfile.txt"},
				{"DUMPFILE", dir + tag + "-dumpfile.bin"},
				{"outfile", dir + tag + "-lower.txt"},
			} {
				q := "SELECT label FROM small LIMIT 1 INTO " + c.into + " '" + c.file + "'"
				_, msg := agentRun(t, call, "app", q)
				if !strings.HasPrefix(msg, "plan: ") || !strings.Contains(strings.ToUpper(msg), "INTO "+strings.ToUpper(c.into)) {
					t.Errorf("%s: not refused at plan: %q", q, msg)
				}
				if fileExists(srv, c.file) {
					t.Errorf("%s: %s exists in the container", q, c.file)
				}
			}
		})
	}
}

// TestMariaDBSequenceReadOnly: NEXTVAL, NEXT VALUE FOR and SETVAL are
// refused by the classifier in a read, and, sent anyway, by MariaDB inside
// START TRANSACTION READ ONLY (error 1792): the sequence does not move.
func TestMariaDBSequenceReadOnly(t *testing.T) {
	for _, m := range mysqlTargets() {
		if m.flavor != engine.FlavorMariaDB {
			continue
		}
		t.Run(m.image(), func(t *testing.T) {
			ctx := context.Background()
			srv := startMySQL(t, m)
			admin := connectMySQL(t, m, srv, "rw", config.TierDDL, 10*time.Second)
			ddl := func(q string) {
				t.Helper()
				if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}, 0); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			ddl("CREATE SEQUENCE seq_it START WITH 1 NOCACHE")
			t.Cleanup(func() { ddl("DROP SEQUENCE IF EXISTS seq_it") })
			next := func() string {
				t.Helper()
				return fmt.Sprint(mustRun(t, admin, "SELECT next_not_cached_value FROM seq_it").Rows[0][0])
			}

			s := connectMySQL(t, m, srv, "rw", config.TierRead, 10*time.Second)
			call := consoleServer(t, s, "app", pii.Rules{}, config.TierRead, []string{})
			for _, q := range []string{
				"SELECT NEXTVAL(seq_it)",
				"SELECT nextval(app.seq_it)",
				"SELECT NEXT VALUE FOR seq_it",
				"SELECT SETVAL(seq_it, 100)",
				"SELECT id, NEXTVAL(seq_it) FROM small",
			} {
				if _, msg := agentRun(t, call, "app", q); !strings.HasPrefix(msg, "plan: ") || !strings.Contains(msg, "sequence") {
					t.Errorf("%s: not refused at plan: %q", q, msg)
				}
			}
			if v := next(); v != "1" {
				t.Fatalf("after the refusals the sequence moved: next = %s", v)
			}

			// A classifier bypass, simulated: the read-only transaction
			// refuses it too.
			for _, q := range []string{"SELECT NEXTVAL(seq_it)", "SELECT NEXT VALUE FOR seq_it", "SELECT SETVAL(seq_it, 100)"} {
				if _, err := s.Run(ctx, "app", read(q), 10); err == nil || !strings.Contains(strings.ToUpper(err.Error()), "READ ONLY") {
					t.Errorf("%s in a read-only transaction: err = %v", q, err)
				}
			}
			if v := next(); v != "1" {
				t.Errorf("the read-only transaction let the sequence move: next = %s", v)
			}
		})
	}
}

// seedHugeCell creates table hugecell, readable by ro, holding a 1 MiB
// text cell with an e-mail address after offset 70 000, past the engine
// cap (engine.MaxCellBytes), and a second cell with one at 60 000, inside
// the detectors' scan window but past max_cell_chars. The classifier caps
// REPEAT, so the server builds them in an INSERT.
func seedHugeCell(t *testing.T, admin engine.Session, d sqlclass.Dialect) {
	t.Helper()
	ctx := context.Background()
	run := func(class sqlclass.Class, q string) {
		t.Helper()
		if _, err := admin.Run(ctx, "app", sqlclass.Statement{Class: class, Kind: "x", SQL: q, Limit: -1}, 0); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const size = 1 << 20
	far, near := "far.leak@example.com", "near.leak@example.com"
	cell := func(at int, email string) string {
		if d == sqlclass.Postgres {
			return fmt.Sprintf("repeat('x', %d) || ' %s ' || repeat('y', %d)", at, email, size-at-len(email)-2)
		}
		return fmt.Sprintf("CONCAT(REPEAT('x', %d), ' %s ', REPEAT('y', %d))", at, email, size-at-len(email)-2)
	}
	text := "LONGTEXT"
	if d == sqlclass.Postgres {
		text = "text"
	}
	run(sqlclass.DDL, "CREATE TABLE hugecell (id int PRIMARY KEY, far "+text+", near "+text+")")
	t.Cleanup(func() { run(sqlclass.DDL, "DROP TABLE hugecell") })
	if d == sqlclass.Postgres {
		run(sqlclass.Admin, "GRANT SELECT ON hugecell TO ro")
	}
	run(sqlclass.Write, "INSERT INTO hugecell VALUES (1, "+cell(70000, far)+", "+cell(60000, near)+")")
}

// assertHugeCell reads hugecell on s and through a console server with the
// default detectors: the engine keeps at most MaxCellBytes of each cell,
// and the agent gets a cut cell and no e-mail address.
func assertHugeCell(t *testing.T, s engine.Session) {
	t.Helper()
	const q = "SELECT far, near FROM hugecell LIMIT 1"
	res, err := s.Run(context.Background(), "app", read(q), 10)
	if err != nil {
		t.Fatal(err)
	}
	if v := fmt.Sprint(res.Rows[0][0]); len(v) > engine.MaxCellBytes || !res.IsCut(0, 0) || strings.Contains(v, "@") {
		t.Errorf("engine: far cell of %d bytes, cut %v, e-mail kept %v", len(v), res.IsCut(0, 0), strings.Contains(v, "@"))
	}
	if v := fmt.Sprint(res.Rows[0][1]); !strings.Contains(v, "near.leak@example.com") {
		t.Errorf("engine: near cell lost its e-mail within the cap (%d bytes)", len(v))
	}

	call := consoleServer(t, s, "app", pii.Rules{}, config.TierRead, config.DefaultDetectors())
	rr, msg := agentRun(t, call, "app", q)
	if msg != "" {
		t.Fatal(msg)
	}
	all := fmt.Sprint(rr.Rows) + rr.Text
	if strings.Contains(all, "@") || strings.Contains(all, "leak") {
		t.Errorf("agent got an e-mail: %.400s", all)
	}
	if len(rr.Rows) != 1 || !strings.HasSuffix(fmt.Sprint(rr.Rows[0][0]), engine.CutMark) || rr.CutCells == 0 {
		t.Errorf("far cell not cut: cut_cells %d, %.300v", rr.CutCells, rr.Rows)
	}
	if limit := config.DefaultLimits(false).MaxCellChars; len([]rune(fmt.Sprint(rr.Rows[0][0]))) > limit+1 {
		t.Errorf("far cell longer than max_cell_chars %d", limit)
	}
}

func TestHugeCellNoEmail(t *testing.T) {
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) {
			srv := startMySQL(t, m)
			seedHugeCell(t, connectMySQL(t, m, srv, "rw", config.TierAdmin, 30*time.Second), sqlclass.MySQL)
			assertHugeCell(t, connectMySQL(t, m, srv, "ro", config.TierRead, 30*time.Second))
		})
	}
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			seedHugeCell(t, connectPG(t, srv, "postgres", config.TierAdmin, 30*time.Second), sqlclass.Postgres)
			assertHugeCell(t, connectPG(t, srv, "ro", config.TierRead, 30*time.Second))
		})
	}
}

// startPostgresAuth starts a server whose pg_hba asks md5u for an MD5 hash
// and pwu for its password in clear (password_encryption = md5), and
// scramu for SCRAM.
func startPostgresAuth(t *testing.T, version string) Server {
	env := []string{"POSTGRES_PASSWORD=" + RootPassword, "POSTGRES_DB=app"}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%d user=postgres password=%s dbname=app sslmode=disable",
			host, port, RootPassword))
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return c.Ping(ctx)
	}
	return StartVariant(t, "auth", "postgres:"+version, 5432, env, nil, nil, ready, func(s Server) error {
		if err := Exec(s, "", "sh", "-c", `sed -i -e '1i host all md5u all md5' -e '1i host all pwu all password' "$PGDATA/pg_hba.conf"`); err != nil {
			return err
		}
		return Exec(s, `SET password_encryption = 'md5';
CREATE ROLE md5u LOGIN PASSWORD '`+ROPassword+`';
CREATE ROLE pwu LOGIN PASSWORD '`+ROPassword+`';
SET password_encryption = 'scram-sha-256';
CREATE ROLE scramu LOGIN PASSWORD '`+ROPassword+`';
SELECT pg_reload_conf();
`, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app")
	})
}

// TestPostgresPasswordAuth records the guard on a server that asks for the
// password in clear text or MD5-hashed: answered on a loopback host,
// refused on a remote host without a verified certificate (the server
// has no TLS: tls disable, prefer or unset); a SCRAM account logs in on both.
func TestPostgresPasswordAuth(t *testing.T) {
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgresAuth(t, v)
			for _, user := range []string{"md5u", "pwu", "scramu"} {
				local := config.Profile{Engine: config.EnginePostgres, Host: srv.Host, Port: srv.Port, User: user, Database: "app"}
				if _, err := tlsConnect(t, local, ROPassword, nil); err != nil {
					t.Errorf("%s on loopback: %v", user, err)
				}
				for _, mode := range []string{"", config.TLSDisable, config.TLSPrefer} {
					remote := local
					remote.Host, remote.Port, remote.TLS = tlsServerName, 5432, mode
					_, err := tlsConnect(t, remote, ROPassword, remoteDial(srv))
					switch {
					case user == "scramu" && err != nil:
						t.Errorf("%s remote, tls %q: %v", user, mode, err)
					case user != "scramu" && (err == nil || !strings.Contains(err.Error(), "clear text or MD5-hashed")):
						t.Errorf("%s remote, tls %q: err = %v, want the password guard", user, mode, err)
					case err != nil && strings.Contains(err.Error(), ROPassword):
						t.Errorf("%s remote, tls %q: the error echoes the password", user, mode)
					}
				}
			}
		})
	}
}

// TestDetectorsUnicodeAndFloatPG reads, through a console server with the
// default detectors, the issue #17 cells as PostgreSQL returns them: a card
// number in a float8 column, a Unicode e-mail address and NBSP-grouped
// numbers. The agent sees none of them.
func TestDetectorsUnicodeAndFloatPG(t *testing.T) {
	const q = "SELECT 4111111111111111::float8 AS f, 'josé.dupont@exämple.de' AS e," +
		" E'BE68\\u00a05390\\u00a00754\\u00a07034' AS i, E'0475\\u202f12\\u202f34\\u202f56' AS p, 1.5::float8 AS h LIMIT 1"
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			s := connectPG(t, srv, "ro", config.TierRead, 30*time.Second)
			call := consoleServer(t, s, "app", pii.Rules{}, config.TierRead, config.DefaultDetectors())
			rr, msg := agentRun(t, call, "app", q)
			if msg != "" {
				t.Fatal(msg)
			}
			all := fmt.Sprint(rr.Rows) + rr.Text
			for _, leak := range []string{"4111111111111111", "4.111111111111111e+15", "dupont", "exämple", "7034", "12\u202f34\u202f56", "34\u202f56"} {
				if strings.Contains(all, leak) {
					t.Errorf("agent got %q: %.400s", leak, all)
				}
			}
			if !strings.Contains(all, "1.5") {
				t.Errorf("a non-integral float was masked: %.400s", all)
			}
		})
	}
}

// TestShadowedFunctionPG creates public.lower(varchar), which PostgreSQL
// picks over pg_catalog.lower(text) for a varchar argument: a read that
// calls lower is refused before it runs, and lower stays usable once the
// overload is gone.
func TestShadowedFunctionPG(t *testing.T) {
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			psql := func(sql string) {
				t.Helper()
				if err := Exec(srv, sql, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app"); err != nil {
					t.Fatal(err)
				}
			}
			psql(`CREATE FUNCTION public.lower(varchar) RETURNS text LANGUAGE sql AS 'SELECT ''overload''';`)
			s := connectPG(t, srv, "ro", config.TierRead, 30*time.Second)
			fs, ok := s.(engine.FunctionShadows)
			if !ok {
				t.Fatal("the PostgreSQL session does not implement engine.FunctionShadows")
			}
			got, err := fs.ShadowedFunctions(context.Background(), "app", []string{"lower", "upper"})
			if err != nil || len(got) != 1 || got[0] != "lower" {
				t.Fatalf("ShadowedFunctions = %v, %v; want [lower]", got, err)
			}
			call := consoleServer(t, s, "app", pii.Rules{}, config.TierRead, nil)
			const q = "SELECT lower('X'::varchar) AS x LIMIT 1"
			if _, msg := agentRun(t, call, "app", q); !strings.Contains(msg, "outside pg_catalog") {
				t.Fatalf("plan of %q: %q, want a refusal naming pg_catalog", q, msg)
			}
			psql(`DROP FUNCTION public.lower(varchar);`)
			rr, msg := agentRun(t, call, "app", q)
			if msg != "" || !strings.Contains(fmt.Sprint(rr.Rows), "x") {
				t.Fatalf("after DROP: %v %q", rr.Rows, msg)
			}

			// A quoted name is another function in PostgreSQL ("LOWER" is
			// not lower): refused whatever the catalog holds.
			psql(`CREATE FUNCTION public."LOWER"(text) RETURNS text LANGUAGE sql AS 'SELECT ''overload''';`)
			if _, msg := agentRun(t, call, "app", `SELECT "LOWER"('x') AS x LIMIT 1`); msg == "" {
				t.Fatal(`"LOWER"('x') was planned`)
			}

			// Operators resolve like functions: public.||(varchar, varchar)
			// beats pg_catalog.||(text, text).
			psql(`CREATE FUNCTION public.cat(varchar, varchar) RETURNS text LANGUAGE sql AS 'SELECT ''overload''';
				CREATE OPERATOR public.|| (LEFTARG = varchar, RIGHTARG = varchar, FUNCTION = public.cat);`)
			ops, err := fs.ShadowedOperators(context.Background(), "app", []string{"||", "+"})
			if err != nil || len(ops) != 1 || ops[0] != "||" {
				t.Fatalf("ShadowedOperators = %v, %v; want [||]", ops, err)
			}
			const cq = "SELECT 'a'::varchar || 'b'::varchar AS x LIMIT 1"
			if _, msg := agentRun(t, call, "app", cq); !strings.Contains(msg, "operator ||") {
				t.Fatalf("plan of %q: %q, want a refusal naming operator ||", cq, msg)
			}
			psql(`DROP OPERATOR public.|| (varchar, varchar);`)
			if rr, msg := agentRun(t, call, "app", cq); msg != "" || !strings.Contains(fmt.Sprint(rr.Rows), "ab") {
				t.Fatalf("after DROP OPERATOR: %v %q", rr.Rows, msg)
			}
		})
	}
}
