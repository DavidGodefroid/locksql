//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// yesIO approves every prompt.
type yesIO struct{ t *testing.T }

// Println fails on a k-anonymity count the server rejects: the console
// only warns of it, and the bug would go unseen.
func (y yesIO) Println(s string) {
	if strings.Contains(s, "k-anonymity check failed") {
		y.t.Errorf("console: %s", s)
	}
}
func (y yesIO) Ask(context.Context, string, time.Duration) (string, bool) {
	return "y", true
}
func (y yesIO) AskSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("no secret")
}

// assertNoLeak runs each query through a console server, the way a client
// would (plan, approval, run, mask), and fails when an e-mail value of big
// comes out. A refusal by locksql or an error from the server both count
// as safe.
func assertNoLeak(t *testing.T, s engine.Session, d sqlclass.Dialect, rules pii.Rules, queries []string) {
	t.Helper()
	asAgent(t, s, "app", rules, queries, func(q string, run bool, answer string) {
		if run && strings.Contains(answer, "@example.com") { // a plan echoes the literals of q
			t.Errorf("%s: leaked %s", q, answer)
		}
	})
}

// asAgent runs each query through a console server, the way a client would
// (plan, approval, run, mask), and hands seen every answer the agent gets:
// the plan or its refusal (run false), then the result or the error of the
// run (run true). It fails on a k-anonymity check that cannot be planned
// (a refusal hiding a bug) or run (see yesIO.Println).
func asAgent(t *testing.T, s engine.Session, db string, rules pii.Rules, queries []string, seen func(q string, run bool, answer string)) {
	t.Helper()
	call := leakServer(t, s, db, rules)
	answer := func(r ipc.Response) string {
		if r.Error != nil {
			return r.Error.Message
		}
		return string(r.Result)
	}
	for _, q := range queries {
		resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: db, SQL: q})
		seen(q, false, answer(resp))
		if resp.Error != nil {
			if strings.Contains(resp.Error.Message, "k-anonymity check of this statement cannot be planned") {
				t.Errorf("%s: %s", q, resp.Error.Message) // a k-check the server rejects
			}
			continue // refused
		}
		var pr ipc.PlanResult
		if err := json.Unmarshal(resp.Result, &pr); err != nil {
			t.Fatal(err)
		}
		resp = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		seen(q, true, answer(resp))
	}
}

// assertWriteRowsMasked runs each write through a console server and
// requires that it is accepted, runs, and returns rows in which every
// e-mail of big is masked.
func assertWriteRowsMasked(t *testing.T, s engine.Session, rules pii.Rules, queries []string) {
	t.Helper()
	call := leakServer(t, s, "app", rules)
	for _, q := range queries {
		resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		if resp.Error != nil {
			t.Errorf("%s: refused: %s", q, resp.Error.Message)
			continue
		}
		var pr ipc.PlanResult
		if err := json.Unmarshal(resp.Result, &pr); err != nil {
			t.Fatal(err)
		}
		resp = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		if resp.Error != nil {
			t.Errorf("%s: run failed: %s", q, resp.Error.Message)
			continue
		}
		var rr ipc.RunResult
		if err := json.Unmarshal(resp.Result, &rr); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rr.Text, "@example.com") {
			t.Errorf("%s: leaked %s", q, rr.Text)
		}
		if !strings.Contains(rr.Text, "<redacted>") {
			t.Errorf("%s: no masked cell in %s", q, rr.Text)
		}
	}
}

// assertPlanRefused requires that locksql refuses each statement before
// it runs.
func assertPlanRefused(t *testing.T, s engine.Session, rules pii.Rules, queries []string) {
	t.Helper()
	call := leakServer(t, s, "app", rules)
	for _, q := range queries {
		if resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q}); resp.Error == nil {
			t.Errorf("%s: accepted", q)
		}
	}
}

// leakServer is a console server on s at tier write that approves every
// prompt; it returns the client call.
func leakServer(t *testing.T, s engine.Session, db string, rules pii.Rules) func(method string, params any) ipc.Response {
	t.Helper()
	return consoleServer(t, s, db, rules, config.TierWrite, []string{})
}

// consoleServer is leakServer at tier, with the value detectors named.
func consoleServer(t *testing.T, s engine.Session, db string, rules pii.Rules, tier config.Tier, detectors []string) func(method string, params any) ipc.Response {
	t.Helper()
	log, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng := string(s.Flavor())
	p := config.Profile{Name: "it", Engine: eng, Host: "127.0.0.1", Tier: tier, Credentials: config.CredentialsAsk,
		Limits: config.DefaultLimits(false), Detectors: detectors}
	srv, err := console.NewServer(console.ServerConfig{
		Policy: config.NewPolicy(p, rules.Mask, rules.Allow).WithModes(rules.Modes), RulesPath: filepath.Join(t.TempDir(), pii.RulesFile), Session: nopClose{s},
		DBUser: "it", Databases: []string{db}, Audit: log, IO: yesIO{t}, Version: "it",
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(method string, params any) ipc.Response {
		raw, _ := json.Marshal(params)
		return srv.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
	}
}

// nopClose keeps the shared session open when a test server ends.
type nopClose struct{ engine.Session }

func (nopClose) Close() error { return nil }

func (s nopClose) ShadowedFunctions(ctx context.Context, db string, names []string) ([]string, error) {
	return engine.ShadowedFunctions(ctx, s.Session, db, names)
}

func (s nopClose) ShadowedOperators(ctx context.Context, db string, names []string) ([]string, error) {
	return engine.ShadowedOperators(ctx, s.Session, db, names)
}

func (s nopClose) ObjectState(ctx context.Context, db string, refs engine.ObjectRefs) (engine.ObjectState, error) {
	return engine.ObjectStateOf(ctx, s.Session, db, refs)
}

func (s nopClose) RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs engine.ObjectRefs, check func(engine.ObjectState, bool) error) (engine.Result, error) {
	return engine.RunGuarded(ctx, s.Session, db, st, maxRows, refs, check)
}

// leakQueries are the adversarial review round 2 and 3 cases, written
// against the seeds (big.email under a rule, small(id, label)). Write cases
// change no data, or only rows they insert themselves; they need a write
// session (writeLeakQueries).
func leakQueries(d sqlclass.Dialect) []string {
	q := []string{
		"SELECT email AS emaİl FROM big WHERE id IN (SELECT id FROM small) ORDER BY id LIMIT 3",
		"SELECT small.*, big.email FROM small, big WHERE big.id = 1 UNION SELECT id, email, id FROM big WHERE id < 3 LIMIT 5",
		"SELECT * FROM (SELECT email FROM big WHERE id = 1) a CROSS JOIN ((SELECT id FROM small) UNION SELECT email FROM big WHERE id < 3) b LIMIT 10",
		// Provenance: aliases, CTEs, derived tables, set operations, scalar
		// subqueries and stars all resolve to big.email.
		"WITH c(x) AS (SELECT email FROM big) SELECT x AS id FROM c WHERE id IS NOT NULL LIMIT 3",
		"SELECT id FROM (SELECT email AS id FROM big) t LIMIT 3",
		"SELECT t.* FROM (SELECT b.* FROM big b) t LIMIT 3",
		"SELECT (SELECT max(email) FROM big) AS m FROM small LIMIT 1",
		"SELECT label FROM small UNION ALL SELECT email FROM big LIMIT 5",
		// Constant PII filters: the subject counts (quoted, qualified by the
		// catalog) must run on the server.
		"SELECT id FROM big WHERE email = 'x@example.com' LIMIT 3",
		"SELECT s.id FROM big b JOIN small s ON s.id = b.id WHERE b.email IN ('a@example.com', 'b@example.com') AND b.id > 0 LIMIT 3",
		"SELECT count(*) FROM big WHERE email IS NULL LIMIT 1",
		// Expressions and oracles over the PII column are refused.
		"SELECT concat(email, '') AS x FROM big LIMIT 3",
		"SELECT CASE WHEN email LIKE 'a%' THEN 1 ELSE 0 END AS f FROM big LIMIT 3",
		"SELECT id FROM big WHERE substr(email, 1, 1) = 'a' LIMIT 3",
		"SELECT id FROM big ORDER BY email LIMIT 3",
		"SELECT email AS id FROM big ORDER BY id LIMIT 3",
	}
	switch d {
	case sqlclass.MySQL:
		q = append(q,
			"SELECT emaİl FROM big WHERE id IN (SELECT id FROM small) ORDER BY id LIMIT 3",
			"SELECT émail FROM big WHERE id IN (SELECT id FROM small) ORDER BY id LIMIT 3",
			"SELECT email AS `emaİl` FROM big WHERE id < 3 UNION ALL SELECT 'x' LIMIT 3",
			// Round 3.
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT (SELECT * FROM c LIMIT 1) AS x LIMIT 5",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT (TABLE c LIMIT 1) AS x LIMIT 5",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT JSON_ARRAYAGG((SELECT * FROM c LIMIT 1)) AS x LIMIT 5",
		)
	case sqlclass.Postgres:
		q = append(q,
			`SELECT email AS "emaİl" FROM big WHERE id < 3 UNION ALL SELECT 'x' LIMIT 3`,
			"SELECT label FROM small UNION SELECT * FROM (SELECT email FROM big WHERE id < 3) LIMIT 10",
			"WITH x AS (SELECT email FROM big) SELECT * FROM ((SELECT label FROM small) UNION SELECT email FROM big WHERE id < 3) b LIMIT 10",
			// Round 3.
			"SELECT lower(email) AS delete FROM big LIMIT 3",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT (SELECT * FROM c LIMIT 1) || '' AS x LIMIT 5",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT ARRAY(TABLE c)::text AS x LIMIT 5",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT * FROM unnest(ARRAY(TABLE c)) LIMIT 5",
			"WITH c AS (SELECT email FROM big WHERE id < 3) SELECT label FROM small UNION SELECT (TABLE c LIMIT 1) LIMIT 5",
			"SELECT table_to_xml('big', true, false, '')::text LIMIT 5",
			"SELECT most_common_vals::text, histogram_bounds::text FROM pg_stats WHERE tablename = 'big' AND attname = 'email' LIMIT 5",
			// Round 4: attribute notation, rel.f is f(rel) on the whole row.
			"SELECT b.row_to_json FROM big b LIMIT 2",
			"SELECT big.record_out::text AS r FROM big LIMIT 2",
			"SELECT b.text FROM big b LIMIT 2",
			"SELECT b.id, b.name FROM big b LIMIT 2",
			"SELECT upper(b.text) AS u FROM big b LIMIT 2",
			"SELECT x.key, x.value FROM big b, json_each_text(b.row_to_json) x LIMIT 4",
		)
	}
	return q
}

// writeLeakQueries return rows from a write (RETURNING, data-modifying
// CTE). They change no seed data.
func writeLeakQueries(d sqlclass.Dialect) []string {
	switch d {
	case sqlclass.MySQL: // MariaDB only; MySQL refuses RETURNING
		return []string{
			"INSERT INTO big (status, email) VALUES ('t', 'ins1@example.com') RETURNING concat(email, '') AS x",
			"DELETE FROM big WHERE email = 'ins1@example.com' RETURNING concat(email, '') AS x",
			// Round 4.
			"INSERT INTO small (id, label) SELECT 3000 + id, email FROM big WHERE id < 3 RETURNING label",
		}
	case sqlclass.Postgres:
		return []string{
			"UPDATE big SET status = status WHERE id < 3 RETURNING lower(email)",
			"WITH d AS (DELETE FROM small WHERE false RETURNING 1) SELECT lower(email) AS x FROM big LIMIT 3",
			// Round 4.
			"UPDATE big SET id = id WHERE id < 3 RETURNING big.row_to_json",
			"INSERT INTO small (id, label) SELECT 1000 + id, substr(email, 1, 20) FROM big WHERE id < 3 RETURNING label",
			"UPDATE small SET label = (SELECT substr(email, 1, 20) FROM big WHERE big.id = small.id - 1000) WHERE id > 1000 RETURNING label",
			"WITH i AS (INSERT INTO small (id, label) SELECT 2000 + id, substr(email, 1, 20) FROM big WHERE id < 3 RETURNING label) SELECT label FROM i LIMIT 5",
		}
	}
	return nil
}

// writeMaskedQueries return rows from a write that rename or move big.email:
// the write analysis resolves them and masks the column. They change no
// seed data; the DELETE removes the row seedReturned inserts.
func writeMaskedQueries(d sqlclass.Dialect) []string {
	switch d {
	case sqlclass.MySQL: // MariaDB only
		return []string{
			"DELETE FROM big WHERE status = 'wret' RETURNING email AS x, id",
			"INSERT INTO small (id, label) VALUES (9001, 'z') RETURNING label, (SELECT email FROM big WHERE id = 1) AS e",
		}
	case sqlclass.Postgres:
		return []string{
			"UPDATE big SET status = status WHERE id < 3 RETURNING email AS x",
			"UPDATE big SET status = status WHERE id < 3 RETURNING id AS email, email AS id",
			"UPDATE big AS b SET status = b.status FROM small s WHERE s.id = b.id RETURNING *",
			"DELETE FROM small s USING big b WHERE b.id = 1 AND s.id = 9002 RETURNING b.email, s.id",
			"UPDATE small SET label = label WHERE id = 1 RETURNING (SELECT email FROM big WHERE id = 1) AS e",
			"WITH u AS (UPDATE big SET status = status WHERE id < 3 RETURNING email AS e) SELECT e AS z FROM u",
			"WITH d AS (DELETE FROM small WHERE false RETURNING 1) SELECT email AS x FROM big WHERE id < 3 LIMIT 3",
			"DELETE FROM big WHERE status = 'wret' RETURNING email AS x",
		}
	}
	return nil
}

// writeRefusedQueries copy big.email into another column or transform it
// on its way out.
func writeRefusedQueries(d sqlclass.Dialect) []string {
	switch d {
	case sqlclass.MySQL:
		return []string{
			"INSERT INTO small (id, label) SELECT id + 7000, x FROM (SELECT id, email AS x FROM big) d WHERE id < 3",
			"INSERT INTO small (id, label) SELECT id + 7000, x FROM (SELECT id, email AS x FROM big) d WHERE id < 3 RETURNING label",
			"DELETE FROM big WHERE status = 'wret' RETURNING concat(email, '') AS x",
		}
	case sqlclass.Postgres:
		return []string{
			"INSERT INTO small (id, label) SELECT i + 7000, x FROM big AS b(i, s, x, c) WHERE i < 3",
			"WITH s(a, b) AS (SELECT id, email FROM big) INSERT INTO small SELECT a + 7000, b FROM s WHERE a < 3",
			"UPDATE big SET status = status WHERE id < 3 RETURNING email || ''",
			"WITH u AS (UPDATE big SET status = status WHERE id < 3 RETURNING email AS e) SELECT lower(e) FROM u",
			"WITH u AS (UPDATE big SET status = status WHERE id < 3 RETURNING email AS e) SELECT e FROM u ORDER BY e",
		}
	}
	return nil
}

// seedReturned inserts the row the write tests delete, and the cleanup of
// what they may leave.
func seedReturned(t *testing.T, s engine.Session) {
	t.Helper()
	run := func(q string) {
		st := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert", SQL: q, Limit: -1}
		if _, err := s.Run(context.Background(), "app", st, 10); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	run("INSERT INTO big (status, email) VALUES ('wret', 'wret@example.com')")
	run("INSERT INTO small (id, label) VALUES (9002, 'y')")
	t.Cleanup(func() {
		run("DELETE FROM big WHERE status = 'wret'")
		run("DELETE FROM small WHERE id > 3")
	})
}
