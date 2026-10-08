//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// yesIO approves every prompt.
type yesIO struct{ t *testing.T }

func (y yesIO) Println(string) {}
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
	log, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng := string(s.Flavor())
	p := config.Profile{Name: "it", Engine: eng, Host: "127.0.0.1", Tier: config.TierWrite, Credentials: config.CredentialsAsk,
		Limits: config.DefaultLimits(false), Detectors: []string{}}
	srv, err := console.NewServer(console.ServerConfig{
		Policy: config.NewPolicy(p, rules.Mask, rules.Allow), Root: t.TempDir(), Session: nopClose{s},
		DBUser: "it", Databases: []string{"app"}, Audit: log, IO: yesIO{t}, Version: "it",
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method string, params any) ipc.Response {
		raw, _ := json.Marshal(params)
		return srv.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
	}
	for _, q := range queries {
		resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		if resp.Error != nil {
			continue // refused
		}
		var pr ipc.PlanResult
		if err := json.Unmarshal(resp.Result, &pr); err != nil {
			t.Fatal(err)
		}
		resp = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		if resp.Error != nil {
			if strings.Contains(resp.Error.Message, "@example.com") {
				t.Errorf("%s: leaked in an error: %s", q, resp.Error.Message)
			}
			continue
		}
		if strings.Contains(string(resp.Result), "@example.com") {
			t.Errorf("%s: leaked %s", q, resp.Result)
		}
	}
}

// nopClose keeps the shared session open when a test server ends.
type nopClose struct{ engine.Session }

func (nopClose) Close() error { return nil }

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
