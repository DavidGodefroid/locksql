//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// assertNoLeak runs each query the way the console does (classify, alias
// check when needed, run, mask) and fails when an e-mail value of big comes
// out. A refusal by locksql or an error from the server both count as safe.
func assertNoLeak(t *testing.T, s engine.Session, d sqlclass.Dialect, rules pii.Rules, queries []string) {
	t.Helper()
	for _, q := range queries {
		st, err := sqlclass.Classify(d, q, 200)
		if err != nil {
			continue // refused
		}
		if pii.PlanCheck(st, rules, d, s.OriginColumns()) != nil {
			continue
		}
		r, err := s.Run(context.Background(), "app", st, 100)
		if err != nil {
			continue
		}
		if pii.NeedsAliasCheck(r, s.OriginColumns()) && pii.ResultAliasViolation(st, rules, d, r.Columns) != nil {
			continue
		}
		pii.MaskResult(&r, rules, nil, s.OriginColumns())
		for _, row := range r.Rows {
			for _, v := range row {
				if strings.Contains(fmt.Sprint(v), "@example.com") {
					t.Errorf("%s: leaked %v (columns %+v)", q, v, r.Columns)
				}
			}
		}
	}
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
