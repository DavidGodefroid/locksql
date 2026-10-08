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
			t.Fatalf("Classify(%s): %v", q, err)
		}
		if !s.OriginColumns() && pii.AliasViolation(st, rules, d) != nil {
			continue
		}
		r, err := s.Run(context.Background(), "app", st, 100)
		if err != nil {
			continue
		}
		if pii.NeedsAliasCheck(r, s.OriginColumns()) && pii.AliasViolation(st, rules, d) != nil {
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

// leakQueries are the adversarial review round 2 cases, written against the
// seeds (big.email under a rule, small(id, label)).
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
		)
	case sqlclass.Postgres:
		q = append(q,
			`SELECT email AS "emaİl" FROM big WHERE id < 3 UNION ALL SELECT 'x' LIMIT 3`,
			"SELECT label FROM small UNION SELECT * FROM (SELECT email FROM big WHERE id < 3) LIMIT 10",
			"WITH x AS (SELECT email FROM big) SELECT * FROM ((SELECT label FROM small) UNION SELECT email FROM big WHERE id < 3) b LIMIT 10",
		)
	}
	return q
}
