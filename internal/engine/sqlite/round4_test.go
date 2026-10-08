package sqlite

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// A compound view reports the origin of one arm only, while its values come
// from every arm: origins that come through a view are never trusted.
func TestRunBlanksOriginsThroughViews(t *testing.T) {
	path := setupDB(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE VIEW v_all AS SELECT id, email AS who FROM big UNION ALL SELECT id, label FROM items`,
		`CREATE VIEW v_nested AS SELECT who FROM v_all`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s := connect(t, path, config.TierRead)
	for _, q := range []string{
		"SELECT who FROM v_all LIMIT 5",
		`SELECT v.who FROM "V_ALL" v LIMIT 5`,
		"SELECT who FROM v_nested LIMIT 5",
		"SELECT b.email, e.email FROM big b JOIN emails e ON e.id = b.id LIMIT 5",
	} {
		r, err := s.Run(context.Background(), "main", classify(t, q), 10)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for _, c := range r.Columns {
			if c.HasOrigin() {
				t.Errorf("%s: origin %+v", q, c)
			}
		}
	}
	r, err := s.Run(context.Background(), "main", classify(t, "SELECT email FROM big LIMIT 1"), 10)
	if err != nil || !r.Columns[0].HasOrigin() {
		t.Fatalf("base table origin lost: %+v %v", r.Columns, err)
	}
}
