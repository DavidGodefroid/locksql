package pii

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func TestStatementTextRelation(t *testing.T) {
	for _, n := range []string{"pg_stat_statements", "PG_STAT_ACTIVITY", "Pg_Stat_Statements"} {
		if !StatementTextRelation(n) {
			t.Errorf("%s not recognised", n)
		}
	}
	for _, n := range []string{"users", "pg_stats_users", "statements"} {
		if StatementTextRelation(n) {
			t.Errorf("%s taken for a statement-text view", n)
		}
	}
}

func TestStatsViolationStatementText(t *testing.T) {
	r := Rules{Mask: []string{"app.users.email"}}
	st := sqlclass.Statement{SQL: "INSERT INTO t SELECT query FROM pg_stat_statements"}
	err := StatsViolation(st, r, sqlclass.Postgres)
	if err == nil || !strings.Contains(err.Error(), "text of past statements") {
		t.Fatalf("err = %v", err)
	}
}
