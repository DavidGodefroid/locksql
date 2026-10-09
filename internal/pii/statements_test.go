package pii

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

func TestStatementTextRelation(t *testing.T) {
	for _, c := range []struct {
		d   sqlclass.Dialect
		rel string
	}{
		{sqlclass.Postgres, "pg_stat_statements"},
		{sqlclass.Postgres, "public.PG_STAT_ACTIVITY"},
		{sqlclass.Postgres, "Pg_Stat_Statements"},
		{sqlclass.MySQL, "pg_stat_statements"},
		{sqlclass.MySQL, "information_schema.PROCESSLIST"},
		{sqlclass.MySQL, "performance_schema.threads"},
		{sqlclass.MySQL, "performance_schema.events_statements_history_long"},
		{sqlclass.MySQL, "events_statements_summary_by_digest"},
		{sqlclass.MySQL, "sys.session"},
		{sqlclass.MySQL, "sys.x$statement_analysis"},
		{sqlclass.MySQL, "mysql.general_log"},
		{sqlclass.MySQL, "mysql.slow_log"},
	} {
		if !StatementTextRelation(c.d, c.rel) {
			t.Errorf("%s not recognised", c.rel)
		}
	}
	for _, c := range []struct {
		d   sqlclass.Dialect
		rel string
	}{
		{sqlclass.Postgres, "users"},
		{sqlclass.Postgres, "pg_stats_users"},
		{sqlclass.Postgres, "statements"},
		{sqlclass.Postgres, "sys.session"},
		{sqlclass.MySQL, "app.users"},
		{sqlclass.MySQL, "app.session"},
		{sqlclass.MySQL, "mysql.user"},
	} {
		if StatementTextRelation(c.d, c.rel) {
			t.Errorf("%s taken for a statement-text view", c.rel)
		}
	}
}

func TestStatsViolationStatementText(t *testing.T) {
	masked := Rules{Mask: []string{"app.users.email"}}
	for _, c := range []struct {
		d   sqlclass.Dialect
		sql string
	}{
		{sqlclass.Postgres, "INSERT INTO t SELECT query FROM pg_stat_statements"},
		{sqlclass.Postgres, "INSERT INTO t SELECT query FROM pg_stat_activity"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT INFO FROM information_schema.PROCESSLIST"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT SQL_TEXT FROM performance_schema.events_statements_history"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT SQL_TEXT FROM `performance_schema`.`events_statements_current`"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT DIGEST_TEXT FROM performance_schema.events_statements_summary_by_digest"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT PROCESSLIST_INFO FROM performance_schema.threads"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT current_statement FROM sys.session"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT query FROM sys.statement_analysis"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT argument FROM mysql.general_log"},
		{sqlclass.MySQL, "INSERT INTO notes(t) SELECT sql_text FROM mysql.slow_log"},
	} {
		st := sqlclass.Statement{SQL: c.sql}
		err := StatsViolation(st, masked, c.d)
		if err == nil || !strings.Contains(err.Error(), "text of past statements") {
			t.Errorf("%s: err = %v", c.sql, err)
		}
		// Without mask rules there is nothing to protect.
		if err := StatsViolation(st, Rules{}, c.d); err != nil {
			t.Errorf("%s without mask rules: %v", c.sql, err)
		}
	}
	// An ordinary table named like a column of those views passes.
	st := sqlclass.Statement{SQL: "INSERT INTO notes(t) SELECT info FROM app.session_log"}
	if err := StatsViolation(st, masked, sqlclass.MySQL); err != nil {
		t.Errorf("ordinary table refused: %v", err)
	}
}
