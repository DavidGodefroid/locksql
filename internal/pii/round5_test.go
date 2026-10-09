package pii

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Round 5: a write without RETURNING that copies a rule column into another
// column is refused too; the next plain read would return the copy under a
// trusted origin no rule matches.
func TestWriteCopiesRuleColumnRound5(t *testing.T) {
	r := Rules{Mask: []string{"*.big.email", "*.users.firstname"}}
	refused := []dsql{
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT id, upper(email) FROM big"},
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT id, email FROM big"},
		{sqlclass.Postgres, "INSERT INTO small SELECT * FROM big"},
		{sqlclass.Postgres, "INSERT INTO small TABLE big"},
		{sqlclass.Postgres, "UPDATE small SET label = email"},
		{sqlclass.Postgres, "UPDATE small s SET label = b.email FROM big b WHERE b.id = s.id"},
		{sqlclass.Postgres, "UPDATE small s SET label = b.row_to_json FROM big b WHERE b.id = s.id"},
		{sqlclass.Postgres, "UPDATE big SET status = email WHERE id < 3"},
		{sqlclass.Postgres, "UPDATE big SET status = upper(email) WHERE id < 3"},
		{sqlclass.Postgres, "UPDATE big SET email = lower(email), status = email WHERE id < 3"},
		{sqlclass.Postgres, "MERGE INTO small s USING big b ON b.id = s.id WHEN MATCHED THEN UPDATE SET label = b.email"},
		{sqlclass.Postgres, "WITH x AS (SELECT id, email FROM big) INSERT INTO small SELECT id, email FROM x"},
		{sqlclass.MySQL, "INSERT INTO small (id, label) SELECT id, email FROM big"},
		{sqlclass.MySQL, "REPLACE INTO small SELECT id, email FROM big"},
		{sqlclass.MySQL, "UPDATE small s JOIN big b ON b.id = s.id SET s.label = b.email"},
		{sqlclass.MySQL, "INSERT INTO small (id, label) VALUES (5, 'x') ON DUPLICATE KEY UPDATE label = (SELECT email FROM big LIMIT 1)"},
		{sqlclass.SQLite, "INSERT INTO small (id, label) SELECT id, firstname FROM users"},
		{sqlclass.SQLite, "UPDATE small SET label = (SELECT firstname FROM users LIMIT 1)"},
	}
	for _, c := range refused {
		if PlanCheck(classify(t, c), r, c.d, true) == nil {
			t.Errorf("accepted: %s", c.sql)
		}
	}
	allowed := []dsql{
		// A rule column may only be set to NULL or DEFAULT (planted_test.go).
		{sqlclass.Postgres, "UPDATE users SET firstname = NULL WHERE id = 1"},
		{sqlclass.Postgres, "INSERT INTO users (id, firstname) VALUES (1, NULL)"},
		{sqlclass.Postgres, "DELETE FROM big WHERE email LIKE '%x'"},
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT id, status FROM big WHERE email LIKE 'a%'"},
		{sqlclass.Postgres, "UPDATE small SET label = 'x' WHERE id IN (SELECT id FROM big WHERE email LIKE 'a%')"},
		{sqlclass.Postgres, "INSERT INTO small (id, label) SELECT id, status FROM big ON CONFLICT (id) DO NOTHING"},
		{sqlclass.MySQL, "UPDATE small s JOIN big b ON b.id = s.id SET s.label = b.status WHERE b.email LIKE 'a%'"},
		{sqlclass.SQLite, "INSERT INTO small (id, label) VALUES (1, 'x')"},
	}
	for _, c := range allowed {
		if err := PlanCheck(classify(t, c), r, c.d, true); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
}
