package pii

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// While mask rules exist, a write may store into a column under a rule only
// NULL or DEFAULT: any value the agent chose (a literal, an expression,
// another column) would be masked on the next read and handed back as a
// cell reference to a value the agent knows, which it could then look up
// without the k-anonymity check.
func TestWritePlantsValueRefused(t *testing.T) {
	r := Rules{Mask: []string{"*.users.email", "*.big.email"}}
	refused := []dsql{
		{sqlclass.MySQL, "UPDATE users SET email = 'victim@x.com' WHERE id = 1"},
		{sqlclass.MySQL, "INSERT INTO users (id, email) VALUES (99, 'victim@x.com')"},
		{sqlclass.MySQL, "UPDATE users SET email = note WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET email = CONCAT('vic', 'tim@x.com') WHERE id = 1"},
		{sqlclass.MySQL, "INSERT INTO users (id, email) SELECT 99, note FROM users WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET note = 'x', email = 'victim@x.com' WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET email = NULL || 'x' WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users u JOIN orders o ON o.user_id = u.id SET u.email = o.note"},
		{sqlclass.MySQL, "INSERT INTO users (id, email) VALUES (1, NULL), (2, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT INTO users (id, email) VALUES ROW(1, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT users (id, email) VALUES (1, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT INTO users PARTITION (p0) (id, email) VALUES (1, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT INTO users SET id = 1, email = 'victim@x.com'"},
		{sqlclass.MySQL, "INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE email = 'victim@x.com'"},
		{sqlclass.MySQL, "REPLACE INTO users (id, email) VALUES (1, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT INTO users VALUES (1, 'victim@x.com')"},
		{sqlclass.MySQL, "INSERT INTO users SELECT 1, 'victim@x.com'"},
		{sqlclass.Postgres, "UPDATE users SET (id, email) = (2, 'victim@x.com') WHERE id = 1"},
		{sqlclass.Postgres, "UPDATE users SET (id, email) = (SELECT 2, 'victim@x.com') WHERE id = 1"},
		{sqlclass.Postgres, "INSERT INTO users AS u (id, email) VALUES (1, 'victim@x.com')"},
		{sqlclass.Postgres, "INSERT INTO users (id, email) OVERRIDING SYSTEM VALUE VALUES (1, 'victim@x.com')"},
		{sqlclass.Postgres, "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET email = 'victim@x.com'"},
		{sqlclass.Postgres, "WITH x AS (UPDATE users SET email = 'victim@x.com' WHERE id = 1 RETURNING id) SELECT id FROM x LIMIT 5"},
		{sqlclass.Postgres, "UPDATE users SET email = 'victim@x.com' WHERE id = 1 RETURNING id"},
		{sqlclass.Postgres, "MERGE INTO users u USING small s ON s.id = u.id WHEN MATCHED THEN UPDATE SET email = 'victim@x.com'"},
		{sqlclass.Postgres, "MERGE INTO users u USING small s ON s.id = u.id WHEN NOT MATCHED THEN INSERT (id, email) VALUES (s.id, 'victim@x.com')"},
		{sqlclass.SQLite, "INSERT OR REPLACE INTO users (id, email) VALUES (1, 'victim@x.com')"},
		{sqlclass.SQLite, "UPDATE users SET email = 'victim@x.com' WHERE id = 1"},
	}
	for _, c := range refused {
		err := PlanCheck(classify(t, c), r, c.d, true)
		if err == nil {
			t.Errorf("accepted: %s", c.sql)
			continue
		}
		if strings.Contains(err.Error(), "victim") {
			t.Errorf("%s: refusal quotes the value: %v", c.sql, err)
		}
	}
	allowed := []dsql{
		{sqlclass.MySQL, "UPDATE users SET email = NULL WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET email = DEFAULT, note = 'x' WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET note = 'victim@x.com' WHERE id = 1"},
		{sqlclass.MySQL, "INSERT INTO users (id, email) VALUES (99, NULL), (100, DEFAULT)"},
		{sqlclass.MySQL, "INSERT INTO users (id, note) VALUES (99, 'x')"},
		{sqlclass.MySQL, "INSERT INTO users (id, note) SELECT id + 100, note FROM users WHERE id = 1"},
		{sqlclass.MySQL, "INSERT INTO users SET id = 1, email = NULL"},
		{sqlclass.MySQL, "UPDATE users SET note = INSERT(note, 1, 1, 'x') WHERE id = 1"},
		{sqlclass.MySQL, "UPDATE users SET note = REPLACE(note, 'a', 'b') WHERE id = 1"},
		{sqlclass.Postgres, "INSERT INTO users DEFAULT VALUES"},
		{sqlclass.Postgres, "UPDATE users SET (id, email) = (2, NULL) WHERE id = 1"},
		{sqlclass.Postgres, "UPDATE users SET email = NULL WHERE id = 1 RETURNING id"},
		{sqlclass.SQLite, "INSERT INTO small (id) VALUES (1)"},
	}
	for _, c := range allowed {
		if err := PlanCheck(classify(t, c), r, c.d, true); err != nil {
			t.Errorf("refused %s: %v", c.sql, err)
		}
	}
	// No rule: nothing to protect.
	if err := PlanCheck(classify(t, dsql{sqlclass.MySQL, "UPDATE users SET email = 'x' WHERE id = 1"}), Rules{}, sqlclass.MySQL, true); err != nil {
		t.Errorf("no rules: %v", err)
	}
}

// Copying a rule column into another rule column stays refused: by the copy
// rule of writtenValues for an INSERT source, by the SET check first for a
// SET list.
func TestWriteCopiesRuleColumnIntoRuleColumn(t *testing.T) {
	r := Rules{Mask: []string{"*.users.email", "*.big.email"}}
	for _, c := range []struct {
		dsql
		want string
	}{
		{dsql{sqlclass.MySQL, "INSERT INTO users (id, email) SELECT id + 100, email FROM big"}, "stores values of PII column"},
		{dsql{sqlclass.MySQL, "UPDATE users u JOIN big b ON b.id = u.id SET u.email = b.email"}, "a masked column cannot receive values the agent chose"},
	} {
		err := PlanCheck(classify(t, c.dsql), r, c.d, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.sql, err)
		}
	}
}
