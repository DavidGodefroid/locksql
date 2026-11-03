package sqlast

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Steering lists every column whose values steer the result without being
// returned as they are: a grant covers no read that steers on a column the
// detectors alone protect.
func TestSteering(t *testing.T) {
	for _, c := range []struct{ sql, want string }{
		{"SELECT id, name FROM users LIMIT 1", ""},
		{"SELECT * FROM users LIMIT 1", ""},
		{"SELECT id FROM users WHERE name = 'b' LIMIT 1", "app.users.name"},
		{"SELECT id FROM users WHERE name LIKE 'b%' LIMIT 1", "app.users.name"},
		{"SELECT id FROM users WHERE substr(name, 2, 1) = 'b' LIMIT 1", "app.users.name"},
		{"SELECT id FROM users ORDER BY name LIMIT 1", "app.users.name"},
		{"SELECT name FROM users ORDER BY 1 LIMIT 1", "app.users.name"},
		{"SELECT status, COUNT(*) FROM users GROUP BY status LIMIT 1", "app.users.status"},
		{"SELECT DISTINCT status FROM users LIMIT 1", "app.users.status"},
		{"SELECT upper(name) FROM users LIMIT 1", "app.users.name"},
		{"SELECT CASE WHEN name LIKE 'b%' THEN 1 ELSE 0 END FROM users LIMIT 1", "app.users.name"},
		{"SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id LIMIT 1", "app.orders.user_id,app.users.id"},
		{"SELECT id FROM (SELECT id, name AS n FROM users) d WHERE n = 'b' LIMIT 1", "app.users.name"},
		{"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 1) LIMIT 1", "app.orders.total,app.orders.user_id,app.users.id"},
		{"SELECT name FROM users UNION SELECT name FROM users LIMIT 1", "app.users.name"},
		{"SELECT name FROM users UNION ALL SELECT name FROM users LIMIT 1", ""},
	} {
		a, err := analyze(t, sqlclass.SQLite, c.sql)
		if err != nil {
			t.Fatalf("%s: %v", c.sql, err)
		}
		var got []string
		for _, s := range a.Steering {
			got = append(got, s.String())
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%s: steering %v, want %s", c.sql, got, c.want)
		}
	}
}
