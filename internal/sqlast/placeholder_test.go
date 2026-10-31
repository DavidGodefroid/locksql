package sqlast

import (
	"errors"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// Placeholders and cell references are not supported: wherever they sit,
// well-formed or not, masked or unmasked, the analysis refuses them with
// E_PLACEHOLDER and the not-supported reason, before any value could be
// looked up.
func TestPlaceholderRefused(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM users WHERE email = '${email}' LIMIT 1",
		"SELECT id FROM users WHERE email IN ('${e}', 'a') LIMIT 1",
		"SELECT id FROM users WHERE email IN ('${r1.1.2}', '${r1.2.2}') LIMIT 1",
		"SELECT id FROM users WHERE email = '${r1.1.2}' LIMIT 1",
		"SELECT id FROM users WHERE email = '${Email}' LIMIT 1",
		"SELECT '${email}' AS x FROM users LIMIT 1",
		"SELECT id FROM users WHERE id = '${email}' LIMIT 1",
		"SELECT id FROM users u JOIN orders o ON o.user_id = u.id AND u.email = '${email}' LIMIT 1",
		"SELECT id FROM users WHERE email = E'${email}' LIMIT 1",
		"SELECT $$${email}$$ AS x FROM users LIMIT 1",
	} {
		for _, masking := range []bool{true, false} {
			st, err := Parse(sqlclass.Postgres, sql)
			if err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
			_, err = Analyze(st, testEnv(masking))
			var r *sqlclass.Refusal
			if !errors.As(err, &r) || r.Code != refusal.Placeholder || r.Reason != PlaceholderRefusal {
				t.Errorf("%q (masking %v): err = %v, want %s %q", sql, masking, err, refusal.Placeholder, PlaceholderRefusal)
			}
		}
	}
}

func TestHasPlaceholder(t *testing.T) {
	for _, c := range []struct {
		d    sqlclass.Dialect
		sql  string
		want bool
	}{
		{sqlclass.MySQL, "UPDATE users SET email = '${email}' WHERE id = 7", true},
		{sqlclass.MySQL, "DELETE FROM users WHERE email = '${r1.1.2}'", true},
		{sqlclass.MySQL, "UPDATE users SET email = '${bad name}'", true},
		{sqlclass.MySQL, `INSERT INTO users (email) VALUES ("${email}")`, true},
		{sqlclass.Postgres, "INSERT INTO users (email) VALUES (E'${email}')", true},
		{sqlclass.Postgres, "INSERT INTO users (email) VALUES ($$${email}$$)", true},
		{sqlclass.MySQL, "UPDATE users SET note = 'cost: ${x}' WHERE id = 1", false},
		{sqlclass.MySQL, "UPDATE `${email}` SET note = 'x'", false},
		// Comments do not lex: reported as holding one (fail closed).
		{sqlclass.MySQL, "UPDATE users SET note = 'x' -- c", true},
	} {
		if got := HasPlaceholder(c.d, c.sql); got != c.want {
			t.Errorf("%s: got %v", c.sql, got)
		}
	}
}
