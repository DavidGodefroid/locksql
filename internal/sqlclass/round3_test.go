package sqlclass

import "testing"

func TestRound3Classify(t *testing.T) {
	cases := []struct {
		d     Dialect
		sql   string
		class Class
	}{
		// DELETE as a name does not make a read WRITE.
		{Postgres, "SELECT upper(email) AS delete FROM big LIMIT 3", Read},
		{Postgres, "SELECT t.delete FROM t LIMIT 3", Read},
		{Postgres, "SELECT delete, id FROM t LIMIT 3", Read},
		// A real DELETE still does.
		{Postgres, "WITH d AS (DELETE FROM small RETURNING 1) SELECT 1 LIMIT 1", Write},
		{SQLite, "WITH d AS (SELECT 1) DELETE FROM small", Write},
		{MySQL, "WITH d AS (SELECT 1) DELETE t FROM t JOIN d", Write},
		{MySQL, "WITH d AS (SELECT 1) DELETE IGNORE FROM t", Write},
	}
	for _, c := range cases {
		st, err := Classify(c.d, c.sql, 0)
		if err != nil {
			t.Fatalf("Classify(%q): %v", c.sql, err)
		}
		if st.Class != c.class {
			t.Errorf("%s: class %v, want %v", c.sql, st.Class, c.class)
		}
	}
	for _, q := range []string{
		"SELECT table_to_xml('users', true, false, '') LIMIT 5",
		"SELECT table_to_xml_and_xmlschema('users', true, false, '') LIMIT 5",
		"SELECT schema_to_xml('public', true, false, '') LIMIT 5",
		"SELECT database_to_xml(true, false, '') LIMIT 5",
		"SELECT cursor_to_xml('c', 1, true, false, '') LIMIT 5",
	} {
		if _, err := Classify(Postgres, q, 0); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
}
