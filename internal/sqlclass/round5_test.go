package sqlclass

import "testing"

// SQLite virtual tables that expose raw pages or storage details are refused
// in every form: they return stored values under labels no mask rule matches.
func TestRound5SQLiteRawStorageTables(t *testing.T) {
	for _, q := range []string{
		"SELECT pgno, data FROM sqlite_dbpage LIMIT 5",
		"SELECT pgno, CAST(substr(data, 4000) AS TEXT) AS t FROM sqlite_dbpage WHERE pgno = 2 LIMIT 1",
		"SELECT data FROM main.sqlite_dbpage LIMIT 1",
		"SELECT data FROM sqlite_dbpage('main') LIMIT 1",
		`SELECT data FROM "SQLite_DBPage" LIMIT 1`,
		"SELECT data FROM [sqlite_dbpage] LIMIT 1",
		"SELECT data FROM 'sqlite_dbpage' LIMIT 1",
		"SELECT * FROM dbstat LIMIT 5",
		"SELECT * FROM dbstat('main') LIMIT 5",
		"SELECT * FROM sqlite_dbdata LIMIT 5",
		"SELECT * FROM sqlite_dbptr LIMIT 5",
		"SELECT sql FROM sqlite_stmt LIMIT 5",
		"UPDATE sqlite_dbpage SET data = zeroblob(4096) WHERE pgno = 1",
		"INSERT INTO sqlite_dbpage (pgno, data) VALUES (1, x'00')",
	} {
		if _, err := Classify(SQLite, q, 0); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	// Other dialects and ordinary SQLite names are unaffected.
	for _, c := range []struct {
		d   Dialect
		sql string
	}{
		{SQLite, "SELECT name FROM sqlite_master LIMIT 5"},
		{SQLite, "SELECT id FROM users WHERE note = 'page' LIMIT 5"},
		{Postgres, "SELECT dbstat FROM t LIMIT 5"},
	} {
		if _, err := Classify(c.d, c.sql, 0); err != nil {
			t.Errorf("%s: %v", c.sql, err)
		}
	}
}
