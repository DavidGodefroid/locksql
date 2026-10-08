package pii

import (
	"strings"
	"testing"
)

func TestRedactMessage(t *testing.T) {
	ds, _ := Detectors([]string{"email"})
	cases := []struct {
		msg, sql string
		leak     string // must not survive
		keep     string // must survive
	}{
		{`postgres: ERROR 22P02: invalid input syntax for type integer: "Smith"`,
			`SELECT id FROM users WHERE last_name::int = 0 LIMIT 1`, "Smith", "22P02"},
		{`mysql: error 1772 (HY000): Malformed GTID set specification 'Smith'.`,
			`SELECT id FROM users WHERE GTID_SUBSET(last_name, '') LIMIT 1`, "Smith", "1772"},
		{`mysql: error 1105 (HY000): XPATH syntax error: '~alice@example.com'`,
			`SELECT 1 FROM users WHERE EXTRACTVALUE(1, CONCAT(0x7e, email)) LIMIT 1`, "alice", "XPATH syntax error"},
		// A value wrapped in quotes cannot shift the pairing.
		{`postgres: ERROR 22P02: invalid input syntax for type integer: ""Smith""`,
			`SELECT 1 FROM users WHERE ('"' || last_name || '"')::int = 0 LIMIT 1`, "Smith", "22P02"},
		{`mysql: error 1292 (22007): Truncated incorrect DOUBLE value: 'O'Brien'`,
			`SELECT 1 FROM users WHERE last_name + 0 = 1 LIMIT 1`, "Brien", "1292"},
		{`postgres: ERROR 22P02: invalid input syntax for type integer: "(1,alice@x.be)"`,
			`SELECT 1 FROM users u WHERE u::text::int = 0 LIMIT 1`, "alice", "22P02"},
		// A single stray quote redacts the rest.
		{`mysql: error 1 (HY000): bad value 'Smith`, `SELECT 1 LIMIT 1`, "Smith", "bad value"},
		// Text quoted from the statement itself stays.
		{`postgres: ERROR 42601: syntax error at or near "FROMM"`, `SELECT id FROMM users LIMIT 1`, "", `"FROMM"`},
		{`postgres: ERROR 42703: column "emial" does not exist`, `SELECT EMIAL FROM users LIMIT 1`, "", `"emial"`},
		{`mysql: error 1054 (42S22): Unknown column 'emial' in 'where clause'`, `SELECT id FROM users WHERE emial = 1 LIMIT 1`, "", `'emial' in 'where clause'`},
		{`mysql: error 1064 (42000): You have an error in your SQL syntax; check the manual near 'FROMM users LIMIT 1' at line 1`,
			`SELECT id FROMM users LIMIT 1`, "", `'FROMM users LIMIT 1'`},
		// Unquoted values go through the detectors.
		{`sqlite: bad thing alice@example.com here`, `SELECT 1 LIMIT 1`, "alice@example.com", "bad thing"},
	}
	for _, c := range cases {
		got := RedactMessage(c.msg, c.sql, ds)
		if c.leak != "" && strings.Contains(got, c.leak) {
			t.Errorf("RedactMessage(%q) = %q leaks %q", c.msg, got, c.leak)
		}
		if !strings.Contains(got, c.keep) {
			t.Errorf("RedactMessage(%q) = %q lost %q", c.msg, got, c.keep)
		}
	}
}
