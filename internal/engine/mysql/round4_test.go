package mysql

import (
	"reflect"
	"strings"
	"testing"
)

func TestFromNames(t *testing.T) {
	cases := []struct {
		q             string
		rels, aliases string
		ok            bool
	}{
		{"SELECT small.label FROM v_def AS small LIMIT 5", "V_DEF", "SMALL", true},
		{"SELECT label FROM app.v_def small LIMIT 5", "V_DEF", "SMALL", true},
		{"SELECT b.id FROM big b JOIN small ON small.id = b.id, other.t AS x WHERE 1", "BIG SMALL T", "B X", true},
		{"SELECT id FROM big LEFT JOIN small USING (id) ORDER BY id", "BIG SMALL", "", true},
		{"SELECT id FROM big PARTITION (p0) AS p USE INDEX (i) LIMIT 1", "BIG", "P", true},
		{"SELECT 1 FROM DUAL", "", "", true},
		{"SELECT id FROM (big JOIN small USING (id))", "", "", false},
		// Round 5: MariaDB accepts FULL (it has no FULL JOIN) and WINDOW
		// as unquoted aliases.
		{"SELECT full.email FROM full AS f, v6 AS full LIMIT 5", "FULL V6", "F FULL", true},
		{"SELECT full.email FROM full f JOIN v6 full LIMIT 5", "FULL V6", "F FULL", true},
		{"SELECT window.email FROM window w, v6 window LIMIT 5", "WINDOW V6", "W WINDOW", true},
	}
	for _, c := range cases {
		rels, aliases, ok := fromNames(c.q)
		if ok != c.ok {
			t.Errorf("%s: ok = %v", c.q, ok)
			continue
		}
		if !ok {
			continue
		}
		set := func(s string) map[string]bool {
			m := map[string]bool{}
			for _, w := range strings.Fields(s) {
				m[w] = true
			}
			return m
		}
		if !reflect.DeepEqual(rels, set(c.rels)) || !reflect.DeepEqual(aliases, set(c.aliases)) {
			t.Errorf("%s: rels %v aliases %v", c.q, rels, aliases)
		}
	}
}
