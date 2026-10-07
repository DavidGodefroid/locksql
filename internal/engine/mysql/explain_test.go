package mysql

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// shape renders a normalised plan compactly: a group is "{flags children}",
// a table is "name:access:rows" with "!nojoin" when it has no join
// condition. Rows of 40 000 or more print as N, since InnoDB estimates of
// the 50 000-row table vary between captures.
func shape(n engine.PlanNode) string {
	if n.Table != "" {
		rows := fmt.Sprint(n.EstRows)
		if n.EstRows >= 40_000 {
			rows = "N"
		}
		s := n.Table + ":" + n.Access + ":" + rows
		if n.NoJoinCond {
			s += "!nojoin"
		}
		return s
	}
	var parts []string
	if n.Correlated {
		parts = append(parts, "corr")
	}
	if n.Sort {
		parts = append(parts, "sort")
	}
	if n.Temp {
		parts = append(parts, "temp")
	}
	for _, c := range n.Children {
		parts = append(parts, shape(c))
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// fixtureShapes holds the expected shape of every captured fixture, by
// name, then by "<flavor>/<version>" when the versions disagree ("*" for
// all of them).
var fixtureShapes = map[string]map[string]string{
	"ref":        {"*": "{big:lookup:1}"},
	"range":      {"*": "{big:range:9}"},
	"small_scan": {"*": "{small:full:3}"},
	"join":       {"*": "{s:full:3 a:lookup:1}"},
	"subquery": {
		"*":            "{small:index:3 big:lookup:1}",
		"mariadb/11.4": "{small:full:3 big:lookup:1}",
	},
	"full_scan": {"*": "{big:full:N}"},
	"filesort":  {"*": "{sort big:full:N}"},
	"group_by": {
		"mariadb/10.11": "{sort temp big:full:N}",
		"mariadb/11.4":  "{sort temp big:full:N}",
		"mysql/8.0":     "{temp big:full:N}",
		"mysql/8.4":     "{temp big:full:N}",
	},
	"union":      {"*": "{{temp {big:full:N} {small:full:3}}}"},
	"cartesian":  {"*": "{a:full:N b:full:N!nojoin}"},
	"correlated": {"*": "{s:full:3 {corr b:full:N}}"},
	"derived": {
		"mariadb/10.11": "{<derived2>:full:N {sort temp big:full:N}}",
		"mariadb/11.4":  "{<derived2>:full:N {sort temp big:full:N}}",
		"mysql/8.0":     "{d:full:N {temp big:full:N}}",
		"mysql/8.4":     "{d:full:N {temp big:full:N}}",
	},
	"scalar_subquery": {
		"*": "{s:full:3 {small:lookup:1} {}}",
	},
	"join_no_index": {"*": "{a:full:N b:full:N}"},
}

var fixtureVersions = []string{"mariadb/10.11", "mariadb/11.4", "mysql/8.0", "mysql/8.4"}

func TestParsePlanFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "explain")
	seen := 0
	for _, fv := range fixtureVersions {
		files, err := filepath.Glob(filepath.Join(root, fv, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != len(fixtureShapes) {
			t.Errorf("%s: %d fixtures, want %d", fv, len(files), len(fixtureShapes))
		}
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".json")
			want, ok := fixtureShapes[name][fv]
			if !ok {
				want, ok = fixtureShapes[name]["*"]
			}
			if !ok {
				t.Errorf("%s/%s: no expected shape", fv, name)
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := ParsePlan(raw)
			if err != nil {
				t.Errorf("%s/%s: %v", fv, name, err)
				continue
			}
			if string(plan.Raw) != string(raw) {
				t.Errorf("%s/%s: Raw is not the server's plan", fv, name)
			}
			if plan.Root.Detail != "QUERY" || plan.Root.EstRows != -1 {
				t.Errorf("%s/%s: root = %+v", fv, name, plan.Root)
			}
			if got := shape(plan.Root); got != want {
				t.Errorf("%s/%s:\n got %s\nwant %s", fv, name, got, want)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no fixture found")
	}
}

func TestParsePlanShapes(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{
			"mariadb bnl with condition on the wrapper is a join",
			`{"query_block":{"nested_loop":[{"table":{"table_name":"a","access_type":"ALL","rows":10}},
			  {"block-nl-join":{"table":{"table_name":"b","access_type":"ALL","rows":20},"attached_condition":"b.x = a.x"}}]}}`,
			"{a:full:10 b:full:20}",
		},
		{
			"second full scan with no condition and no join buffer",
			`{"query_block":{"nested_loop":[{"table":{"table_name":"a","access_type":"ALL","rows":10}},
			  {"table":{"table_name":"b","access_type":"index","rows":20}}]}}`,
			"{a:full:10 b:index:20!nojoin}",
		},
		{
			"mariadb expression cache marks a correlated subquery",
			`{"query_block":{"nested_loop":[{"table":{"table_name":"s","access_type":"ALL","rows":3}}],
			  "subqueries":[{"expression_cache":{"query_block":{"nested_loop":[{"table":{"table_name":"b","access_type":"ref","rows":7}}]}}}]}}`,
			"{s:full:3 {corr b:lookup:7}}",
		},
		{
			"mysql attached dependent subquery",
			`{"query_block":{"table":{"table_name":"s","access_type":"ALL","rows_examined_per_scan":3,
			  "attached_subqueries":[{"dependent":true,"query_block":{"table":{"table_name":"b","access_type":"ALL","rows_examined_per_scan":9}}}]}}}`,
			"{s:full:3 {corr b:full:9}}",
		},
		{
			"access types",
			`{"query_block":{"nested_loop":[
			  {"table":{"table_name":"t1","access_type":"system","rows":1}},
			  {"table":{"table_name":"t2","access_type":"ref_or_null","rows":2}},
			  {"table":{"table_name":"t3","access_type":"index_merge","rows":3}},
			  {"table":{"table_name":"t4","access_type":"hash_ALL","rows":4,"attached_condition":"x"}},
			  {"table":{"table_name":"t5","access_type":"hash_range","rows":5}},
			  {"table":{"table_name":"t6","access_type":"fulltext","rows":6}},
			  {"table":{"table_name":"t7","access_type":"weird","rows":7}},
			  {"table":{"table_name":"t8","access_type":"ALL"}}]}}`,
			"{t1:lookup:1 t2:lookup:2 t3:range:3 t4:full:4 t5:range:5 t6:lookup:6 t7:unknown:7 t8:full:-1!nojoin}",
		},
		{
			"fractional row estimates round",
			`{"query_block":{"table":{"table_name":"t","access_type":"ALL","rows":12.6}}}`,
			"{t:full:13}",
		},
		{
			"update plan",
			`{"query_block":{"select_id":1,"table":{"update":true,"table_name":"t","access_type":"range","rows_examined_per_scan":4}}}`,
			"{t:range:4}",
		},
		{
			"no tables",
			`{"query_block":{"select_id":1,"message":"No tables used"}}`,
			"{}",
		},
		{
			"mysql union all without a temporary table",
			`{"query_block":{"union_result":{"using_temporary_table":false,"table_name":"<union1,2>","access_type":"ALL",
			  "query_specifications":[{"query_block":{"table":{"table_name":"a","access_type":"ALL","rows_examined_per_scan":1}}},
			  {"query_block":{"table":{"table_name":"b","access_type":"ALL","rows_examined_per_scan":2}}}]}}}`,
			"{{{a:full:1} {b:full:2}}}",
		},
	}
	for _, c := range cases {
		p, err := ParsePlan([]byte(c.raw))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := shape(p.Root); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestParsePlanRejectsGarbage(t *testing.T) {
	for _, raw := range []string{``, `not json`, `[]`, `{"no_query_block":{}}`, `{"query_block":[]}`} {
		if _, err := ParsePlan([]byte(raw)); err == nil {
			t.Errorf("ParsePlan(%q) succeeded", raw)
		}
	}
}

func FuzzParsePlanNoPanic(f *testing.F) {
	f.Add(`{"query_block":{"nested_loop":[{"table":{"table_name":"a","access_type":"ALL","rows":1}}]}}`)
	f.Add(`{"query_block":{"subqueries":[{"expression_cache":{}}],"union_result":{"query_specifications":[1,"x",{}]}}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ParsePlan([]byte(raw))
	})
}
