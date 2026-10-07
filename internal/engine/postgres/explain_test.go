package postgres

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// shape renders a normalised plan compactly: a group is "{flags children}",
// a table is "name:access:rows" with "!nojoin" when it has no join
// condition. Rows of 40 000 or more print as N, since the estimates of the
// 50 000-row table vary between captures.
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

// fixtureSizes are the table sizes of the capture seed, as pg_class reports
// them after ANALYZE.
var fixtureSizes = map[string]int64{"public.big": 50_000, "public.small": 3}

// fixtureShapes holds the expected shape of every captured fixture, by name,
// then by server major version when they disagree ("*" for all of them).
var fixtureShapes = map[string]map[string]string{
	"ref":        {"*": "{big:lookup:1}"},
	"range":      {"*": "{big:range:10}"},
	"small_scan": {"*": "{small:full:3}"},
	// Merge join: the outer index scan is the pipeline, the sorted inner
	// side is read once.
	"join":     {"*": "{big:index:N {sort small:full:3}}"},
	"subquery": {"*": "{small:full:3 big:lookup:1}"},
	// The filter leaves 1 row, but the scan reads the whole table.
	"full_scan":  {"*": "{big:full:N}"},
	"filesort":   {"*": "{sort big:full:N}"},
	"group_by":   {"*": "{temp big:full:N}"},
	"union":      {"13": "{temp {big:full:N} {small:full:3}}", "17": "{sort {big:full:N} {small:full:3}}"},
	"cartesian":  {"*": "{temp big:full:N big:full:N!nojoin}"},
	"correlated": {"*": "{small:full:3 {corr big:full:N}}"},
	"derived":    {"*": "{d:full:1 {sort temp big:full:N}}"},
	// An InitPlan runs once: not correlated.
	"scalar_subquery": {"*": "{small:full:3 {small:full:3}}"},
	// Hash join: the hashed inner side is read once.
	"join_no_index": {"*": "{big:full:N {big:full:N}}"},
}

var fixtureVersions = []string{"13", "17"}

func TestParsePlanFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "explain", "postgres")
	seen := 0
	for _, v := range fixtureVersions {
		files, err := filepath.Glob(filepath.Join(root, v, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != len(fixtureShapes) {
			t.Errorf("%s: %d fixtures, want %d", v, len(files), len(fixtureShapes))
		}
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".json")
			want, ok := fixtureShapes[name][v]
			if !ok {
				want, ok = fixtureShapes[name]["*"]
			}
			if !ok {
				t.Errorf("%s/%s: no expected shape", v, name)
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := ParsePlan(raw, fixtureSizes)
			if err != nil {
				t.Errorf("%s/%s: %v", v, name, err)
				continue
			}
			if string(plan.Raw) != string(raw) {
				t.Errorf("%s/%s: Raw is not the server's plan", v, name)
			}
			if plan.Root.Detail != "QUERY" || plan.Root.EstRows != -1 {
				t.Errorf("%s/%s: root = %+v", v, name, plan.Root)
			}
			if got := shape(plan.Root); got != want {
				t.Errorf("%s/%s:\n got %s\nwant %s", v, name, got, want)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no fixture found")
	}
}

func TestParsePlanWithoutSizesUsesPlanRows(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "explain", "postgres", "17", "full_scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePlan(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := shape(p.Root); got != "{big:full:1}" {
		t.Errorf("shape = %s", got)
	}
}

func TestPlanRelations(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "explain", "postgres", "17", "correlated.json"))
	if err != nil {
		t.Fatal(err)
	}
	rels, err := PlanRelations(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rels, []Relation{{"public", "big"}, {"public", "small"}}) {
		t.Errorf("relations = %v", rels)
	}
}

// plan wraps a node in the EXPLAIN (FORMAT JSON) envelope.
func plan(node string) string { return `[{"Plan":` + node + `}]` }

func TestParsePlanShapes(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{
			"nested loop with a join filter is a join",
			plan(`{"Node Type":"Nested Loop","Join Filter":"(a.x = b.x)","Plans":[
			  {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"a","Schema":"public","Alias":"a","Plan Rows":10},
			  {"Node Type":"Seq Scan","Parent Relationship":"Inner","Relation Name":"b","Schema":"public","Alias":"b","Plan Rows":20}]}`),
			"{a:full:10 b:full:20}",
		},
		{
			"inner scan filtered on an outer column is a join",
			plan(`{"Node Type":"Nested Loop","Plans":[
			  {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"t","Schema":"public","Alias":"a","Plan Rows":10},
			  {"Node Type":"Seq Scan","Parent Relationship":"Inner","Relation Name":"t","Schema":"public","Alias":"b","Plan Rows":20,"Filter":"(b.x = a.x)"}]}`),
			"{t:full:10 t:full:20}",
		},
		{
			"inner scan filtered on its own columns only is cartesian",
			plan(`{"Node Type":"Nested Loop","Plans":[
			  {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"t","Schema":"public","Alias":"a","Plan Rows":10},
			  {"Node Type":"Seq Scan","Parent Relationship":"Inner","Relation Name":"t","Schema":"public","Alias":"b","Plan Rows":20,"Filter":"(b.x = 'a.x')"}]}`),
			"{t:full:10 t:full:20!nojoin}",
		},
		{
			"bitmap heap scan",
			plan(`{"Node Type":"Bitmap Heap Scan","Relation Name":"t","Schema":"public","Alias":"t","Plan Rows":5,
			  "Recheck Cond":"((t.x > 1) AND (t.x < 9))","Plans":[
			  {"Node Type":"Bitmap Index Scan","Parent Relationship":"Outer","Index Name":"i","Plan Rows":8,"Index Cond":"((t.x > 1) AND (t.x < 9))"}]}`),
			"{t:range:8}",
		},
		{
			"bitmap equality is a lookup",
			plan(`{"Node Type":"Bitmap Heap Scan","Relation Name":"t","Alias":"t","Plan Rows":5,"Recheck Cond":"(t.x = '<>')","Plans":[
			  {"Node Type":"Bitmap Index Scan","Parent Relationship":"Outer","Index Name":"i","Plan Rows":5,"Index Cond":"(t.x = '<>')"}]}`),
			"{t:lookup:5}",
		},
		{
			"index scans",
			plan(`{"Node Type":"Nested Loop","Join Filter":"true","Plans":[
			  {"Node Type":"Index Scan","Parent Relationship":"Outer","Relation Name":"t1","Alias":"t1","Plan Rows":100},
			  {"Node Type":"Index Only Scan","Parent Relationship":"Inner","Relation Name":"t2","Alias":"t2","Plan Rows":2,"Index Cond":"(t2.id = ANY ('{1,2}'::integer[]))"}]}`),
			"{t1:index:100 t2:range:2}",
		},
		{
			"full index scan is sized from the catalog",
			plan(`{"Node Type":"Index Only Scan","Relation Name":"big","Schema":"public","Alias":"big","Plan Rows":7,"Filter":"(id > 0)"}`),
			"{big:index:N}",
		},
		{
			"append under a nested loop inner side runs per outer row",
			plan(`{"Node Type":"Nested Loop","Plans":[
			  {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"a","Alias":"a","Plan Rows":10},
			  {"Node Type":"Append","Parent Relationship":"Inner","Plans":[
			    {"Node Type":"Index Scan","Parent Relationship":"Member","Relation Name":"p1","Alias":"p1","Plan Rows":1,"Index Cond":"(p1.id = a.id)"},
			    {"Node Type":"Index Scan","Parent Relationship":"Member","Relation Name":"p2","Alias":"p2","Plan Rows":1,"Index Cond":"(p2.id = a.id)"}]}]}`),
			"{a:full:10 {corr p1:lookup:1} {corr p2:lookup:1}}",
		},
		{
			"hash join under a nested loop inner side",
			plan(`{"Node Type":"Nested Loop","Plans":[
			  {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"a","Alias":"a","Plan Rows":10},
			  {"Node Type":"Hash Join","Parent Relationship":"Inner","Hash Cond":"(b.x = c.x)","Plans":[
			    {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"b","Alias":"b","Plan Rows":4,"Filter":"(b.y = a.y)"},
			    {"Node Type":"Hash","Parent Relationship":"Inner","Plans":[
			      {"Node Type":"Seq Scan","Parent Relationship":"Outer","Relation Name":"c","Alias":"c","Plan Rows":5}]}]}]}`),
			"{a:full:10 b:full:4 {corr c:full:5}}",
		},
		{
			"functions, values, CTEs",
			plan(`{"Node Type":"Nested Loop","Join Filter":"x","Plans":[
			  {"Node Type":"Function Scan","Parent Relationship":"Outer","Function Name":"generate_series","Alias":"g","Plan Rows":1000},
			  {"Node Type":"CTE Scan","Parent Relationship":"Inner","CTE Name":"c","Alias":"c","Plan Rows":3,"Plans":[
			    {"Node Type":"Values Scan","Parent Relationship":"InitPlan","Subplan Name":"CTE c","Alias":"*VALUES*","Plan Rows":3}]}]}`),
			"{generate_series:full:1000 c:full:3 {*VALUES*:full:3}}",
		},
		{
			"modify table, materialize, memoize, hashed setop",
			plan(`{"Node Type":"ModifyTable","Operation":"Update","Relation Name":"t","Alias":"t","Plan Rows":0,"Plans":[
			  {"Node Type":"SetOp","Strategy":"Hashed","Parent Relationship":"Outer","Plans":[
			    {"Node Type":"Memoize","Parent Relationship":"Outer","Plans":[
			      {"Node Type":"Tid Scan","Parent Relationship":"Outer","Relation Name":"t","Alias":"t","Plan Rows":1}]}]}]}`),
			"{temp t:lookup:1}",
		},
		{
			"foreign and unknown scans",
			plan(`{"Node Type":"Append","Plans":[
			  {"Node Type":"Foreign Scan","Parent Relationship":"Member","Relation Name":"f","Alias":"f","Plan Rows":9},
			  {"Node Type":"Custom Scan","Parent Relationship":"Member","Relation Name":"c","Alias":"c","Plan Rows":2}]}`),
			"{{f:unknown:9} {c:unknown:2}}",
		},
		{
			"no tables",
			plan(`{"Node Type":"Result","Plan Rows":1}`),
			"{}",
		},
		{
			"fractional and huge row estimates",
			plan(`{"Node Type":"Seq Scan","Relation Name":"t","Alias":"t","Plan Rows":12.6}`),
			"{t:full:13}",
		},
	}
	for _, c := range cases {
		p, err := ParsePlan([]byte(c.raw), fixtureSizes)
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
	for _, raw := range []string{``, `not json`, `[]`, `{}`, `[{}]`, `[{"Plan":[]}]`, `[{"Plan":{}}]`, `[1]`} {
		if _, err := ParsePlan([]byte(raw), nil); err == nil {
			t.Errorf("ParsePlan(%q) succeeded", raw)
		}
	}
}

func FuzzParsePlanNoPanic(f *testing.F) {
	f.Add(plan(`{"Node Type":"Nested Loop","Plans":[{"Node Type":"Seq Scan","Relation Name":"a","Plan Rows":1}]}`))
	f.Add(plan(`{"Node Type":"Append","Plans":[{"Node Type":"Hash Join","Plans":[{},{"Node Type":"Hash"}]}]}`))
	f.Add(`[{"Plan":{"Node Type":"Seq Scan","Plan Rows":1e300}}]`)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ParsePlan([]byte(raw), fixtureSizes)
		_, _ = PlanRelations([]byte(raw))
	})
}
