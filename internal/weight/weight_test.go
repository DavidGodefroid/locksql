package weight

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/engine/mysql"
	"github.com/DavidGodefroid/locksql/internal/engine/postgres"
)

var limits = config.Limits{ExplainRowsWarn: 10_000, ExplainRowsRefuse: 100_000}

// pgSizes are the pg_class.reltuples of the tables the PostgreSQL fixtures
// were captured on.
var pgSizes = map[string]int64{"public.big": 50000, "public.small": 3}

// expected is the level of each fixture query, for every engine unless
// overridden in engineLevel.
var expected = map[string]Level{
	"ref":             OK,
	"range":           OK,
	"small_scan":      OK,
	"join":            OK,
	"subquery":        OK,
	"scalar_subquery": OK,
	"full_scan":       Warn,
	"filesort":        Warn,
	"group_by":        Warn,
	"union":           Warn,
	"derived":         Warn,
	"cartesian":       Refuse,
	"correlated":      Refuse,
	"join_no_index":   Refuse,
}

// engineLevel overrides expected for one engine.
var engineLevel = map[string]map[string]Level{
	"postgres": {
		// PostgreSQL picks a merge join that walks big's primary key from
		// the start. The normalisation counts a whole-index walk as reading
		// the whole table (it never trusts the early stop of a merge join),
		// so this is a full index scan of 50 000 rows.
		"join": Warn,
		// A hash join reads each side once: 50 000 + 50 000 rows.
		"join_no_index": Warn,
	},
}

// loadPlan reads one fixture and normalises it with its engine's parser.
func loadPlan(t *testing.T, file string) (engine.Plan, string) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	rel, _ := filepath.Rel(filepath.Join("..", "..", "testdata", "explain"), file)
	eng := strings.Split(filepath.ToSlash(rel), "/")[0]
	var p engine.Plan
	switch eng {
	case "sqlite":
		err = json.Unmarshal(raw, &p)
	case "postgres":
		p, err = postgres.ParsePlan(raw, pgSizes)
	case "mysql", "mariadb":
		p, err = mysql.ParsePlan(raw)
	default:
		t.Fatalf("%s: unknown engine %q", file, eng)
	}
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return p, eng
}

func fixtures(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{"*/*.json", "*/*/*.json"} {
		m, err := filepath.Glob(filepath.Join("..", "..", "testdata", "explain", pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 60 {
		t.Fatalf("found only %d fixtures", len(files))
	}
	return files
}

func TestFixtureLevels(t *testing.T) {
	for _, file := range fixtures(t) {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		if name == "unknown_size" {
			continue // TestUnknownSize
		}
		t.Run(file, func(t *testing.T) {
			p, eng := loadPlan(t, file)
			want, ok := engineLevel[eng][name]
			if !ok {
				want, ok = expected[name]
			}
			if !ok {
				t.Fatalf("no expected level for %q", name)
			}
			for _, production := range []bool{false, true} {
				v := Assess(p, limits, production)
				if v.Level != want {
					t.Errorf("production=%v: level = %v, want %v\nreasons: %q\nsummary: %s",
						production, v.Level, want, v.Reasons, v.Summary)
				}
				if v.Level != OK && len(v.Reasons) == 0 {
					t.Errorf("level %v without a reason", v.Level)
				}
				if !strings.Contains(v.Summary, "est. ") || !strings.Contains(v.Summary, " rows examined") {
					t.Errorf("summary = %q", v.Summary)
				}
			}
		})
	}
}

func TestUnknownSize(t *testing.T) {
	p, _ := loadPlan(t, filepath.Join("..", "..", "testdata", "explain", "sqlite", "unknown_size.json"))
	if v := Assess(p, limits, false); v.Level != OK {
		t.Errorf("non-production: level = %v (%q), want OK", v.Level, v.Reasons)
	}
	v := Assess(p, limits, true)
	if v.Level != Warn {
		t.Fatalf("production: level = %v, want WARN", v.Level)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "nostat") || !strings.Contains(v.Reasons[0], "unknown size") {
		t.Errorf("reasons = %q", v.Reasons)
	}
	if !strings.Contains(v.Summary, "nostat full ~?") {
		t.Errorf("summary = %q", v.Summary)
	}
}

func TestSummary(t *testing.T) {
	p, _ := loadPlan(t, filepath.Join("..", "..", "testdata", "explain", "mysql", "8.4", "filesort.json"))
	v := Assess(p, limits, false)
	for _, s := range []string{"big full ~49 840", "sort", "est. 49 840 rows examined"} {
		if !strings.Contains(v.Summary, s) {
			t.Errorf("summary %q lacks %q", v.Summary, s)
		}
	}
	if v.EstimatedRows != 49_840 {
		t.Errorf("estimate = %d", v.EstimatedRows)
	}

	p, _ = loadPlan(t, filepath.Join("..", "..", "testdata", "explain", "mariadb", "11.4", "join.json"))
	v = Assess(p, limits, false)
	if want := "s full ~3 · a lookup ~1 · est. 3 rows examined"; v.Summary != want {
		t.Errorf("summary = %q, want %q", v.Summary, want)
	}
}

func TestCorrelatedMultipliesByOuterRows(t *testing.T) {
	p, _ := loadPlan(t, filepath.Join("..", "..", "testdata", "explain", "mariadb", "11.4", "correlated.json"))
	v := Assess(p, limits, false)
	if want := int64(3 + 3*49_959); v.EstimatedRows != want {
		t.Errorf("estimate = %d, want %d", v.EstimatedRows, want)
	}
}

func TestReasons(t *testing.T) {
	cases := []struct {
		name string
		file string
		want []string
	}{
		{"full scan", "mysql/8.4/full_scan.json", []string{"full scan of big (~49 840 rows)"}},
		{"cartesian", "mysql/8.4/cartesian.json", []string{"cartesian join on b (no join condition)"}},
		{"temp", "mysql/8.4/group_by.json", []string{"temporary table over ~49 840 rows"}},
		{"sort", "mysql/8.4/filesort.json", []string{"sort over ~49 840 rows"}},
		{"estimate", "mysql/8.4/correlated.json", []string{"estimated rows examined 149 523 > 100 000"}},
	}
	for _, c := range cases {
		p, _ := loadPlan(t, filepath.Join("..", "..", "testdata", "explain", filepath.FromSlash(c.file)))
		v := Assess(p, limits, false)
		for _, w := range c.want {
			found := false
			for _, r := range v.Reasons {
				found = found || strings.Contains(r, w)
			}
			if !found {
				t.Errorf("%s: reasons %q lack %q", c.name, v.Reasons, w)
			}
		}
	}
}

func table(name, access string, rows int64) engine.PlanNode {
	return engine.PlanNode{Table: name, Access: access, EstRows: rows}
}

func group(children ...engine.PlanNode) engine.PlanNode {
	return engine.PlanNode{EstRows: -1, Detail: "QUERY", Children: children}
}

func TestFullScanAboveRefuseIsRefused(t *testing.T) {
	p := engine.Plan{Root: group(table("t", engine.AccessFull, 500_000))}
	v := Assess(p, config.Limits{ExplainRowsWarn: 1_000_000, ExplainRowsRefuse: 400_000}, false)
	if v.Level != Refuse {
		t.Errorf("level = %v (%q)", v.Level, v.Reasons)
	}
}

func TestFullIndexScanCountsAsFullScan(t *testing.T) {
	p := engine.Plan{Root: group(table("t", engine.AccessIndex, 20_000))}
	v := Assess(p, limits, false)
	if v.Level != Warn || len(v.Reasons) == 0 || !strings.Contains(strings.Join(v.Reasons, ";"), "full scan of t") {
		t.Errorf("verdict = %+v", v)
	}
}

func TestCartesianUnderWarnIsWarn(t *testing.T) {
	b := table("b", engine.AccessFull, 30)
	b.NoJoinCond = true
	p := engine.Plan{Root: group(table("a", engine.AccessFull, 20), b)}
	v := Assess(p, limits, false)
	if v.Level != Warn || v.EstimatedRows != 600 {
		t.Errorf("verdict = %+v", v)
	}
}

func TestNestedCorrelation(t *testing.T) {
	inner := group(table("c", engine.AccessFull, 10))
	inner.Correlated = true
	mid := group(table("b", engine.AccessLookup, 2), inner)
	mid.Correlated = true
	p := engine.Plan{Root: group(table("a", engine.AccessFull, 5), mid)}
	// a: 5; per a row: b 2 + per b row c 10 → 2 + 2*10 = 22; total 5 + 5*22.
	if v := Assess(p, limits, false); v.EstimatedRows != 115 {
		t.Errorf("estimate = %d", v.EstimatedRows)
	}
}

func TestSaturates(t *testing.T) {
	big := table("t", engine.AccessFull, math.MaxInt64/2)
	p := engine.Plan{Root: group(big, big, big)}
	v := Assess(p, limits, false)
	if v.EstimatedRows != math.MaxInt64 || v.Level != Refuse {
		t.Errorf("verdict = %+v", v)
	}
}

func TestNoTable(t *testing.T) {
	v := Assess(engine.Plan{Root: group()}, limits, true)
	if v.Level != OK || v.EstimatedRows != 0 || !strings.Contains(v.Summary, "no table") {
		t.Errorf("verdict = %+v", v)
	}
}

func TestZeroLimitsUseDefaults(t *testing.T) {
	p := engine.Plan{Root: group(table("t", engine.AccessFull, 300_000))}
	if v := Assess(p, config.Limits{}, true); v.Level != Refuse {
		t.Errorf("production with zero limits: level = %v", v.Level)
	}
	if v := Assess(p, config.Limits{}, false); v.Level != Warn {
		t.Errorf("non-production with zero limits: level = %v", v.Level)
	}
}

func TestLevelText(t *testing.T) {
	b, err := json.Marshal(Verdict{Level: Refuse})
	if err != nil || !strings.Contains(string(b), `"level":"REFUSE"`) {
		t.Errorf("json = %s, %v", b, err)
	}
	var v Verdict
	if err := json.Unmarshal([]byte(`{"level":"WARN"}`), &v); err != nil || v.Level != Warn {
		t.Errorf("unmarshal = %+v, %v", v, err)
	}
	if OK.String() != "OK" || Warn.String() != "WARN" || Refuse.String() != "REFUSE" {
		t.Error("String")
	}
}
