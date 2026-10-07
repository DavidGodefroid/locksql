package render

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

func limits() config.Limits {
	return config.Limits{MaxRows: 200, MaxCellChars: 200, MaxOutputBytes: 65536}
}

func cols(labels ...string) []engine.ResultColumn {
	out := make([]engine.ResultColumn, len(labels))
	for i, l := range labels {
		out[i] = engine.ResultColumn{Label: l}
	}
	return out
}

func render(t *testing.T, res engine.Result, l config.Limits, format string) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, res, l, format); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b.String()
}

func TestTSVHeaderRowsAndCount(t *testing.T) {
	out := render(t, engine.Result{Columns: cols("id", "status"), Rows: [][]any{{int64(1), "sent"}, {int64(2), "failed"}}}, limits(), "tsv")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if lines[0] != "id\tstatus" || lines[1] != "1\tsent" || lines[2] != "2\tfailed" || lines[len(lines)-1] != "(2 rows)" {
		t.Errorf("out = %q", out)
	}
}

func TestTSVSpecialValues(t *testing.T) {
	ts := time.Date(2026, 10, 7, 14, 3, 0, 0, time.FixedZone("CEST", 2*3600))
	out := render(t, engine.Result{
		Columns: cols("a", "b", "c", "d", "e", "f", "g", "h", "i"),
		Rows:    [][]any{{nil, []byte{0, 1}, ts, "1.50", math.NaN(), math.Inf(-1), true, uint64(math.MaxUint64), 2.5}},
	}, limits(), "")
	want := "NULL\t<bytes:2>\t2026-10-07T14:03:00+02:00\t1.50\tNaN\t-Infinity\ttrue\t18446744073709551615\t2.5"
	if !strings.Contains(out, want) {
		t.Errorf("out = %q\nwant %q", out, want)
	}
}

func TestTSVEscapes(t *testing.T) {
	out := render(t, engine.Result{Columns: cols("a\tb"), Rows: [][]any{{"x\ty\nz\r\\ \x1b[31m \u202e \x7f"}}}, limits(), "tsv")
	if !strings.HasPrefix(out, "a\\tb\n") {
		t.Errorf("header = %q", out)
	}
	if !strings.Contains(out, `x\ty\nz\r\\ \x1b[31m \u202e \x7f`) {
		t.Errorf("out = %q", out)
	}
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x202e) {
		t.Errorf("raw control left in %q", out)
	}
}

func TestTSVCellCut(t *testing.T) {
	out := render(t, engine.Result{Columns: cols("a"), Rows: [][]any{{strings.Repeat("x", 500)}, {strings.Repeat("é", 300)}}}, limits(), "tsv")
	if !strings.Contains(out, strings.Repeat("x", 199)+"…\n") || strings.Contains(out, strings.Repeat("x", 200)) {
		t.Errorf("ascii cut wrong: %q", out)
	}
	if !strings.Contains(out, strings.Repeat("é", 199)+"…\n") || strings.Contains(out, strings.Repeat("é", 200)) {
		t.Error("multi-byte cut wrong")
	}
	// Exactly at the cap: not cut.
	out = render(t, engine.Result{Columns: cols("a"), Rows: [][]any{{strings.Repeat("y", 200)}}}, limits(), "tsv")
	if !strings.Contains(out, strings.Repeat("y", 200)+"\n") || strings.Contains(out, "…") {
		t.Errorf("at cap: %q", out)
	}
}

func TestTSVOutputCut(t *testing.T) {
	rows := make([][]any, 1000)
	for i := range rows {
		rows[i] = []any{strings.Repeat("y", 150)}
	}
	l := limits()
	l.MaxOutputBytes = 2000
	l.MaxRows = 0 // default (200)
	out := render(t, engine.Result{Columns: cols("a"), Rows: rows}, l, "tsv")
	if len(out) > 2200 {
		t.Errorf("len = %d", len(out))
	}
	if !strings.Contains(out, "[output cut at 2000 bytes: 13 of 200 rows shown]") {
		t.Errorf("out = %q", out[len(out)-200:])
	}
}

func TestTSVWideHeaderStaysWithinCap(t *testing.T) {
	labels := make([]string, 100)
	for i := range labels {
		labels[i] = strings.Repeat("é", 100)
	}
	l := limits()
	l.MaxOutputBytes = 1000
	out := render(t, engine.Result{Columns: cols(labels...), Rows: [][]any{make([]any, 100)}}, l, "tsv")
	header, rest, _ := strings.Cut(out, "\n")
	if len(header)+1 > 1000 || !utf8.ValidString(header) || !strings.HasSuffix(header, "…") {
		t.Errorf("header: %d bytes, %q", len(header), header[max(0, len(header)-20):])
	}
	if !strings.Contains(rest, "[output cut at 1000 bytes: 0 of 1 rows shown]") {
		t.Errorf("rest = %q", rest)
	}
}

func TestTSVTruncatedAndRowCap(t *testing.T) {
	out := render(t, engine.Result{Columns: cols("a"), Rows: [][]any{{int64(1)}}, Truncated: true}, limits(), "tsv")
	if !strings.Contains(out, "(1 rows) — more rows exist beyond the row cap") {
		t.Errorf("out = %q", out)
	}
	l := limits()
	l.MaxRows = 2
	out = render(t, engine.Result{Columns: cols("a"), Rows: [][]any{{int64(1)}, {int64(2)}, {int64(3)}}}, l, "tsv")
	if strings.Contains(out, "\n3\n") || !strings.Contains(out, "(2 rows) — more rows exist") {
		t.Errorf("row cap: %q", out)
	}
}

func TestTSVAffected(t *testing.T) {
	out := render(t, engine.Result{Affected: 3}, limits(), "tsv")
	if out != "(3 rows affected)\n" {
		t.Errorf("out = %q", out)
	}
}

func TestHugeCellStaysWithinCap(t *testing.T) {
	big := strings.Repeat("z", 10<<20)
	for _, format := range []string{"tsv", "json"} {
		var b bytes.Buffer
		if err := Render(&b, engine.Result{Columns: cols("a"), Rows: [][]any{{big}, {[]byte(big)}}}, limits(), format); err != nil {
			t.Fatal(err)
		}
		if b.Len() > 1024 {
			t.Errorf("%s: output %d bytes for a 10 MB cell", format, b.Len())
		}
	}
}

func TestInvalidUTF8Replaced(t *testing.T) {
	for _, format := range []string{"tsv", "json"} {
		out := render(t, engine.Result{Columns: cols("a\xff"), Rows: [][]any{{"ok\xff\xfeend"}}}, limits(), format)
		if !utf8.ValidString(out) || !strings.Contains(out, "ok��end") && !strings.Contains(out, `ok��end`) {
			t.Errorf("%s: %q", format, out)
		}
	}
}

func TestJSON(t *testing.T) {
	ts := time.Date(2026, 10, 7, 14, 3, 0, 0, time.UTC)
	out := render(t, engine.Result{
		Columns:   cols("id", "s", "b", "t", "n", "f", "ok"),
		Rows:      [][]any{{int64(1), "a\nb", []byte("xyz"), ts, nil, math.NaN(), false}},
		Truncated: true,
	}, limits(), "json")
	var got struct {
		Columns   []string `json:"columns"`
		Rows      [][]any  `json:"rows"`
		Truncated bool     `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if strings.Join(got.Columns, ",") != "id,s,b,t,n,f,ok" || !got.Truncated || len(got.Rows) != 1 {
		t.Fatalf("got %+v", got)
	}
	row := got.Rows[0]
	if row[0] != 1.0 || row[1] != "a\nb" || row[2] != "<bytes:3>" || row[3] != "2026-10-07T14:03:00Z" || row[4] != nil || row[5] != "NaN" || row[6] != false {
		t.Errorf("row = %#v", row)
	}
}

func TestJSONOutputCut(t *testing.T) {
	rows := make([][]any, 1000)
	for i := range rows {
		rows[i] = []any{strings.Repeat("y", 150)}
	}
	l := limits()
	l.MaxOutputBytes = 2000
	l.MaxRows = 1000
	out := render(t, engine.Result{Columns: cols("a"), Rows: rows}, l, "json")
	if len(out) > 2000 {
		t.Errorf("len = %d", len(out))
	}
	var got struct {
		Rows      [][]any `json:"rows"`
		Truncated bool    `json:"truncated"`
		CutAt     int     `json:"output_cut_at_bytes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.CutAt != 2000 || len(got.Rows) == 0 || len(got.Rows) >= 1000 {
		t.Errorf("rows=%d truncated=%v cut=%d", len(got.Rows), got.Truncated, got.CutAt)
	}
}

func TestJSONWideHeaderStaysWithinCap(t *testing.T) {
	labels := make([]string, 100)
	for i := range labels {
		labels[i] = strings.Repeat("é", 100)
	}
	l := limits()
	l.MaxOutputBytes = 1000
	out := render(t, engine.Result{Columns: cols(labels...), Rows: [][]any{make([]any, 100)}}, l, "json")
	if len(out) > 1000 {
		t.Errorf("len = %d", len(out))
	}
	var got struct {
		Columns   []string `json:"columns"`
		Rows      [][]any  `json:"rows"`
		Truncated bool     `json:"truncated"`
		CutAt     int      `json:"output_cut_at_bytes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got.Columns) == 0 || !got.Truncated || got.CutAt != 1000 || len(got.Rows) != 0 {
		t.Errorf("columns=%d rows=%d truncated=%v cut=%d", len(got.Columns), len(got.Rows), got.Truncated, got.CutAt)
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Render(&bytes.Buffer{}, engine.Result{}, limits(), "xml"); err == nil {
		t.Error("xml accepted")
	}
}

func FuzzRenderNoPanic(f *testing.F) {
	f.Add("a\tb\n\x00\xff\u202e", 5, 64)
	f.Fuzz(func(t *testing.T, s string, cell, total int) {
		l := config.Limits{MaxRows: 10, MaxCellChars: cell % 300, MaxOutputBytes: total % 5000}
		for _, format := range []string{"tsv", "json"} {
			var b bytes.Buffer
			if err := Render(&b, engine.Result{Columns: cols(s), Rows: [][]any{{s, []byte(s), nil}}}, l, format); err != nil {
				t.Fatal(err)
			}
			if !utf8.Valid(b.Bytes()) {
				t.Fatalf("invalid UTF-8 output %q", b.String())
			}
			if format == "json" {
				if !json.Valid(b.Bytes()) {
					t.Fatalf("invalid JSON %q", b.String())
				}
				if limit := effective(l).MaxOutputBytes; limit >= 200 && b.Len() > limit {
					t.Fatalf("JSON output %d bytes over the %d cap", b.Len(), limit)
				}
			}
		}
	})
}
