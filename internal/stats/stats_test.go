package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/audit"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// logOf renders records as audit log lines.
func logOf(t *testing.T, recs ...audit.Record) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	for _, r := range recs {
		line, err := json.Marshal(struct {
			TS string `json:"ts"`
			audit.Record
		}{"2026-10-11T10:00:00.000Z", r})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	return &b
}

func refused(code, token, sql string) audit.Record {
	r := audit.Record{Event: audit.EventRefused, Engine: "postgres", SQL: sql, Code: code, Error: "reason naming secret_table"}
	if token != "" {
		r.Span = &refusal.Span{Line: 1, Col: 1, Token: token}
	}
	return r
}

func TestReadGroupsRefusals(t *testing.T) {
	in := logOf(t,
		refused("E_MASKED_FILTER", "LIKE", "SELECT id FROM users WHERE email LIKE 'a%' LIMIT 1"),
		refused("E_MASKED_FILTER", "like", "SELECT id FROM users WHERE email LIKE 'b%' LIMIT 1"),
		refused("E_MASKED_FILTER", "BETWEEN", "SELECT id FROM users WHERE email BETWEEN 'a' AND 'b' LIMIT 1"),
		refused("E_NO_LIMIT", "", "SELECT id FROM users"),
		audit.Record{Event: audit.EventApproved, SQL: "SELECT 1 LIMIT 1"},
		audit.Record{Event: audit.EventRefused, SQL: "SELECT 1"}, // written before refusal codes
	)
	in.WriteString("not json\n")
	r, err := Read(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Refusals != 5 || r.Skipped != 1 {
		t.Fatalf("refusals %d skipped %d", r.Refusals, r.Skipped)
	}
	wantCodes := []Count{{Code: "E_MASKED_FILTER", N: 3}, {Code: "E_NO_LIMIT", N: 1}, {Code: Uncoded, N: 1}}
	if fmt.Sprint(r.ByCode) != fmt.Sprint(wantCodes) {
		t.Errorf("by code %v, want %v", r.ByCode, wantCodes)
	}
	wantTokens := []Count{{Code: "E_MASKED_FILTER", Token: "LIKE", N: 2}, {Code: "E_MASKED_FILTER", Token: "BETWEEN", N: 1},
		{Code: "E_NO_LIMIT", Token: NoToken, N: 1}, {Code: Uncoded, Token: NoToken, N: 1}}
	if fmt.Sprint(r.ByToken) != fmt.Sprint(wantTokens) {
		t.Errorf("by token %v, want %v", r.ByToken, wantTokens)
	}
	var out bytes.Buffer
	r.WriteText(&out, 10)
	for _, want := range []string{"5 refusals", "E_MASKED_FILTER", "LIKE", refusal.MaskedFilter.Title()} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, out.String())
		}
	}
}

func TestShape(t *testing.T) {
	for in, want := range map[string]string{
		"SELECT id, email FROM users WHERE email LIKE 'a%' LIMIT 10":                "SELECT id , id FROM id WHERE id LIKE '?' LIMIT N",
		"select lower(email) from app.users u -- why\nlimit 1":                      "SELECT LOWER ( id ) FROM id . id id --… LIMIT N",
		"SELECT `x`, \"y\", [z] FROM t /* c */ WHERE a = $1 AND b = $$x$$":          "SELECT `id` , \"id\" , [id] FROM id /*…*/ WHERE id = $N AND id = $$?$$",
		"SELECT myfunc(a) FROM t WHERE b = E'\\'' OR c = 0x1F OR d = 1.5e3 LIMIT 1": "SELECT id ( id ) FROM id WHERE id = '?' OR id = N OR id = N LIMIT N",
		"SELECT * FROM t WHERE a = '${secret_name}' AND b = @v LIMIT 1":             "SELECT * FROM id WHERE id = '?' AND id = @ id LIMIT N",
		"SELECT SLEEP(1), pg_read_file('x'), pg_mine(1) LIMIT 1":                    "SELECT SLEEP ( N ) , PG_READ_FILE ( '?' ) , id ( N ) LIMIT N",
		"SELECT 'unterminated":      "SELECT '?'",
		"SELECT ünïcode FROM tàble": "SELECT id FROM id",
	} {
		if got := Shape(in); got != want {
			t.Errorf("Shape(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	if got := Shape(strings.Repeat("SELECT ", 500)); len(got) > MaxShape+len("…") {
		t.Errorf("shape of %d bytes", len(got))
	}
}

// secrets are identifiers and literals that must never reach an export.
var secrets = []string{
	"customers", "emailaddr", "acme", "s3cr3t", "4242", "zzlit", "hunter", "ssn_col", "pg_mine", "x_tok",
	"secret_table", "q9", "1987",
}

// TestExportHoldsNoLiteralOrIdentifier proves the export on hand-written
// and random statements: no identifier, literal or reason of the input
// appears in it, and every string it holds comes from a closed vocabulary.
func TestExportHoldsNoLiteralOrIdentifier(t *testing.T) {
	recs := []audit.Record{
		refused("E_MASKED_FILTER", "LIKE", "SELECT emailaddr FROM customers WHERE emailaddr LIKE '%acme%' LIMIT 4242"),
		refused("E_UNKNOWN_NAME", "ssn_col", "SELECT ssn_col FROM \"customers\" WHERE x_tok = 1987 LIMIT 1"),
		refused("E_FORBIDDEN_TOKEN", "--", "SELECT 1 -- s3cr3t hunter\nLIMIT 1"),
		refused("E_FUNCTION", "pg_mine", "SELECT pg_mine(emailaddr) FROM customers LIMIT 1"),
		refused("E_PLACEHOLDER", "", "SELECT q9 FROM customers WHERE emailaddr = '${zzlit}' LIMIT 1"),
		refused("E_UNSUPPORTED_SYNTAX", "&&", "SELECT `customers`.`ssn_col` FROM customers WHERE a && $zzlit$hunter$zzlit$ LIMIT 1"),
		refused("E_FORBIDDEN_TOKEN", "@", "SELECT @acme := 's3cr3t' /* hunter */ LIMIT 1"),
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		recs = append(recs, randomRefusal(rng))
	}
	r, err := Read(logOf(t, recs...))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.WriteExport(&b, "test"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, s := range append(secrets, randomWords...) {
		if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
			t.Errorf("the export holds %q", s)
		}
	}
	var v any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	walkStrings(v, func(s string) {
		if !vocabulary(s) {
			t.Errorf("the export holds %q, outside the closed vocabulary", s)
		}
	})
}

// randomWords collects the identifiers and literals randomRefusal made.
var randomWords []string

func randomWord(rng *rand.Rand) string {
	const letters = "bcdfghjklmnpqrstvwxz"
	n := 6 + rng.IntN(5)
	w := make([]byte, n)
	for i := range w {
		w[i] = letters[rng.IntN(len(letters))]
	}
	randomWords = append(randomWords, string(w))
	return string(w)
}

func randomRefusal(rng *rand.Rand) audit.Record {
	parts := []func() string{
		func() string { return randomWord(rng) },
		func() string { return "'" + randomWord(rng) + "'" },
		func() string { return "`" + randomWord(rng) + "`" },
		func() string { return `"` + randomWord(rng) + `"` },
		func() string { w := randomWord(rng); return "$" + w + "$" + randomWord(rng) + "$" + w + "$" },
		func() string { return "/* " + randomWord(rng) + " */" },
		func() string { return "-- " + randomWord(rng) + "\n" },
		func() string { return fmt.Sprint(1_000_000 + rng.IntN(1_000_000)) },
		func() string { return "'${" + randomWord(rng) + "}'" },
		func() string { return randomWord(rng) + "(" + randomWord(rng) + ")" },
		func() string {
			return []string{"SELECT", "FROM", "WHERE", "=", "LIKE", "AND", ",", "(", ")", "LIMIT"}[rng.IntN(10)]
		},
	}
	var b strings.Builder
	for range 3 + rng.IntN(20) {
		b.WriteString(parts[rng.IntN(len(parts))]())
		b.WriteByte(" \n\t"[rng.IntN(3)])
	}
	codes := refusal.Codes()
	return refused(string(codes[rng.IntN(len(codes))]), randomWord(rng), b.String())
}

func walkStrings(v any, f func(string)) {
	switch v := v.(type) {
	case string:
		f(v)
	case []any:
		for _, x := range v {
			walkStrings(x, f)
		}
	case map[string]any:
		for k, x := range v {
			f(k)
			walkStrings(x, f)
		}
	}
}

// vocabulary reports whether s is made only of shape tokens, codes,
// engine names and the export's own keys.
func vocabulary(s string) bool {
	if refusal.Code(s).Known() || s == Uncoded || exportWords[s] {
		return true
	}
	for _, tok := range strings.Fields(s) {
		if !ShapeToken(tok) {
			return false
		}
	}
	return true
}

var exportWords = map[string]bool{
	"locksql_version": true, "test": true, "refusals": true, "skipped": true, "by_code": true,
	"by_construct": true, "shapes": true, "code": true, "token": true, "n": true, "engine": true, "shape": true,
	"postgres": true, "note": true, ExportNote: true,
}

// FuzzShapeVocabulary checks the closed vocabulary on any input.
func FuzzShapeVocabulary(f *testing.F) {
	f.Add("SELECT a FROM b WHERE c = 'd' LIMIT 1")
	f.Add("SELECT $x$ $y$ \xff `a\x00` [q")
	f.Fuzz(func(t *testing.T, sql string) {
		for _, tok := range strings.Fields(Shape(sql)) {
			if !ShapeToken(tok) {
				t.Fatalf("Shape(%q) holds %q", sql, tok)
			}
		}
		if tok := ExportToken(sql); !ShapeToken(tok) && tok != NoToken {
			t.Fatalf("ExportToken(%q) = %q", sql, tok)
		}
	})
}
