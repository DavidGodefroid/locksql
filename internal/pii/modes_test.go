package pii

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

func TestMaskValueModes(t *testing.T) {
	tok := NewTokens()
	cases := []struct {
		mode string
		in   any
		want string
	}{
		{ModeRedact, "alice@example.com", Redacted},
		{ModeRedact, []byte{1, 2, 3}, Redacted},
		{ModePartial, "alice@example.com", "a***(17)"},
		{ModeEmail, "alice@example.com", "a***@example.com"},
		{ModeEmail, "not an address", "n***(14)"},
	}
	for _, c := range cases {
		if got := MaskValue(c.in, c.mode, tok); got != c.want {
			t.Errorf("%s(%v) = %v, want %v", c.mode, c.in, got, c.want)
		}
	}
	a, b := MaskValue("alice@example.com", ModeHash, tok), MaskValue("alice@example.com", ModeHash, tok)
	if a != b || !strings.HasPrefix(a.(string), "tok_") || strings.Contains(a.(string), "alice") {
		t.Errorf("hash tokens %v %v", a, b)
	}
	if MaskValue("bob@example.com", ModeHash, tok) == a {
		t.Error("two values share a token")
	}
	if NewTokens().Token("alice@example.com") == a {
		t.Error("tokens are stable across sessions")
	}
	v, isTok, ok := tok.Lookup(a.(string))
	if !isTok || !ok || v != "alice@example.com" {
		t.Errorf("Lookup = %q %v %v", v, isTok, ok)
	}
	if _, isTok, ok := tok.Lookup("tok_aaaaaaaaaaaaaaaaaaaa"); !isTok || ok {
		t.Error("unknown token resolved")
	}
	if _, isTok, _ := tok.Lookup("hello"); isTok {
		t.Error("plain text taken for a token")
	}
}

func TestRulesModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := `[[mask]]
column = "app.users.email"
mode = "hash"

[[mask]]
column = "*.*.email"
mode = "partial"

[[mask]]
column = "app.users.salary"
mode = "redact"
`
	if err := os.WriteFile(filepath.Join(dir, RulesFile), []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := r.Mode("app", "users", "salary"); !ok || m != ModeRedact {
		t.Errorf("salary mode %q %v", m, ok)
	}
	// Two rules with different modes: the strictest.
	if m, _ := r.Mode("app", "users", "email"); m != ModeRedact {
		t.Errorf("email mode %q", m)
	}
	if m, _ := r.Mode("app", "orders", "email"); m != ModePartial {
		t.Errorf("orders.email mode %q", m)
	}
	if err := SaveRules(dir, r); err != nil {
		t.Fatal(err)
	}
	back, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.Modes["app.users.email"] != ModeHash || back.Modes["*.*.email"] != ModePartial || len(back.Modes) != 2 {
		t.Errorf("modes after save: %v", back.Modes)
	}
	if err := os.WriteFile(filepath.Join(dir, RulesFile), []byte("[[mask]]\ncolumn = \"a.b.c\"\nmode = \"rot13\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(dir); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestMaskOutputs(t *testing.T) {
	res := engine.Result{
		Columns: []engine.ResultColumn{{Label: "x"}, {Label: "note"}, {Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "email"}},
		Rows:    [][]any{{"alice@example.com", "mail bob@example.org", "carol@example.net"}},
	}
	outs := []sqlast.Output{{Label: "X", Mask: ModeRedact}, {Label: "NOTE"}, {}}
	r := Rules{Mask: []string{"app.users.email"}}
	ds, _ := Detectors([]string{"email"})
	if err := MaskOutputs(&res, outs, r, ds, NewTokens(), true); err != nil {
		t.Fatal(err)
	}
	row := res.Rows[0]
	if row[0] != Redacted || strings.Contains(row[1].(string), "bob@") || row[2] != Redacted {
		t.Errorf("masked row %v", row)
	}
	// A label the analysis did not expect: refused.
	res = engine.Result{Columns: []engine.ResultColumn{{Label: "y"}}, Rows: [][]any{{"v"}}}
	if err := MaskOutputs(&res, []sqlast.Output{{Label: "X"}}, r, ds, nil, true); err == nil {
		t.Error("unexpected label accepted")
	}
	if err := MaskOutputs(&res, nil, r, ds, nil, true); err == nil {
		t.Error("column count mismatch accepted")
	}
}
