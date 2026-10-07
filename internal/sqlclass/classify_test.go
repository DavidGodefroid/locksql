package sqlclass

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestLexTokens(t *testing.T) {
	toks, err := Lex(Postgres, `select "A""b", E'x\'y', $q$z$q$, f(1, (2)) from t`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Token{
		{TokWord, "SELECT", 0},
		{TokQuotedIdent, `"A""b"`, 0},
		{TokPunct, ",", 0},
		{TokString, `E'x\'y'`, 0},
		{TokPunct, ",", 0},
		{TokString, "$q$z$q$", 0},
		{TokPunct, ",", 0},
		{TokWord, "F", 0},
		{TokPunct, "(", 1},
		{TokNumber, "1", 1},
		{TokPunct, ",", 1},
		{TokPunct, "(", 2},
		{TokNumber, "2", 2},
		{TokPunct, ")", 1},
		{TokPunct, ")", 0},
		{TokWord, "FROM", 0},
		{TokWord, "T", 0},
	}
	if !reflect.DeepEqual(toks, want) {
		t.Errorf("Lex =\n%v\nwant\n%v", toks, want)
	}
}

func TestLexQuotingPerDialect(t *testing.T) {
	cases := []struct {
		d    Dialect
		sql  string
		kind TokKind
	}{
		{MySQL, `"x"`, TokString},
		{MySQL, "`x`", TokQuotedIdent},
		{Postgres, `"x"`, TokQuotedIdent},
		{SQLite, `"x"`, TokQuotedIdent},
		{SQLite, "`x`", TokQuotedIdent},
		{SQLite, "[x]", TokQuotedIdent},
		{Postgres, "$$x$$", TokString},
		{Postgres, "e'x'", TokString},
	}
	for _, c := range cases {
		toks, err := Lex(c.d, c.sql)
		if err != nil {
			t.Errorf("%v %s: %v", c.d, c.sql, err)
			continue
		}
		if len(toks) != 1 || toks[0].Kind != c.kind || toks[0].Text != c.sql {
			t.Errorf("%v %s: got %v, want one token of kind %d", c.d, c.sql, toks, c.kind)
		}
	}
}

func TestTokenName(t *testing.T) {
	cases := []struct {
		d    Dialect
		sql  string
		want string
	}{
		{MySQL, "email", "EMAIL"},
		{MySQL, "`e``mail`", "E`MAIL"},
		{Postgres, `"Mixed""Case"`, `MIXED"CASE`},
		{SQLite, "[order]", "ORDER"},
		{MySQL, "'str'", ""},
		{MySQL, "ſleep", "SLEEP"},
	}
	for _, c := range cases {
		toks, err := Lex(c.d, c.sql)
		if err != nil || len(toks) != 1 {
			t.Fatalf("%s: %v %v", c.sql, toks, err)
		}
		if got := toks[0].Name(); got != c.want {
			t.Errorf("%s: Name() = %q, want %q", c.sql, got, c.want)
		}
	}
}

func TestLexRefusalType(t *testing.T) {
	_, err := Lex(MySQL, "SELECT 1 -- x")
	var r *Refusal
	if !errors.As(err, &r) || r.Reason == "" {
		t.Fatalf("Lex error = %v (%T), want *Refusal", err, err)
	}
}

func TestClassifyKeepsSQL(t *testing.T) {
	st, err := Classify(MySQL, "  SELECT id FROM t WHERE s = 'a;b'  LIMIT 5 ; \n", 200)
	if err != nil {
		t.Fatal(err)
	}
	if want := "SELECT id FROM t WHERE s = 'a;b'  LIMIT 5"; st.SQL != want {
		t.Errorf("SQL = %q, want %q", st.SQL, want)
	}
}

func TestClassifyNoMaxRows(t *testing.T) {
	st, err := Classify(SQLite, "SELECT id FROM t LIMIT 100000", 0)
	if err != nil || st.Limit != 100000 {
		t.Fatalf("Classify with maxRows 0 = %+v, %v", st, err)
	}
	if _, err := Classify(SQLite, "SELECT id FROM t", 0); err == nil {
		t.Fatal("maxRows 0 must still require a LIMIT")
	}
}

func TestRefusalDoesNotQuoteLiterals(t *testing.T) {
	_, err := Classify(MySQL, "SET PASSWORD = 'hunter2'", 200)
	if err == nil {
		t.Fatal("accepted")
	}
	if got := err.Error(); strings.Contains(got, "hunter2") {
		t.Errorf("refusal %q quotes the literal", got)
	}
}

func TestClassOrderMatchesTiers(t *testing.T) {
	if !(Read < Write && Write < DDL && DDL < Admin) {
		t.Fatal("class order must be read < write < ddl < admin")
	}
	for c, want := range map[Class]string{Read: "read", Write: "write", DDL: "ddl", Admin: "admin"} {
		if c.String() != want {
			t.Errorf("%d.String() = %q, want %q", c, c.String(), want)
		}
	}
}

func TestDialectFor(t *testing.T) {
	for engine, want := range map[string]Dialect{"mariadb": MySQL, "mysql": MySQL, "postgres": Postgres, "sqlite": SQLite} {
		got, err := DialectFor(engine)
		if err != nil || got != want {
			t.Errorf("DialectFor(%q) = %v, %v; want %v", engine, got, err, want)
		}
	}
	if _, err := DialectFor("oracle"); err == nil {
		t.Error("DialectFor(oracle) must fail")
	}
}
