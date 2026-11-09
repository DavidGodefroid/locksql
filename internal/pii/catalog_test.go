package pii

import (
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// A PostgreSQL catalog: ColumnInfo.DB is the schema.
var pgCols = []engine.ColumnInfo{
	{DB: "public", Table: "customers", Column: "id"},
	{DB: "public", Table: "customers", Column: "name"},
	{DB: "sales", Table: "customers", Column: "name"},
	{DB: "public", Table: "orders", Column: "customer_name"},
}

func TestMatchesColumnUsesTheFirstSegmentAsGiven(t *testing.T) {
	for p, want := range map[string]bool{
		"public.customers.name": true,
		"PUBLIC.Customers.NAME": true,
		"app.customers.name":    false, // the database, not the schema
		"*.customers.name":      true,
		"*.*.*name":             true,
		"*.*.iban":              false,
	} {
		if got := MatchesColumn(p, pgCols); got != want {
			t.Errorf("MatchesColumn(%q) = %v, want %v", p, got, want)
		}
	}
	if got := Unmatched([]string{"public.customers.name", "app.customers.name", "*.*.iban"}, pgCols); !slices.Equal(got, []string{"app.customers.name", "*.*.iban"}) {
		t.Errorf("Unmatched = %v", got)
	}
}

func TestCandidates(t *testing.T) {
	if got := Candidates("app.customers.name", pgCols); !slices.Equal(got, []string{"public.customers.name", "sales.customers.name"}) {
		t.Errorf("same table and column: %v", got)
	}
	if got := Candidates("app.clients.name", pgCols); !slices.Equal(got, []string{"public.customers.name", "sales.customers.name"}) {
		t.Errorf("same column: %v", got)
	}
	if got := Candidates("app.clients.iban", pgCols); len(got) != 0 {
		t.Errorf("nothing near: %v", got)
	}
	var many []engine.ColumnInfo
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		many = append(many, engine.ColumnInfo{DB: s, Table: "t", Column: "c"})
	}
	if got := Candidates("x.t.c", many); len(got) != maxCandidates || got[0] != "a.t.c" {
		t.Errorf("capped: %v", got)
	}
	if got := FirstSegments(pgCols); !slices.Equal(got, []string{"public", "sales"}) {
		t.Errorf("FirstSegments = %v", got)
	}
	if !Glob("*.*.email") || !Glob("app.users.*mail") || Glob("app.users.email") {
		t.Error("Glob")
	}
}
