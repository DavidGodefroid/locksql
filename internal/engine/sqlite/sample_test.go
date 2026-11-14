package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// SampleColumn reads at most n non-null values as text, cut to
// SampleBytes, with the names quoted as identifiers.
func TestSampleColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE "odd ""t""" (id INTEGER PRIMARY KEY, "na""me" TEXT)`,
		`INSERT INTO "odd ""t""" ("na""me") VALUES ('Alice Dupont'), (NULL), ('Bob Martin'), (42), ('` + strings.Repeat("x", 1000) + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()
	s := connect(t, path, config.TierRead)
	c := engine.ColumnInfo{DB: "main", Table: `odd "t"`, Column: `na"me`, Type: "TEXT"}
	got, err := engine.SampleColumn(context.Background(), s, "", c, 3)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Alice Dupont", "Bob Martin", "42"}; !slices.Equal(got, want) {
		t.Errorf("SampleColumn = %q, want %q", got, want)
	}
	all, err := engine.SampleColumn(context.Background(), s, "", c, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 || len(all[3]) != engine.SampleBytes {
		t.Errorf("SampleColumn (20) = %d values, last %d bytes", len(all), len(all[len(all)-1]))
	}
	if _, err := engine.SampleColumn(context.Background(), s, "", engine.ColumnInfo{DB: "nope", Table: "t", Column: "c"}, 3); err == nil {
		t.Error("an unknown schema was sampled")
	}
}
