package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// The triggers of the tables a write names, for its hub ticket (#120).
func TestTriggers(t *testing.T) {
	path := setupDB(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE log (id INT)`,
		`CREATE TRIGGER items_log AFTER UPDATE ON items BEGIN INSERT INTO log VALUES (NEW.id); END`,
		`CREATE TRIGGER "Items Ins" INSTEAD OF INSERT ON emails BEGIN SELECT 1; END`,
		`CREATE TRIGGER big_del DELETE ON big BEGIN SELECT 1; -- a comment
END`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s := connect(t, path, config.TierWrite)
	ctx := context.Background()
	got, err := engine.TriggersOf(ctx, s, "", []string{"update", "ITEMS", "set", "main.\"emails\"", "big", "uniq"})
	want := []string{"trigger main.big.big_del (before delete)", "trigger main.emails.Items Ins (instead of insert)", "trigger main.items.items_log (after update)"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("triggers %q, %v; want %q", got, err, want)
	}
	if got, err := engine.TriggersOf(ctx, s, "", []string{"items_log", "log"}); err != nil || len(got) != 0 {
		t.Fatalf("no triggers: %q, %v", got, err)
	}
	if _, err := engine.TriggersOf(ctx, s, "nope", []string{"items"}); err == nil {
		t.Fatal("an unknown database was accepted")
	}
}

// VACUUM cannot be counted: a typed refusal (#120).
func TestRunCountedVacuumUncounted(t *testing.T) {
	s := connect(t, setupDB(t), config.TierAdmin)
	st, err := sqlclass.Classify(sqlclass.SQLite, "VACUUM", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.RunCounted(context.Background(), s, "", st, 10, func(int64) error { return nil }); !errors.Is(err, engine.ErrUncounted) {
		t.Fatalf("VACUUM: %v", err)
	}
}

func TestTriggerWhen(t *testing.T) {
	for def, want := range map[string]string{
		"CREATE TRIGGER x AFTER UPDATE OF a ON t BEGIN SELECT 1; END":          "after update",
		"CREATE TRIGGER beginning INSERT ON t BEGIN SELECT 1; -- c\nEND":       "before insert",
		"create temp trigger if not exists x instead of delete on v begin end": "instead of delete",
		"CREATE TRIGGER x ON t": "timing unknown",
	} {
		if got := triggerWhen(def); got != want {
			t.Errorf("triggerWhen(%q) = %q, want %q", def, got, want)
		}
	}
}
