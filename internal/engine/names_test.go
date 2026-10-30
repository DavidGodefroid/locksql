package engine

import (
	"errors"
	"fmt"
	"testing"
)

func TestSplitName(t *testing.T) {
	for in, want := range map[string][2]string{
		"users":        {"", "users"},
		"App.Users":    {"app", "users"},
		"`app`.`a.b`":  {"app", "a.b"},
		"`a``b`":       {"", "a`b"},
		`"Mixed"."T"`:  {"mixed", "t"},
		`"a""b"`:       {"", `a"b`},
		"[main].[t]":   {"main", "t"},
		"main.\"x.y\"": {"main", "x.y"},
	} {
		if sc, tb := SplitName(in); sc != want[0] || tb != want[1] {
			t.Errorf("SplitName(%q) = %q, %q", in, sc, tb)
		}
	}
}

func TestUncounted(t *testing.T) {
	base := errors.New("mysql: the write reaches tables a ROLLBACK may not undo")
	err := fmt.Errorf("wrapped: %w", Uncounted(base))
	if !errors.Is(err, ErrUncounted) || !errors.Is(err, base) || err.Error() != "wrapped: "+base.Error() {
		t.Fatalf("%v", err)
	}
	if errors.Is(base, ErrUncounted) {
		t.Fatal("an unmarked error matches")
	}
}
