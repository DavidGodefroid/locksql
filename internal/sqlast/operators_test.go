package sqlast

import (
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Operators lists, as PostgreSQL names them, the operators a statement
// uses: explicit ones, the operators LIKE, IN and BETWEEN stand for, and
// the comparisons any statement may use implicitly (joins, sorts, k
// counts).
func TestOperators(t *testing.T) {
	st, err := Parse(sqlclass.Postgres, "SELECT a || b AS c, -d AS e FROM t WHERE x LIKE 'a%' AND y NOT ILIKE 'b' AND z IN (1, 2) AND w BETWEEN 1 AND 2 AND v != 3 AND j -> 'k' = '1' LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}
	got := Operators(st)
	for _, op := range []string{"||", "-", "~~", "!~~*", "=", "<>", "<", ">", "<=", ">=", "->"} {
		if !slices.Contains(got, op) {
			t.Errorf("Operators = %v, want %s", got, op)
		}
	}
	for _, op := range []string{"!=", "AND", "LIKE", "NOT"} {
		if slices.Contains(got, op) {
			t.Errorf("Operators = %v, must not hold %s", got, op)
		}
	}
	if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("Operators = %v, want sorted and unique", got)
	}
}
