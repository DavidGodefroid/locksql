package postgres

import (
	"errors"
	"testing"
)

// chain is a step whose objects each use the next one, n levels in all
// (relation i uses relation i+1); next(i) == 0 ends it.
func chain(n uint32, calls *int) func(rels, funcs []uint32) ([]uint32, []uint32, error) {
	return func(rels, funcs []uint32) ([]uint32, []uint32, error) {
		*calls++
		var out []uint32
		for _, r := range rels {
			if r < n {
				out = append(out, r+1)
			}
		}
		return out, nil, nil
	}
}

// The walk reads at most maxObjectDepth levels and fails closed past
// them: what nests deeper would go unhashed.
func TestFollowDepthBound(t *testing.T) {
	calls := 0
	if err := follow([]uint32{1}, nil, maxObjectDepth, chain(maxObjectDepth, &calls)); err != nil || calls != maxObjectDepth {
		t.Fatalf("%d levels: %v after %d steps", maxObjectDepth, err, calls)
	}
	calls = 0
	if err := follow([]uint32{1}, nil, maxObjectDepth, chain(maxObjectDepth+1, &calls)); !errors.Is(err, errTooDeep) || calls != maxObjectDepth {
		t.Fatalf("%d levels: %v after %d steps", maxObjectDepth+1, err, calls)
	}
}

// A cycle (a view over a function reading the view's table, ...) ends
// once every object was seen, however short the bound.
func TestFollowCycle(t *testing.T) {
	calls := 0
	step := func(rels, funcs []uint32) ([]uint32, []uint32, error) {
		calls++
		return []uint32{1, 2}, []uint32{7}, nil
	}
	if err := follow([]uint32{1}, []uint32{7}, 3, step); err != nil || calls != 2 {
		t.Fatalf("cycle: %v after %d steps", err, calls)
	}
}

// A function chain counts like a relation chain, and a step error ends
// the walk with it.
func TestFollowFunctionsAndErrors(t *testing.T) {
	deep := func(rels, funcs []uint32) ([]uint32, []uint32, error) {
		return nil, []uint32{funcs[0] + 1}, nil
	}
	if err := follow(nil, []uint32{1}, 4, deep); !errors.Is(err, errTooDeep) {
		t.Fatalf("function chain: %v", err)
	}
	boom := errors.New("boom")
	if err := follow([]uint32{1}, nil, 4, func([]uint32, []uint32) ([]uint32, []uint32, error) { return nil, nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("step error: %v", err)
	}
	if err := follow(nil, nil, 4, func([]uint32, []uint32) ([]uint32, []uint32, error) { t.Fatal("step on nothing"); return nil, nil, nil }); err != nil {
		t.Fatal(err)
	}
}
