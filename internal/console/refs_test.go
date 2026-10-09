package console

import (
	"strings"
	"testing"
)

func TestRefStore(t *testing.T) {
	var r refStore
	n := r.begin()
	a, b := r.put(n, 0, 1, "alice@example.com"), r.put(n, 1, 1, "alice@example.com")
	if a == b {
		t.Fatalf("equal values share a reference: %s", a)
	}
	if a != "r1.1.2" {
		t.Errorf("first reference %q", a)
	}
	if v, ok := r.get(a); !ok || v != "alice@example.com" {
		t.Errorf("get(%s) = %q %v", a, v, ok)
	}
	if _, ok := r.get("r1.9.9"); ok {
		t.Error("unknown cell resolved")
	}
}

func TestRefStoreEviction(t *testing.T) {
	var r refStore
	first := r.put(r.begin(), 0, 0, "v")
	for i := 0; i < maxRefResults; i++ {
		r.put(r.begin(), 0, 0, "w")
	}
	if _, ok := r.get(first); ok {
		t.Error("a reference to an evicted result resolved")
	}
	n := r.begin()
	if name := r.put(n, 0, 0, strings.Repeat("x", maxRefBytes+1)); name != "" {
		t.Errorf("a cell over the budget got a reference: %s", name)
	}
}
