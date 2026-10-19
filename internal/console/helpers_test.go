package console

import (
	"context"
	"strings"
)

// twoMisses spends two non-matching fingers on a: the next miss is the
// third in a row.
func twoMisses(a Approver) Approver {
	for range 2 {
		a.Approve(context.Background(), Decision{Prompt: "earlier decision", Expected: "y"})
	}
	return a
}

// containsLine reports whether a line printed on io contains sub.
func containsLine(io *fakeIO, sub string) bool {
	io.mu.Lock()
	defer io.mu.Unlock()
	for _, l := range io.out {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
