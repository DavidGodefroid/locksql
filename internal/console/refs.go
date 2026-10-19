package console

import (
	"strconv"

	kpii "github.com/DavidGodefroid/lockkit/pii"
)

// Bounds of the reference store: the oldest results are forgotten first.
const (
	maxRefResults = kpii.MaxRefResults
	maxRefBytes   = kpii.MaxRefBytes
)

// refStore keeps the clear values of the redacted cells of the last
// results, so that the agent can filter on a cell ('${rN.R.C}') without
// seeing its value. It lives in the console's memory and dies with it.
// It is lockkit's reference store keyed by "<row>.<column>", 1-based.
type refStore struct {
	s kpii.RefStore
}

// begin opens the next result and returns its number.
func (r *refStore) begin() int { return r.s.Begin() }

// put stores the value of a cell (0-based row and column) of result n and
// returns its reference name "rN.R.C", or "" when the store cannot hold it.
func (r *refStore) put(n, row, col int, v string) string {
	return r.s.Put(n, strconv.Itoa(row+1)+"."+strconv.Itoa(col+1), v)
}

// get resolves a reference name "rN.R.C".
func (r *refStore) get(name string) (string, bool) { return r.s.Get(name) }
