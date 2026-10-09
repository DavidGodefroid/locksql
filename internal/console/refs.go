package console

import (
	"fmt"
	"strconv"
	"strings"
)

// Bounds of the reference store: the oldest results are forgotten first.
const (
	maxRefResults = 50
	maxRefBytes   = 16 << 20
)

// refStore keeps the clear values of the redacted cells of the last
// results, so that the agent can filter on a cell ('${rN.R.C}') without
// seeing its value. It lives in the console's memory and dies with it.
type refStore struct {
	next    int
	results []refResult // oldest first
	bytes   int
}

type refResult struct {
	n     int
	cells map[[2]int]string
	bytes int
}

// begin opens the next result and returns its number.
func (r *refStore) begin() int {
	r.next++
	r.results = append(r.results, refResult{n: r.next, cells: map[[2]int]string{}})
	for len(r.results) > maxRefResults {
		r.evict()
	}
	return r.next
}

// put stores the value of a cell (0-based row and column) of result n and
// returns its reference name, or "" when the store cannot hold it.
func (r *refStore) put(n, row, col int, v string) string {
	if len(v) > maxRefBytes {
		return ""
	}
	for r.bytes+len(v) > maxRefBytes && len(r.results) > 1 {
		r.evict()
	}
	res := r.find(n)
	if res == nil || r.bytes+len(v) > maxRefBytes {
		return ""
	}
	res.cells[[2]int{row, col}] = v
	res.bytes += len(v)
	r.bytes += len(v)
	return fmt.Sprintf("r%d.%d.%d", n, row+1, col+1)
}

// get resolves a reference name "rN.R.C".
func (r *refStore) get(name string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(name, "r"), ".")
	if len(parts) != 3 {
		return "", false
	}
	var nums [3]int
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 1 {
			return "", false
		}
		nums[i] = x
	}
	res := r.find(nums[0])
	if res == nil {
		return "", false
	}
	v, ok := res.cells[[2]int{nums[1] - 1, nums[2] - 1}]
	return v, ok
}

func (r *refStore) find(n int) *refResult {
	for i := range r.results {
		if r.results[i].n == n {
			return &r.results[i]
		}
	}
	return nil
}

func (r *refStore) evict() {
	r.bytes -= r.results[0].bytes
	r.results = r.results[1:]
}
