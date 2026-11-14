//go:build integration && linux

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// undecided reports whether raw is the pending answer to the run of a
// ticket the hub's decision has not reached yet (#234: pending, never an
// error).
func undecided(raw json.RawMessage) bool {
	var p struct{ Status string }
	return json.Unmarshal(raw, &p) == nil && p.Status == "pending"
}

// untilDecided calls call (a run of a decided ticket, decoding its answer
// into the out it is given) until the decision has reached the console or
// for d, every poll, and decodes the last answer into out.
func untilDecided(t *testing.T, d, poll time.Duration, call func(out any) *ipc.RPCError, out any) *ipc.RPCError {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		var raw json.RawMessage
		e := call(&raw)
		if e == nil && undecided(raw) && time.Now().Before(deadline) {
			time.Sleep(poll)
			continue
		}
		if e == nil && out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				t.Fatal(err)
			}
		}
		return e
	}
}
