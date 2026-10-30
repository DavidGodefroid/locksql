package client

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// A pending or stale run (hub mode) tells the agent to stop and wait, with
// the ticket to run once decided.
func TestFormatRunPendingAndStale(t *testing.T) {
	var b bytes.Buffer
	FormatRun(&b, ipc.RunResult{Status: "pending", Ticket: "01JB0000000000000000000000", Lock: "locksql"})
	if s := b.String(); !strings.Contains(s, "Pending human approval: ticket 01JB0000000000000000000000 on locksql") || !strings.Contains(s, "End your turn") {
		t.Errorf("pending: %q", s)
	}
	b.Reset()
	FormatRun(&b, ipc.RunResult{Status: "stale", Ticket: "NEW", StaleTicket: "OLD", Lock: "locksql"})
	if s := b.String(); !strings.Contains(s, "ticket OLD") || !strings.Contains(s, "ticket NEW") {
		t.Errorf("stale: %q", s)
	}
}
