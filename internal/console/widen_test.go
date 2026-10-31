package console

import (
	"context"
	"strings"
	"testing"
)

// keyApprover presses keys while the first decision is asked, then answers
// it.
type keyApprover struct {
	Approver
	during func()
}

func (a *keyApprover) Approve(ctx context.Context, d Decision) Result {
	if f := a.during; f != nil {
		a.during = nil
		f()
	}
	return a.Approver.Approve(ctx, d)
}

// A control key or command used while one of the console's own decisions
// waits at the terminal (here :unmask) never widens a switch (lockkit #2):
// no decision nests in the pending one.
func TestNoWideningWhileConsoleDecisionWaits(t *testing.T) {
	var h *harness
	h = newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Approver = &keyApprover{Approver: newTypedApprover(c.IO), during: func() {
			h.s.Key(KeyCtrlO)
			h.s.Command(context.Background(), ":results")
		}}
	})
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.allowUnmask() {
		t.Fatalf("unmask not allowed:\n%s", h.io.output())
	}
	if h.s.showResults() {
		t.Fatal("results widened during a prompt")
	}
	if n := strings.Count(h.io.output(), "not while a prompt waits"); n != 2 {
		t.Fatalf("refusal printed %d times:\n%s", n, h.io.output())
	}
	if h.io.promptCount() != 1 {
		t.Fatalf("prompts %q: a decision nested in :unmask", h.io.prompts)
	}
	// Between prompts the keys work again.
	h.s.Key(KeyCtrlO)
	if !h.s.showResults() {
		t.Fatal("Ctrl-O refused with no prompt waiting")
	}
}
