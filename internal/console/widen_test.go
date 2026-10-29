package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/ipc"
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

// keySecretIO presses keys while the first value is asked, then answers it.
type keySecretIO struct {
	*fakeIO
	during func()
}

func (k *keySecretIO) AskSecret(ctx context.Context, prompt string) ([]byte, error) {
	if f := k.during; f != nil {
		k.during = nil
		f()
	}
	return k.fakeIO.AskSecret(ctx, prompt)
}

// A control key or command used while the approval prompt waits never
// widens a switch (lockkit #2): at level 2 no second finger prompt nests in
// the pending one, and the finger prompt names the decision it takes.
func TestNoWideningWhileApprovalWaits(t *testing.T) {
	v := &fingerprint.Fake{}
	var h *harness
	h = newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Fingerprint = true
		c.Approver = &keyApprover{Approver: newFingerprintApprover(c.IO, v, "left-index-finger", time.Second), during: func() { h.s.Key(KeyShiftTab) }}
	})
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	out := ansi.ReplaceAllString(h.io.output(), "")
	if h.s.autoApprove() || v.Calls != 1 || !strings.Contains(out, "auto mode: not while a prompt waits") {
		t.Fatalf("auto %v, finger calls %d:\n%s", h.s.autoApprove(), v.Calls, out)
	}
	if !strings.Contains(out, "Place your left index finger on the reader to approve the request above") {
		t.Fatalf("the finger prompt does not name its decision:\n%s", out)
	}

	var h0 *harness
	h0 = newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Approver = &keyApprover{Approver: newTypedApprover(c.IO), during: func() {
			h0.s.Key(KeyShiftTab)
			h0.s.Key(KeyCtrlO)
			h0.s.Command(context.Background(), ":unmask")
		}}
	})
	pr = h0.plan(t, selectUsers, false)
	h0.io.answers = []string{"y"}
	h0.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h0.s.autoApprove() || h0.s.showResults || h0.s.allowUnmask {
		t.Fatalf("widened during a prompt: auto %v results %v unmask %v", h0.s.autoApprove(), h0.s.showResults, h0.s.allowUnmask)
	}
	if n := strings.Count(h0.io.output(), "not while a prompt waits"); n != 3 {
		t.Fatalf("refusal printed %d times:\n%s", n, h0.io.output())
	}
	if h0.io.promptCount() != 1 {
		t.Fatalf("prompts %q: a decision nested in the approval", h0.io.prompts)
	}
	// Between prompts the keys work again.
	h0.s.Key(KeyShiftTab)
	if !h0.s.autoApprove() {
		t.Fatal("auto mode refused with no prompt waiting")
	}
}

// The value prompts inside the approval frame are prompts too.
func TestNoWideningWhileValueAsked(t *testing.T) {
	var h *harness
	h = newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.IO = &keySecretIO{fakeIO: c.IO.(*fakeIO), during: func() { h.s.Key(KeyShiftTab) }}
	})
	pr := h.plan(t, typedQ, false)
	h.io.secrets, h.io.answers = []string{"alice@example.com"}, []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.s.autoApprove() || !strings.Contains(h.io.output(), "auto mode: not while a prompt waits") {
		t.Fatalf("auto mode switched on during a value prompt:\n%s", h.io.output())
	}
}

// Narrowing stays allowed while a prompt waits: auto mode can be switched
// off during an unmasked query, which auto mode always prompts.
func TestNarrowingWhileApprovalWaits(t *testing.T) {
	var h *harness
	h = newHarness(t, uatProfile(), skip, allowUnmask, func(c *ServerConfig) {
		c.Approver = &keyApprover{Approver: newTypedApprover(c.IO), during: func() { h.s.Key(KeyShiftTab) }}
	})
	pr := h.plan(t, selectUsers, true)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.s.autoApprove() || strings.Contains(h.io.output(), "not while a prompt waits") {
		t.Fatalf("auto mode not switched off during a prompt:\n%s", h.io.output())
	}
}
