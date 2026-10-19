package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

func TestTypedApproverYes(t *testing.T) {
	io := &fakeIO{answers: []string{"Y"}}
	a := newTypedApprover(io)
	r := a.Approve(context.Background(), Decision{Prompt: "Approve? [y/N] ", Expected: "y"})
	if r.Outcome != Approved {
		t.Fatalf("outcome = %v", r.Outcome)
	}
	if a.Mode() != "session" {
		t.Fatalf("mode = %q", a.Mode())
	}
}

func TestTypedApproverProductionExactName(t *testing.T) {
	io := &fakeIO{answers: []string{"UAT", "uat"}}
	a := newTypedApprover(io)
	d := Decision{Prompt: "Type uat: ", Expected: "uat", Production: true}
	if r := a.Approve(context.Background(), d); r.Outcome != Denied || r.Answer != "UAT" {
		t.Fatalf("got %+v, want Denied with the answer", r)
	}
	if r := a.Approve(context.Background(), d); r.Outcome != Approved {
		t.Fatalf("got %+v", r)
	}
}

func TestTypedApproverRetypeAndUnanswered(t *testing.T) {
	io := &fakeIO{answers: []string{"r"}}
	a := newTypedApprover(io)
	if r := a.Approve(context.Background(), Decision{Prompt: "p", Expected: "y", Retype: "r"}); r.Outcome != RetypeRequested {
		t.Fatalf("got %+v", r)
	}
	io2 := &fakeIO{timeout: true}
	if r := newTypedApprover(io2).Approve(context.Background(), Decision{Prompt: "p", Expected: "y"}); r.Outcome != Unanswered {
		t.Fatalf("got %+v", r)
	}
}

func TestFingerprintApproverTypedYesThenFinger(t *testing.T) {
	io := &fakeIO{answers: []string{"y"}}
	v := &fingerprint.Fake{}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	r := a.Approve(context.Background(), Decision{Prompt: "Approve? ", Expected: "y"})
	if r.Outcome != Approved || v.Calls != 1 {
		t.Fatalf("got %+v, calls %d", r, v.Calls)
	}
	if a.Mode() != "desktop+fingerprint" {
		t.Fatalf("mode = %q", a.Mode())
	}
	if !containsLine(io, "Place your left index finger on the reader") {
		t.Fatalf("no finger prompt in %q", io.out)
	}
}

func TestFingerprintApproverNoPromptOnBusyReader(t *testing.T) {
	io := &fakeIO{answers: []string{"y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrBusy}, NeverReady: true}
	r := newFingerprintApprover(io, v, "left-index-finger", time.Second).Approve(context.Background(), Decision{Prompt: "p", Expected: "y"})
	if r.Outcome != NoFinger || !errors.Is(r.Err, fingerprint.ErrBusy) {
		t.Fatalf("got %+v", r)
	}
	if containsLine(io, "Place your") {
		t.Fatalf("prompted while the reader was busy: %q", io.out)
	}
}

func TestFingerprintApproverTypedNoNeverReachesReader(t *testing.T) {
	io := &fakeIO{answers: []string{"n"}}
	v := &fingerprint.Fake{}
	r := newFingerprintApprover(io, v, "left-index-finger", time.Second).Approve(context.Background(), Decision{Prompt: "p", Expected: "y"})
	if r.Outcome != Denied || v.Calls != 0 {
		t.Fatalf("got %+v, calls %d", r, v.Calls)
	}
}

func TestFingerprintApproverProductionTypedNameFirst(t *testing.T) {
	io := &fakeIO{answers: []string{"wrong", "uat"}}
	v := &fingerprint.Fake{}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	d := Decision{Prompt: "p", Expected: "uat", Production: true}
	if r := a.Approve(context.Background(), d); r.Outcome != Denied || v.Calls != 0 {
		t.Fatalf("wrong name: %+v, calls %d", r, v.Calls)
	}
	if r := a.Approve(context.Background(), d); r.Outcome != Approved || v.Calls != 1 {
		t.Fatalf("right name: %+v, calls %d", r, v.Calls)
	}
}

func TestFingerprintApproverMatchCoversOneDecision(t *testing.T) {
	// A no-match on the first decision, then a match: the first is
	// NoFinger, the second Approved, and each decision made its own call.
	io := &fakeIO{answers: []string{"y", "y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, nil}}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	d := Decision{Prompt: "p", Expected: "y"}
	if r := a.Approve(context.Background(), d); r.Outcome != NoFinger || !errors.Is(r.Err, fingerprint.ErrNoMatch) {
		t.Fatalf("first: %+v", r)
	}
	if r := a.Approve(context.Background(), d); r.Outcome != Approved {
		t.Fatalf("second: %+v", r)
	}
	if v.Calls != 2 {
		t.Fatalf("calls = %d", v.Calls)
	}
}

func TestFingerprintApproverTimeoutIsNoFinger(t *testing.T) {
	io := &fakeIO{answers: []string{"y"}}
	v := &fingerprint.Fake{Block: true}
	r := newFingerprintApprover(io, v, "left-index-finger", 20*time.Millisecond).Approve(context.Background(), Decision{Prompt: "p", Expected: "y"})
	if r.Outcome != NoFinger || !errors.Is(r.Err, fingerprint.ErrTimeout) {
		t.Fatalf("got %+v", r)
	}
}

func TestFingerprintApproverThreeNoMatchesEnd(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, fingerprint.ErrNoMatch}}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	d := Decision{Prompt: "p", Expected: "y"}
	for i := 0; i < 2; i++ {
		if r := a.Approve(context.Background(), d); r.Outcome != NoFinger || errors.Is(r.Err, ErrTooManyNoMatch) {
			t.Fatalf("attempt %d: %+v", i+1, r)
		}
	}
	r := a.Approve(context.Background(), d)
	if r.Outcome != NoFinger || !errors.Is(r.Err, ErrTooManyNoMatch) {
		t.Fatalf("third: %+v", r)
	}
}

func TestFingerprintApproverMatchResetsNoMatchCount(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y", "y", "y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, nil, fingerprint.ErrNoMatch}}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	d := Decision{Prompt: "p", Expected: "y"}
	for i := 0; i < 3; i++ {
		a.Approve(context.Background(), d)
	}
	if r := a.Approve(context.Background(), d); errors.Is(r.Err, ErrTooManyNoMatch) {
		t.Fatalf("count not reset by the match: %+v", r)
	}
}

func TestTypedApproverEmptyExpectedNeverApproves(t *testing.T) {
	for _, ans := range []string{"", "y"} {
		io := &fakeIO{answers: []string{ans}}
		if r := newTypedApprover(io).Approve(context.Background(), Decision{Prompt: "p"}); r.Outcome != Denied {
			t.Fatalf("answer %q: %+v", ans, r)
		}
	}
}

func TestTypedApproverRetypeEqualToExpectedApproves(t *testing.T) {
	io := &fakeIO{answers: []string{"r"}}
	d := Decision{Prompt: "p", Expected: "r", Production: true, Retype: "r"}
	if r := newTypedApprover(io).Approve(context.Background(), d); r.Outcome != Approved {
		t.Fatalf("got %+v", r)
	}
}

func TestFingerprintApproverUnansweredAndRetypeSkipReader(t *testing.T) {
	v := &fingerprint.Fake{}
	a := newFingerprintApprover(&fakeIO{timeout: true}, v, "left-index-finger", time.Second)
	if r := a.Approve(context.Background(), Decision{Prompt: "p", Expected: "y"}); r.Outcome != Unanswered {
		t.Fatalf("got %+v", r)
	}
	a = newFingerprintApprover(&fakeIO{answers: []string{"r"}}, v, "left-index-finger", time.Second)
	if r := a.Approve(context.Background(), Decision{Prompt: "p", Expected: "y", Retype: "r"}); r.Outcome != RetypeRequested {
		t.Fatalf("got %+v", r)
	}
	if v.Calls != 0 {
		t.Fatalf("reader reached: calls = %d", v.Calls)
	}
}

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

// Once tripped, the lockout holds for every later decision: no typed
// prompt, no finger, whatever the caller does with the result.
func TestFingerprintApproverLockoutIsSticky(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y", "y", "y", "y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, nil}}
	a := newFingerprintApprover(io, v, "left-index-finger", time.Second)
	d := Decision{Prompt: "p", Expected: "y"}
	for i := 0; i < 3; i++ {
		a.Approve(context.Background(), d)
	}
	prompts, calls := len(io.prompts), v.Calls
	for i := 0; i < 2; i++ {
		r := a.Approve(context.Background(), d)
		if r.Outcome != NoFinger || !errors.Is(r.Err, ErrTooManyNoMatch) {
			t.Fatalf("after the lockout: %+v", r)
		}
	}
	if len(io.prompts) != prompts || v.Calls != calls {
		t.Fatalf("asked again: prompts %d -> %d, finger calls %d -> %d", prompts, len(io.prompts), calls, v.Calls)
	}
}

// The lockout error is one line.
func TestFingerprintLockoutErrorSingleLine(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y", "y"}}
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch, fingerprint.ErrNoMatch, fingerprint.ErrNoMatch}}
	a := newFingerprintApprover(io, v, "f", time.Second)
	var r Result
	for i := 0; i < 3; i++ {
		r = a.Approve(context.Background(), Decision{Prompt: "p", Expected: "y"})
	}
	if msg := r.Err.Error(); strings.Contains(msg, "\n") || !errors.Is(r.Err, fingerprint.ErrNoMatch) {
		t.Fatalf("error %q", msg)
	}
	busy := fmt.Errorf("%w: x", fingerprint.ErrBusy)
	if strings.Contains(busy.Error(), "\n") {
		t.Fatal("busy error spans lines")
	}
}

func TestApproverModes(t *testing.T) {
	io := &fakeIO{}
	for want, a := range map[string]Approver{
		"session":             newTypedApprover(io),
		"desktop+typed":       newDesktopTypedApprover(io),
		"desktop+fingerprint": newFingerprintApprover(io, &fingerprint.Fake{}, "", time.Second),
	} {
		if got := a.Mode(); got != want {
			t.Errorf("Mode() = %q, want %q", got, want)
		}
	}
}
