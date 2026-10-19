package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// Decision names what a human is approving.
type Decision struct {
	// Prompt is the typed prompt, already framed by the caller.
	Prompt string
	// Expected is the typed answer: "y" (any case) or the production
	// profile name (exact).
	Expected string
	// Production selects the exact match.
	Production bool
	// Retype is the typed answer that asks to retype placeholders ("" when
	// not offered).
	Retype string
}

// Outcome of an approval.
type Outcome int

const (
	Approved Outcome = iota
	// Denied is a typed answer that is not the expected one; Answer holds it.
	Denied
	// Unanswered: no answer within the timeout, or ctx ended.
	Unanswered
	RetypeRequested
	// NoFinger: desktop mode, typed yes, then no match, timeout or reader
	// error; Err holds it.
	NoFinger
)

// Result of an approval.
type Result struct {
	Outcome Outcome
	Answer  string
	Err     error
}

// Approver asks the human for one decision. Each call is one decision: a
// fingerprint match never carries over.
type Approver interface {
	Approve(ctx context.Context, d Decision) Result
	// Mode is the audit value: "session" or "desktop+fingerprint".
	Mode() string
}

// FingerDeadline bounds the wait for a finger after a typed yes.
const FingerDeadline = 30 * time.Second

// ErrTooManyNoMatch is set on the third consecutive no-match: the caller
// ends the console.
var ErrTooManyNoMatch = errors.New("fingerprint: three consecutive non-matching fingers")

const maxNoMatch = 3

type typedApprover struct {
	io IO
	// mode is the audit value: "session" in a login session of the console
	// account, "desktop+typed" in a desktop window without a reader (level 1).
	mode string
}

func newTypedApprover(io IO) Approver { return &typedApprover{io: io, mode: "session"} }

// newDesktopTypedApprover is the level-1 approver: typed answers in a window
// the agent can type into, audited apart from the session shape.
func newDesktopTypedApprover(io IO) Approver {
	return &typedApprover{io: io, mode: "desktop+typed"}
}

func (a *typedApprover) Mode() string { return a.mode }

func (a *typedApprover) Approve(ctx context.Context, d Decision) Result {
	ans, ok := a.io.Ask(ctx, d.Prompt, ApprovalTimeout)
	if !ok {
		return Result{Outcome: Unanswered}
	}
	ans = strings.TrimSpace(ans)
	if d.Retype != "" && d.Retype != d.Expected && ans == d.Retype {
		return Result{Outcome: RetypeRequested, Answer: ans}
	}
	if d.Expected != "" && (ans == d.Expected || (!d.Production && strings.EqualFold(ans, d.Expected))) {
		return Result{Outcome: Approved, Answer: ans}
	}
	return Result{Outcome: Denied, Answer: ans}
}

// fingerprintApprover is not safe for concurrent use (the console calls it
// serially).
type fingerprintApprover struct {
	typed    *typedApprover
	io       IO
	v        fingerprint.Verifier
	finger   string // fprintd name, e.g. "left-index-finger"
	deadline time.Duration
	noMatch  int
}

// newFingerprintApprover wraps the typed approval with a fingerprint of
// the dedicated finger (system.toml `finger`), named in the prompt.
func newFingerprintApprover(io IO, v fingerprint.Verifier, finger string, deadline time.Duration) Approver {
	return &fingerprintApprover{typed: &typedApprover{io: io, mode: "desktop+fingerprint"}, io: io, v: v, finger: finger, deadline: deadline}
}

func (a *fingerprintApprover) Mode() string { return "desktop+fingerprint" }

// fingerLabel turns "left-index-finger" into "left index finger".
func fingerLabel(name string) string {
	if name == "" {
		return "finger"
	}
	return strings.ReplaceAll(name, "-", " ")
}

func (a *fingerprintApprover) Approve(ctx context.Context, d Decision) Result {
	// Once tripped the lockout holds for good: whatever the caller does
	// with the earlier refusal, no later decision is asked or verified.
	if a.noMatch >= maxNoMatch {
		return Result{Outcome: NoFinger, Err: ErrTooManyNoMatch}
	}
	r := a.typed.Approve(ctx, d)
	if r.Outcome != Approved {
		return r
	}
	fctx, cancel := context.WithTimeout(ctx, a.deadline)
	defer cancel()
	// The prompt appears only once the reader is claimed and listening:
	// the human never offers the finger to a reader another process holds.
	err := a.v.Verify(fctx, func() {
		a.io.Println(bold + "Place your " + fingerLabel(a.finger) + " on the reader…" + reset)
	})
	switch {
	case err == nil:
		a.noMatch = 0
		a.io.Println("fingerprint: ok")
		return Result{Outcome: Approved, Answer: r.Answer}
	case errors.Is(err, fingerprint.ErrNoMatch):
		a.noMatch++
		if a.noMatch >= maxNoMatch {
			return Result{Outcome: NoFinger, Answer: r.Answer, Err: fmt.Errorf("%w (%w)", ErrTooManyNoMatch, err)}
		}
	}
	return Result{Outcome: NoFinger, Answer: r.Answer, Err: err}
}
