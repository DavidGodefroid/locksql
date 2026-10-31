package console

import (
	"io"
	"os"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// The terminal, the approvers and the process hardening are lockkit's
// console pieces, under their locksql names.

// Key is a control key the human pressed, outside a line.
type Key = kconsole.Key

// The control keys.
const (
	KeyShiftTab = kconsole.KeyShiftTab
	KeyCtrlO    = kconsole.KeyCtrlO
)

// Terminal is the IO of a real console.
type Terminal = kconsole.Terminal

// NewTerminal returns the IO over in and out (normally os.Stdin and
// os.Stdout).
func NewTerminal(in *os.File, out io.Writer) *Terminal { return kconsole.NewTerminal(in, out) }

// The approvers.
type (
	Decision = kconsole.Decision
	Outcome  = kconsole.Outcome
	Result   = kconsole.Result
	Approver = kconsole.Approver
)

// Outcomes of an approval.
const (
	Approved        = kconsole.Approved
	Denied          = kconsole.Denied
	Unanswered      = kconsole.Unanswered
	RetypeRequested = kconsole.RetypeRequested
	NoFinger        = kconsole.NoFinger
)

// FingerDeadline bounds the wait for a finger after a typed yes.
const FingerDeadline = kconsole.FingerDeadline

// ErrTooManyNoMatch is set on the third consecutive no-match: the caller
// ends the console.
var ErrTooManyNoMatch = kconsole.ErrTooManyNoMatch

func newTypedApprover(io IO) Approver { return kconsole.NewTypedApprover(io) }

func newDesktopTypedApprover(io IO) Approver { return kconsole.NewDesktopTypedApprover(io) }

func newFingerprintApprover(io IO, v fingerprint.Verifier, finger string, deadline time.Duration) Approver {
	return kconsole.NewFingerprintApprover(io, v, finger, deadline)
}

// hardenProcess is lockkit's process hardening; tests replace it.
var hardenProcess = kconsole.Harden
