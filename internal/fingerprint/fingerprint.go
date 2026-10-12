// Package fingerprint verifies the human's finger on the machine's reader
// through fprintd, for the console's approvals in desktop mode.
package fingerprint

import (
	"context"
	"errors"
)

var (
	ErrNoMatch     = errors.New("fingerprint: no match")
	ErrTimeout     = errors.New("fingerprint: no finger within the deadline")
	ErrUnavailable = errors.New("fingerprint: reader or fprintd unavailable")
	ErrBusy        = errors.New("fingerprint: reader in use")
	// ErrWrongOwner: the fprintd name is held by a process of another uid
	// than expected. NewFprintd wraps it together with ErrUnavailable;
	// callers that treat "unavailable" as "no reader" must refuse on this
	// one first: a rogue service is not an absent reader.
	ErrWrongOwner  = errors.New("fingerprint: fprintd runs as an unexpected account")
	ErrNotEnrolled = errors.New("fingerprint: no finger enrolled for the console account")
)

// Verifier is what the console asks for a fingerprint.
type Verifier interface {
	// Verify blocks until a print enrolled for the console account matches,
	// ctx ends (ErrTimeout when its deadline passed, ctx.Err() otherwise),
	// or the reader fails (ErrNoMatch, ErrUnavailable, ErrBusy). onReady,
	// when not nil, runs once the reader is claimed: the caller prompts the
	// human then, never before, so that a finger is never offered to a
	// reader another process holds.
	Verify(ctx context.Context, onReady func()) error
	// Enrolled is the number of prints enrolled for the console account.
	Enrolled(ctx context.Context) (int, error)
}

// Fake is a scripted Verifier for tests.
type Fake struct {
	// Results are returned by successive Verify calls; nil past the end.
	Results []error
	// EnrolledN and EnrolledErr answer Enrolled.
	EnrolledN   int
	EnrolledErr error
	// Calls counts Verify calls; Ready counts onReady calls.
	Calls, Ready int
	// Block makes Verify wait for ctx; the result is then ErrTimeout when
	// the deadline passed, ctx.Err() otherwise.
	Block bool
	// NeverReady returns the result without calling onReady (a reader that
	// was never claimed: busy, unavailable).
	NeverReady bool
}

func (f *Fake) Verify(ctx context.Context, onReady func()) error {
	f.Calls++
	if !f.NeverReady && onReady != nil {
		f.Ready++
		onReady()
	}
	if f.Block {
		<-ctx.Done()
		return deadlineErr(ctx)
	}
	if f.Calls <= len(f.Results) {
		return f.Results[f.Calls-1]
	}
	return nil
}

func (f *Fake) Enrolled(context.Context) (int, error) { return f.EnrolledN, f.EnrolledErr }

// deadlineErr maps a finished context to the package's errors.
func deadlineErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ctx.Err()
}
