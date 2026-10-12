//go:build !linux

package fingerprint

import "context"

// Options is accepted on every platform; fprintd exists on Linux only.
type Options struct {
	Address  string
	User     string
	OwnerUID int
}

// Fprintd is unavailable off Linux.
type Fprintd struct{}

func NewFprintd(Options) (*Fprintd, error)             { return nil, ErrUnavailable }
func (*Fprintd) Verify(context.Context, func()) error  { return ErrUnavailable }
func (*Fprintd) Enrolled(context.Context) (int, error) { return 0, ErrUnavailable }
func (*Fprintd) Close() error                          { return nil }
