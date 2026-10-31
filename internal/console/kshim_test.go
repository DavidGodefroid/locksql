package console

import (
	"context"
	"errors"
	"strings"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// Test shims over lockkit's console, which holds the switches and the
// policy review.

func (s *Server) toggleResults()                   { s.k.Key(kconsole.KeyCtrlO) }
func (s *Server) toggleUnmask(ctx context.Context) { s.k.Command(ctx, ":unmask") }

// refreshStatus redraws the status row (lockkit redraws it after every
// request; a test that changes state behind its back asks for it).
func (s *Server) refreshStatus() { s.k.Loop().Refresh() }

// adopt has the console read p from the config files: a tightening is
// applied at once, a loosening is applied at :review with a typed "y" (the
// answer is put first). The error is the console's "not applied" line.
func (s *Server) adopt(p config.Policy, _ string) error {
	io := s.cfg.IO.(*fakeIO)
	io.mu.Lock()
	from := len(io.out)
	io.mu.Unlock()
	prev := s.cfg.LoadPolicy
	s.cfg.LoadPolicy = func() (config.Policy, error) { return p, nil }
	defer func() { s.cfg.LoadPolicy = prev }()
	s.k.CheckPolicy()
	if s.k.PolicyPending() {
		io.mu.Lock()
		io.answers = append([]string{"y"}, io.answers...)
		io.mu.Unlock()
		s.k.Command(context.Background(), ":review")
	}
	io.mu.Lock()
	defer io.mu.Unlock()
	for _, l := range io.out[from:] {
		if _, msg, ok := strings.Cut(l, "policy change not applied: "); ok {
			return errors.New(msg)
		}
	}
	return nil
}

// setPending has the console read the loosening p from the config files:
// it then awaits :review.
func (s *Server) setPending(p config.Policy) {
	prev := s.cfg.LoadPolicy
	s.cfg.LoadPolicy = func() (config.Policy, error) { return p, nil }
	defer func() { s.cfg.LoadPolicy = prev }()
	s.k.CheckPolicy()
	if !s.k.PolicyPending() {
		panic("setPending: not a loosening")
	}
}
