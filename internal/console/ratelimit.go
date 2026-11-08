package console

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// rateApprover is the hub approver with the last ticket the hub client
// refused over its limits (hubclient.RateLimitError) kept: lockkit's Asker
// answers such a refusal in general words, and the agent must read which
// limit it reached and when to retry (lockkit#150).
type rateApprover struct {
	kconsole.AsyncApprover
	last atomic.Pointer[hubclient.RateLimitError]
}

// Submit implements kconsole.AsyncApprover.
func (a *rateApprover) Submit(ctx context.Context, d kconsole.Decision) (kconsole.Pending, error) {
	p, err := a.AsyncApprover.Submit(ctx, d)
	var rl *hubclient.RateLimitError
	if p.Ticket == "" && errors.As(err, &rl) {
		a.last.Store(rl)
	}
	return p, err
}

// Withdraw implements kconsole.Withdrawer when the wrapped approver does.
func (a *rateApprover) Withdraw(ctx context.Context, d kconsole.Decision, ticket, reason string) error {
	if w, ok := a.AsyncApprover.(kconsole.Withdrawer); ok {
		return w.Withdraw(ctx, d, ticket, reason)
	}
	return nil
}

// ask is s.asker().Ask, with a ticket refused over the hub client's limits
// answered with the limit, the count and when to retry, then what the
// agent does next (again).
func (s *Server) ask(ctx context.Context, id int64, q kconsole.Ask, record func(kaudit.Base), again string) kconsole.Approval {
	ra, _ := s.cfg.Approver.(*rateApprover)
	if ra != nil {
		ra.last.Store(nil)
	}
	a := s.asker().Ask(ctx, id, q, record)
	if ra == nil || a.Pending != nil {
		return a
	}
	if rl := ra.last.Swap(nil); rl != nil {
		msg := "not submitted: " + strings.TrimPrefix(rl.Error(), "hubclient: ") + "; " + again
		a.Refusal = errResp(id, ipc.CodeInternal, msg)
	}
	return a
}
