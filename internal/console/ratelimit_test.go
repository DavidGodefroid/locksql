package console

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// limitApprover is the hub approver with every ticket refused over the
// hub client's limits: refuse picks the error from the decision.
type limitApprover struct {
	kconsole.AsyncApprover
	refuse func(kconsole.Decision) *hubclient.RateLimitError
}

func (a *limitApprover) Submit(ctx context.Context, d kconsole.Decision) (kconsole.Pending, error) {
	return kconsole.Pending{}, a.refuse(d)
}

// withLimits puts the harness console on a fake lockhub whose approver
// refuses every ticket with refuse's error.
func withLimits(t *testing.T, refuse func(kconsole.Decision) *hubclient.RateLimitError) hopt {
	return func(c *ServerConfig) {
		var hub *hubtest.Hub
		withHub(t, &hub)(c)
		c.Approver = &limitApprover{AsyncApprover: c.Approver.(kconsole.AsyncApprover), refuse: refuse}
	}
}

// wantLimit checks a refusal names rl's own limit, count and retry-after,
// then what the agent does next.
func wantLimit(t *testing.T, r ipc.Response, rl *hubclient.RateLimitError, again string) {
	t.Helper()
	wantCode(t, r, ipc.CodeInternal)
	want := "not submitted: " + strings.TrimPrefix(rl.Error(), "hubclient: ") + "; " + again
	if r.Error.Message != want {
		t.Errorf("refusal %q, want %q", r.Error.Message, want)
	}
}

// A ticket the hub client refuses over its limits answers the agent with
// that limit, its count and when to retry, then what to do next: for a
// plan's run and for a grant (#204).
func TestRateLimitRefusalNamesLimit(t *testing.T) {
	rl := &hubclient.RateLimitError{Limit: hubclient.LimitRate, Count: 3, Max: 3, Window: 10 * time.Minute, RetryAfter: 2 * time.Minute}
	h := newHarness(t, uatProfile(), withLimits(t, func(kconsole.Decision) *hubclient.RateLimitError { return rl }))
	pr := h.plan(t, "SELECT id FROM users WHERE id = 1 LIMIT 10", false)
	r := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantLimit(t, r, rl, "plan the query again after that (the plan is used)")
	for _, s := range []string{"limit 3", "retry after 2m0s"} {
		if !strings.Contains(r.Error.Message, s) {
			t.Errorf("refusal %q does not say %q", r.Error.Message, s)
		}
	}
	g := h.call(t, ipc.MethodGrant, ipc.GrantParams{Requester: agentA, DB: "app", Tables: []string{"users"}})
	wantLimit(t, g, rl, "ask for the grant again after that")
}

// Two asks refused at the same time with different limits each get their
// own: no ask reads another's limit or retry-after (#204).
func TestRateLimitRefusalPerAsk(t *testing.T) {
	one := &hubclient.RateLimitError{Limit: hubclient.LimitRate, Count: 3, Max: 3, Window: 10 * time.Minute, RetryAfter: 2 * time.Minute}
	two := &hubclient.RateLimitError{Limit: hubclient.LimitPending, Count: 5, Max: 5}
	// Both asks reach Submit before either returns, when the console lets
	// them run together.
	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	h := newHarness(t, uatProfile(), withLimits(t, func(d kconsole.Decision) *hubclient.RateLimitError {
		arrived.Done()
		select {
		case <-both:
		case <-time.After(time.Second):
		}
		if strings.Contains(strings.Join(d.Screen.Body, "\n"), "111") {
			return one
		}
		return two
	}))
	sqls := []string{"SELECT id FROM users WHERE id = 111 LIMIT 10", "SELECT id FROM users WHERE id = 222 LIMIT 10"}
	ids := make([]string, len(sqls))
	for i, q := range sqls {
		ids[i] = h.plan(t, q, false).PlanID
	}
	resps := make([]ipc.Response, len(sqls))
	var wg sync.WaitGroup
	for i := range sqls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resps[i] = h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: ids[i]})
		}()
	}
	wg.Wait()
	const again = "plan the query again after that (the plan is used)"
	wantLimit(t, resps[0], one, again)
	wantLimit(t, resps[1], two, again)
}
