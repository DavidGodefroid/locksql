package console

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// shadowSession is a session whose server resolves function names through
// a search path (engine.FunctionShadows): shadowed holds the allowlisted
// names a user-defined function also bears.
type shadowSession struct {
	*fakeSession
	shadowed []string
	err      error
	asked    [][]string
}

func (s *shadowSession) ShadowedFunctions(_ context.Context, _ string, names []string) ([]string, error) {
	s.asked = append(s.asked, slices.Clone(names))
	if s.err != nil {
		return nil, s.err
	}
	var out []string
	for _, n := range names {
		if slices.Contains(s.shadowed, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func withShadows(ss *shadowSession) hopt {
	return func(c *ServerConfig) {
		ss.fakeSession = c.Session.(*fakeSession)
		c.Session = ss
	}
}

// An allowlisted function that a user-defined function of the same name
// could overload (PostgreSQL resolves the best match over the whole search
// path) is refused before anything runs, in reads, in their k-anonymity
// counts and in writes under write_functions = "allowlist".
func TestShadowedFunctionsRefused(t *testing.T) {
	ss := &shadowSession{shadowed: []string{"lower", "count"}}
	p := uatProfile()
	p.Tier = config.TierWrite
	p.WriteFunctions = config.WriteFunctionsAllowlist
	h := newHarness(t, p, withShadows(ss))
	for _, q := range []string{
		"SELECT lower(note) AS n FROM users LIMIT 1",
		"SELECT id FROM users WHERE upper(note) = 'A' AND lower(status) = 'b' LIMIT 1",
		"SELECT count(*) AS n FROM users LIMIT 1",
		"SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", // its k-anonymity count calls COUNT
		"UPDATE users SET note = lower(note) WHERE id = 1",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error != nil && !strings.Contains(resp.Error.Message, "outside pg_catalog") {
			t.Errorf("%s: %s", q, resp.Error.Message)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a refused statement ran")
	}
	h.plan(t, "SELECT upper(note) AS n FROM users LIMIT 1", false)
	if last := ss.asked[len(ss.asked)-1]; !slices.Contains(last, "upper") {
		t.Errorf("asked %v, want upper", last)
	}
	h.plan(t, "SELECT note FROM users LIMIT 1", false)
}

// The check fails closed: a catalog error refuses the plan.
func TestShadowedFunctionsError(t *testing.T) {
	ss := &shadowSession{err: errors.New("catalog unavailable")}
	h := newHarness(t, uatProfile(), withShadows(ss))
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT lower(note) AS n FROM users LIMIT 1"})
	if resp.Error == nil {
		t.Fatal("planned despite the catalog error")
	}
	if h.sess.runCount() != 0 {
		t.Fatal("ran")
	}
}

var _ engine.FunctionShadows = (*shadowSession)(nil)
