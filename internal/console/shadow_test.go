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
	ops      []string // operators also defined outside pg_catalog
	err      error
	asked    [][]string
	askedOps [][]string
}

func (s *shadowSession) ShadowedOperators(_ context.Context, _ string, names []string) ([]string, error) {
	s.askedOps = append(s.askedOps, slices.Clone(names))
	if s.err != nil {
		return nil, s.err
	}
	var out []string
	for _, n := range names {
		if slices.Contains(s.ops, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *shadowSession) Flavor() engine.Flavor { return engine.FlavorPostgres }

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
		ss.objects = &engine.ObjectState{SearchPath: "public", Objects: []engine.ObjectDef{}}
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

// pgSession is a PostgreSQL session that cannot look up function
// definitions: the check fails closed.
type pgSession struct{ *fakeSession }

func (pgSession) Flavor() engine.Flavor { return engine.FlavorPostgres }

func TestShadowedFunctionsFailClosed(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.Session = pgSession{c.Session.(*fakeSession)} })
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT lower(note) AS n FROM users LIMIT 1"})
	if resp.Error == nil {
		t.Fatal("a PostgreSQL session without the function lookup planned a call")
	}
	if h.sess.runCount() != 0 {
		t.Fatal("ran")
	}
}

// The session wrappers (SSH tunnel, proxy_command, Vault login) pass the
// lookup on.
func TestShadowedFunctionsThroughWrappers(t *testing.T) {
	inner := &shadowSession{fakeSession: &fakeSession{}, shadowed: []string{"lower"}}
	for name, s := range map[string]engine.Session{
		"tunnel":      &tunneledSession{Session: inner},
		"vault":       &vaultSession{Session: inner},
		"both":        &vaultSession{Session: &tunneledSession{Session: inner}},
		"proxy":       &proxiedSession{Session: inner},
		"vault+proxy": &vaultSession{Session: &proxiedSession{Session: inner}},
	} {
		fs, ok := s.(engine.FunctionShadows)
		if !ok {
			t.Errorf("%s: no engine.FunctionShadows", name)
			continue
		}
		if got, err := fs.ShadowedFunctions(context.Background(), "app", []string{"lower", "upper"}); err != nil || !slices.Equal(got, []string{"lower"}) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
		inner.ops = []string{"||"}
		if got, err := fs.ShadowedOperators(context.Background(), "app", []string{"||", "+"}); err != nil || !slices.Equal(got, []string{"||"}) {
			t.Errorf("%s operators: %v, %v", name, got, err)
		}
	}
	if _, err := (&tunneledSession{Session: &fakeSession{}}).ShadowedFunctions(context.Background(), "app", []string{"lower"}); err == nil {
		t.Error("a wrapper over a session without the lookup answered")
	}
	if _, err := (&proxiedSession{Session: &fakeSession{}}).ShadowedOperators(context.Background(), "app", []string{"+"}); err == nil {
		t.Error("a proxy wrapper over a session without the lookup answered")
	}
}

// Operators resolve like functions: public.||(varchar, varchar) beats
// pg_catalog.||(text, text). The operators a statement uses, and the
// comparisons every statement may use implicitly, are looked up too.
func TestShadowedOperatorsRefused(t *testing.T) {
	ss := &shadowSession{ops: []string{"+"}}
	h := newHarness(t, uatProfile(), withShadows(ss))
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT note FROM users WHERE id + 1 = 2 LIMIT 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if resp.Error != nil && !strings.Contains(resp.Error.Message, "operator +") {
		t.Errorf("refusal %q, want it to name operator +", resp.Error.Message)
	}
	h.plan(t, "SELECT note FROM users WHERE id = 1 LIMIT 1", false)
	last := ss.askedOps[len(ss.askedOps)-1]
	for _, op := range []string{"=", "<>", "<", ">", "<=", ">="} {
		if !slices.Contains(last, op) {
			t.Errorf("operators asked %v, want %s", last, op)
		}
	}
	ss.ops = []string{"="}
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT note FROM users LIMIT 1"}), ipc.CodeRefused)
	if h.sess.runCount() != 0 {
		t.Fatal("a refused statement ran")
	}
}

// A function or operator created between the plan and its run is caught:
// the lookup runs again just before the statement.
func TestShadowedCheckedAgainAtRun(t *testing.T) {
	ss := &shadowSession{}
	h := newHarness(t, uatProfile(), withShadows(ss), skip)
	pr := h.plan(t, "SELECT upper(note) AS n FROM users LIMIT 1", false)
	ss.shadowed = []string{"upper"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "outside pg_catalog") {
		t.Fatalf("run after CREATE FUNCTION: %+v", resp)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("the statement ran")
	}
}

// A function created between the plan and its run is caught before the
// k-anonymity counts run: they call COUNT and MIN. The answer is the
// E_FUNCTION refusal, and nothing runs.
func TestShadowedCheckedBeforeKCounts(t *testing.T) {
	ss := &shadowSession{}
	h := newHarness(t, uatProfile(), withShadows(ss), skip)
	pr := h.plan(t, "SELECT id FROM users WHERE email = 'a@example.com' LIMIT 1", false)
	ss.shadowed = []string{"count"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeRefused)
	if resp.Error != nil && (!strings.Contains(resp.Error.Message, "outside pg_catalog") || strings.Contains(resp.Error.Message, "k-anonymity check")) {
		t.Errorf("refusal %q", resp.Error.Message)
	}
	if n := h.sess.runCount(); n != 0 {
		t.Fatalf("%d statements ran (k-anonymity counts included)", n)
	}
}
