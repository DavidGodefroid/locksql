package console

import (
	"regexp"
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

var hashForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// guarded makes the harness session an engine.ObjectGuard (PostgreSQL).
func guarded(h *harness) *engine.ObjectState {
	st := &engine.ObjectState{SearchPath: `"$user", public`, Objects: []engine.ObjectDef{
		{Kind: "relation", Name: "app.users", Def: "r"},
		{Kind: "function", Name: "app.f(integer)", Def: "SELECT 1"},
	}}
	h.sess.objects = st
	return st
}

// The plan hash covers the statement as its tokens: spacing and comments
// aside, the same statement has the same hash, another one another hash.
func TestPlanHashOfTheStatement(t *testing.T) {
	h := newHarness(t, uatProfile())
	a := h.plan(t, selectUsers, false)
	b := h.plan(t, "select  id, email, note\nfrom users where id = 1 limit 10", false)
	c := h.plan(t, "SELECT id, email, note FROM users WHERE id = 2 LIMIT 10", false)
	if !hashForm.MatchString(a.PlanHash) {
		t.Fatalf("plan hash %q", a.PlanHash)
	}
	if a.PlanHash != b.PlanHash || a.PlanHash == c.PlanHash {
		t.Errorf("hashes %s %s %s", a.PlanHash, b.PlanHash, c.PlanHash)
	}
	// An engine that cannot read definitions runs the statement as before.
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: a.PlanID}, nil)
	if h.sess.guardedRuns != 0 || h.sess.runCount() != 1 {
		t.Errorf("guarded runs %d, runs %d", h.sess.guardedRuns, h.sess.runCount())
	}
}

// On PostgreSQL the hash covers the definitions too, the run checks them
// in its own transaction, and a plan whose objects changed is refused with
// E_STALE: before the human is asked when the change came before the run,
// with the statement rolled back when it came during it.
func TestPlanHashStale(t *testing.T) {
	const q = selectUsers
	h := newHarness(t, uatProfile())
	st := guarded(h)
	pr := h.plan(t, q, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.sess.guardedRuns != 1 {
		t.Fatalf("guarded runs %d", h.sess.guardedRuns)
	}
	if refs := h.sess.objectRefs[0]; !slices.Contains(refs.Relations, "users") {
		t.Errorf("refs %+v", refs)
	}

	for _, change := range []func(){
		func() { st.Objects[1].Def = "SELECT 2" },                                     // CREATE OR REPLACE FUNCTION
		func() { st.SearchPath = "evil, public" },                                     // search_path
		func() { st.Objects = append(st.Objects, engine.ObjectDef{Kind: "trigger"}) }, // a new trigger
	} {
		before := *st
		before.Objects = slices.Clone(st.Objects)
		pr := h.plan(t, q, false)
		change()
		prompts, runs := h.io.promptCount(), h.sess.runCount()
		resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		wantStale(t, resp)
		if h.io.promptCount() != prompts || h.sess.runCount() != runs {
			t.Errorf("a stale plan was prompted (%d) or run (%d)", h.io.promptCount()-prompts, h.sess.runCount()-runs)
		}
		*st = before
	}

	// A change during the statement: it ran, its result is dropped.
	pr = h.plan(t, q, false)
	h.sess.duringRun = func() { st.Objects[0].Def = "r rls" }
	h.io.answers = []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantStale(t, resp)
}

func wantStale(t *testing.T, resp ipc.Response) {
	t.Helper()
	wantCode(t, resp, ipc.CodeRefused)
	if d := resp.Error.Data; d == nil || d.Code != refusal.Stale {
		t.Fatalf("refusal %q: %+v", resp.Error.Message, d)
	}
}

// A PostgreSQL session that cannot read definitions fails the plan.
func TestPlanHashPostgresNeedsGuard(t *testing.T) {
	h := newHarness(t, uatProfile(), withShadows(&shadowSession{}))
	h.s.sess.(*shadowSession).objects = nil
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM users WHERE id = 1 LIMIT 10"})
	if resp.Error == nil {
		t.Fatal("a PostgreSQL plan without its definitions was accepted")
	}
}

func TestObjectRefs(t *testing.T) {
	pl := &plan{st: sqlclass.Statement{SQL: `UPDATE app.users SET note = lower(note) WHERE "Id" = 1 AND x.y.z = 2`}}
	refs := objectRefs(sqlclass.Postgres, pl)
	for _, want := range []string{"app.users", `"Id"`, "note", "lower"} {
		if !slices.Contains(refs.Relations, want) {
			t.Errorf("relations %v lack %q", refs.Relations, want)
		}
	}
	if slices.Contains(refs.Relations, "x.y") || slices.Contains(refs.Relations, "y.z") {
		t.Errorf("a three-part name was taken: %v", refs.Relations)
	}
	if !slices.Equal(refs.Functions, []string{"lower"}) {
		t.Errorf("functions %v", refs.Functions)
	}
}
