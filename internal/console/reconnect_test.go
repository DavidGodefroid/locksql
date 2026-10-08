package console

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// fakeEngineName is a test-only engine handing out the session in fakeNext.
const fakeEngineName = "fake-reconnect"

var fakeNext *fakeSession

type fakeEngine struct{}

func (fakeEngine) Connect(context.Context, config.Profile, []byte) (engine.Session, error) {
	return fakeNext, nil
}

func init() { engine.Register(fakeEngineName, fakeEngine{}) }

// reconnectHarness wires the server's Reconnect to the start-up reconnect
// path, with a fake engine whose next session reports extra privileges.
func reconnectHarness(t *testing.T, p config.Profile, extra []string) (*harness, *fakeSession) {
	t.Helper()
	next := &fakeSession{origin: true, dbs: []string{"app", "other"}, plan: okPlan(), result: userResult(), extra: extra}
	fakeNext = next
	h := newHarness(t, p, func(c *ServerConfig) {
		sp := p // the server keeps the real engine (dialect); the starter connects through the fake
		sp.Engine = fakeEngineName
		st := &starter{io: c.IO, log: c.Audit, profile: sp, user: p.User}
		c.Reconnect = st.reconnect
	})
	return h, next
}

func loseConnection(t *testing.T, h *harness) {
	t.Helper()
	h.sess.runErr = engine.ErrConnLost
	pr := h.plan(t, selectUsers, false)
	h.io.answers = append(h.io.answers, "y")
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeConnLost)
}

func TestReconnectRerunsPrivilegeAuditOnProduction(t *testing.T) {
	h, next := reconnectHarness(t, prodProfile(), []string{"INSERT on app.users"})
	h.io.answers = []string{"prod"} // approval of the statement that loses the connection
	loseConnection(t, h)

	wantCode(t, h.call(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}), ipc.CodeConnLost)
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "privilege audit") {
		t.Fatalf("session not ended by the privilege audit: %q %v", reason, ended)
	}
	if next.catalog != 0 {
		t.Fatal("request served on a session that failed the privilege audit")
	}
	if !next.closed {
		t.Error("refused session left open")
	}
	if !strings.Contains(h.auditLog(t), `"decision":"refused"`) {
		t.Errorf("refusal not audited:\n%s", h.auditLog(t))
	}
}

func TestReconnectPrivilegeAuditNeedsContinue(t *testing.T) {
	h, next := reconnectHarness(t, uatProfile(), []string{"INSERT on app.users"})
	loseConnection(t, h)

	h.io.answers = []string{"no"}
	wantCode(t, h.call(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}), ipc.CodeConnLost)
	if _, ended := h.s.Ended(); !ended {
		t.Fatal("session not ended after the privilege audit was declined")
	}
	if next.catalog != 0 || !next.closed {
		t.Fatalf("declined session: catalog=%d closed=%v", next.catalog, next.closed)
	}
	if !strings.Contains(strings.Join(h.io.prompts, "\n"), `Type "continue"`) {
		t.Errorf("prompts: %q", h.io.prompts)
	}
}

func TestReconnectPrivilegeAuditContinued(t *testing.T) {
	h, next := reconnectHarness(t, uatProfile(), []string{"INSERT on app.users"})
	loseConnection(t, h)

	h.io.answers = []string{"continue"}
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	if next.catalog != 1 {
		t.Fatalf("catalog calls on the new session = %d", next.catalog)
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("session ended")
	}
}

func TestReconnectCleanAccountNeedsNoPrompt(t *testing.T) {
	h, next := reconnectHarness(t, uatProfile(), nil)
	loseConnection(t, h)
	n := h.io.promptCount()
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	if h.io.promptCount() != n || next.catalog != 1 {
		t.Fatalf("prompts %d -> %d, catalog %d", n, h.io.promptCount(), next.catalog)
	}
}
