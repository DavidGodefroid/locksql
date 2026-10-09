package console

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// fakeEngineName is a test-only engine handing out the session in fakeNext.
const fakeEngineName = "fake-reconnect"

var fakeNext *fakeSession

type fakeEngine struct{}

func (fakeEngine) Connect(context.Context, config.Profile, []byte, engine.DialFunc) (engine.Session, error) {
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
		c.Reconnect = func(ctx context.Context, cur config.Profile) (engine.Session, error) {
			cur.Engine = fakeEngineName
			return st.reconnect(ctx, cur)
		}
	})
	h.io.secrets = []string{"not-used", "not-used", "not-used"} // the password asked again on reconnect
	return h, next
}

// asks counts the prompts other than the password asked on reconnect.
func asks(prompts []string) int {
	n := 0
	for _, p := range prompts {
		if !strings.HasPrefix(p, "Password for ") {
			n++
		}
	}
	return n
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
	if asks(h.io.prompts[n:]) != 0 || next.catalog != 1 {
		t.Fatalf("prompts %q, catalog %d", h.io.prompts[n:], next.catalog)
	}
}

// A tightening applied after start-up (production turned on) must govern
// the reconnect: extra privileges are then refused, not offered "continue".
func TestReconnectUsesCurrentPolicy(t *testing.T) {
	h, next := reconnectHarness(t, uatProfile(), []string{"INSERT on app.users"})
	prod := uatProfile()
	prod.Production = true
	if err := h.s.adopt(config.NewPolicy(prod, []string{"app.users.email"}, nil), "tightened"); err != nil {
		t.Fatal(err)
	}
	h.sess.runErr = engine.ErrConnLost
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"uat"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeConnLost)

	n := h.io.promptCount()
	wantCode(t, h.call(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}), ipc.CodeConnLost)
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "privilege audit") {
		t.Fatalf("session not ended by the privilege audit: %q %v", reason, ended)
	}
	if asks(h.io.prompts[n:]) != 0 {
		t.Errorf("production reconnect prompted: %q", h.io.prompts[n:])
	}
	if next.catalog != 0 {
		t.Fatal("request served on a refused session")
	}
}

func TestProductionTighteningReauditsLiveSession(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.extra = []string{"INSERT on app.users"}
	prod := uatProfile()
	prod.Production = true
	if err := h.s.adopt(config.NewPolicy(prod, []string{"app.users.email"}, nil), "tightened"); err != nil {
		t.Fatal(err)
	}
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "privilege audit") {
		t.Fatalf("over-privileged live session kept on production: %q %v", reason, ended)
	}
}

func TestReviewWarnsAboutSkipPermissions(t *testing.T) {
	p := prodProfile()
	h := newHarness(t, p, func(c *ServerConfig) { c.SkipPermissions = true })
	next := p
	next.Production = false
	h.s.pending = new(config.Policy)
	*h.s.pending = config.NewPolicy(next, []string{"app.users.email"}, nil)
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.output(), "without a prompt") {
		t.Errorf("no warning:\n%s", h.io.output())
	}
}

// A project profile shadowing an approved user-config profile of the same
// name is shown as a diff against that approval, not only as a first start.
func TestFirstStartShowsDiffAgainstUserApproval(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{answers: []string{"n"}}
	user := uatProfile()
	if err := config.SaveApproved(state, config.ApprovedKey("", "uat"), config.NewPolicy(user, nil, nil)); err != nil {
		t.Fatal(err)
	}
	shadow := user
	shadow.Tier = config.TierAdmin
	st := &starter{io: io, log: log, profile: shadow}
	_, _, err = st.startPolicy(context.Background(), state, config.ApprovedKey(t.TempDir(), "uat"), config.NewPolicy(shadow, nil, nil))
	if err == nil {
		t.Fatal("refused first start accepted")
	}
	if out := io.output(); !strings.Contains(out, "differs from the user-config profile") || !strings.Contains(out, "(loosens)") {
		t.Errorf("no diff shown:\n%s", out)
	}
}

// A client that leaves while its request waits for the console (busy with
// another client's approval) must not have that request served.
func TestServeConnDropsRequestOfClientGoneBeforeHandoff(t *testing.T) {
	srv, cli := net.Pipe()
	jobs := make(chan job)
	var inflight sync.WaitGroup
	done := make(chan struct{})
	go func() {
		serveConn(context.Background(), srv, jobs, &inflight)
		close(done)
	}()
	if err := ipc.WriteMsg(cli, ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodStatus}); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	// Nobody serves jobs (the console is busy): serveConn must notice the
	// client left and return without handing the request over.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveConn still waits to hand over the request of a gone client")
	}
}
