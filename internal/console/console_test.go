package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// fakeSession is a scripted engine.Session.
type fakeSession struct {
	mu     sync.Mutex
	origin bool
	dbs    []string
	plan   engine.Plan
	// kplan, when set, answers the EXPLAIN of the k-anonymity counts.
	kplan    *engine.Plan
	result   engine.Result
	runErr   error
	explains []string
	runs     []string
	catalog  int
	extra    []string // ExtraPrivileges warnings
	extraErr error    // ExtraPrivileges error
	closed   bool
	// count answers the k-anonymity row counts (nil: the default result).
	count   *engine.Result
	indexes []engine.IndexDesc
	cols    []engine.ColumnInfo // appended to the catalog Columns answers
	colsErr error               // answers the catalog Columns calls
	// explainErr answers the EXPLAIN calls.
	explainErr error
	// objects, when set, makes the session an engine.ObjectGuard reading
	// that state; duringRun runs between a guarded run's two checks.
	objects     *engine.ObjectState
	objectRefs  []engine.ObjectRefs
	duringRun   func()
	guardedRuns int
	countedRuns int
	rolledBack  []string
	// triggers answers engine.TriggerLister; triggerNames are the names
	// it was asked about.
	triggers     []string
	triggerNames [][]string
}

func (f *fakeSession) Triggers(_ context.Context, _ string, names []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.triggerNames = append(f.triggerNames, names)
	return slices.Clone(f.triggers), nil
}

func (f *fakeSession) ObjectState(_ context.Context, _ string, refs engine.ObjectRefs) (engine.ObjectState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects == nil {
		return engine.ObjectState{}, engine.ErrNoObjectGuard
	}
	f.objectRefs = append(f.objectRefs, refs)
	return cloneState(*f.objects), nil
}

func (f *fakeSession) RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs engine.ObjectRefs, check engine.GuardCheck) (engine.Result, error) {
	before, err := f.ObjectState(ctx, db, refs)
	if err != nil {
		return engine.Result{}, err
	}
	f.mu.Lock()
	f.guardedRuns++
	f.mu.Unlock()
	if err := check(before, engine.Step{}); err != nil {
		return engine.Result{}, err
	}
	res, err := f.Run(ctx, db, st, maxRows)
	if err != nil {
		return res, err
	}
	if f.duringRun != nil {
		f.duringRun()
	}
	after, _ := f.ObjectState(ctx, db, refs)
	if err := check(after, engine.Step{After: true, Affected: res.Affected}); err != nil {
		f.rollback(st)
		return engine.Result{}, err
	}
	return res, nil
}

// RunCounted implements engine.RowChecker: a failed check takes the
// statement out of runs again (rolled back).
func (f *fakeSession) RunCounted(ctx context.Context, db string, st sqlclass.Statement, maxRows int, check func(int64) error) (engine.Result, error) {
	res, err := f.Run(ctx, db, st, maxRows)
	if err != nil {
		return res, err
	}
	f.mu.Lock()
	f.countedRuns++
	f.mu.Unlock()
	if err := check(res.Affected); err != nil {
		f.rollback(st)
		return engine.Result{}, err
	}
	return res, nil
}

// rollback records that st was rolled back.
func (f *fakeSession) rollback(st sqlclass.Statement) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolledBack = append(f.rolledBack, st.SQL)
}

func cloneState(s engine.ObjectState) engine.ObjectState {
	s.Objects = slices.Clone(s.Objects)
	return s
}

func (f *fakeSession) ServerVersion() string { return "11.4.0-MariaDB" }
func (f *fakeSession) Flavor() engine.Flavor { return engine.FlavorMariaDB }
func (f *fakeSession) OriginColumns() bool   { return f.origin }
func (f *fakeSession) ExtraPrivileges(context.Context, config.Tier) ([]string, error) {
	return f.extra, f.extraErr
}
func (f *fakeSession) Databases(context.Context) ([]string, error) { return f.dbs, nil }
func (f *fakeSession) Tables(context.Context, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.catalog++
	return []string{"users"}, nil
}
func (f *fakeSession) Describe(_ context.Context, db, table string) (engine.TableInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.catalog++
	return engine.TableInfo{DB: db, Table: table, Columns: []engine.ColumnDesc{{Name: "id", Type: "int"}}, Indexes: f.indexes, EstRows: 3}, nil
}
func (f *fakeSession) Columns(_ context.Context, db string) ([]engine.ColumnInfo, error) {
	if f.colsErr != nil {
		return nil, f.colsErr
	}
	var out []engine.ColumnInfo
	for _, c := range []struct{ t, c string }{
		{"users", "id"}, {"users", "email"}, {"users", "note"}, {"users", "status"},
		{"orders", "id"}, {"orders", "user_id"}, {"orders", "total"},
	} {
		out = append(out, engine.ColumnInfo{DB: db, Table: c.t, Column: c.c, Type: "text"})
	}
	out = append(out, f.cols...)
	return out, nil
}
func (f *fakeSession) Explain(_ context.Context, _ string, sql string) (engine.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.explains = append(f.explains, sql)
	if f.explainErr != nil {
		return engine.Plan{}, f.explainErr
	}
	if f.kplan != nil && strings.Contains(sql, "COUNT(*)") {
		return *f.kplan, nil
	}
	return f.plan, nil
}
func (f *fakeSession) Run(_ context.Context, _ string, st sqlclass.Statement, _ int) (engine.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, st.SQL)
	if f.runErr != nil {
		return engine.Result{}, f.runErr
	}
	if f.count != nil && strings.Contains(st.SQL, "COUNT(*)") {
		return *f.count, nil
	}
	// Hand out a deep copy: masking works in place.
	res := f.result
	res.Rows = nil
	for _, r := range f.result.Rows {
		res.Rows = append(res.Rows, append([]any(nil), r...))
	}
	return res, nil
}
func (f *fakeSession) Ping(context.Context) error { return nil }
func (f *fakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeSession) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

// fakeIO answers prompts from a script.
type fakeIO struct {
	mu      sync.Mutex
	out     []string
	prompts []string
	answers []string
	timeout bool // answer every prompt with a timeout
	// block makes Ask wait for its context to end.
	block   bool
	blocked chan struct{}
	// onAsk, when set, runs before each scripted answer (e.g. to let time pass).
	onAsk func()
	// secrets answer AskSecret, in order; none left fails the prompt.
	secrets []string
	// bells counts the terminal bells, kept out of out.
	bells int
	// status is the last status line set (StatusLine).
	status string
	// transcript is everything the human sees, in order: lines, prompts
	// ("? " and "?secret "), bells ("<bell>"). The golden screens compare it.
	transcript []string
}

func (f *fakeIO) SetStatus(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = s
}

func (f *fakeIO) statusLine() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ansi.ReplaceAllString(f.status, "")
}

func (f *fakeIO) Bell() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bells++
	f.transcript = append(f.transcript, "<bell>")
}

func (f *fakeIO) Println(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, s)
	f.transcript = append(f.transcript, s)
}

func (f *fakeIO) Ask(ctx context.Context, prompt string, _ time.Duration) (string, bool) {
	f.mu.Lock()
	f.prompts = append(f.prompts, prompt)
	f.transcript = append(f.transcript, "? "+prompt)
	if f.block {
		ch := f.blocked
		f.mu.Unlock()
		if ch != nil {
			close(ch)
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		return "", false
	}
	defer f.mu.Unlock()
	if f.onAsk != nil {
		f.onAsk()
	}
	if f.timeout || len(f.answers) == 0 {
		return "", false
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, true
}

func (f *fakeIO) AskSecret(_ context.Context, prompt string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	f.transcript = append(f.transcript, "?secret "+prompt)
	if len(f.secrets) == 0 {
		return nil, errors.New("no answer")
	}
	s := f.secrets[0]
	f.secrets = f.secrets[1:]
	return []byte(s), nil
}

func (f *fakeIO) promptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.prompts)
}

// ansi matches terminal colour sequences.
var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func (f *fakeIO) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.out, "\n")
}

func uatProfile() config.Profile {
	return config.Profile{
		Name: "uat", Engine: config.EngineMariaDB, Host: "db.uat.example.com", Port: 3306,
		User: "alice", Credentials: config.CredentialsAsk, Tier: config.TierRead,
		Detectors: []string{"email"}, Limits: config.DefaultLimits(false),
	}
}

func prodProfile() config.Profile {
	p := uatProfile()
	p.Name, p.Host, p.Production, p.Limits = "prod", "db.example.com", true, config.DefaultLimits(true)
	return p
}

func okPlan() engine.Plan {
	return engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{
		{Table: "users", Access: engine.AccessLookup, EstRows: 1},
	}}}
}

func heavyPlan() engine.Plan {
	return engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{
		{Table: "users", Access: engine.AccessFull, EstRows: 50_000_000},
	}}}
}

func userResult() engine.Result {
	return engine.Result{
		Columns: []engine.ResultColumn{
			{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"},
			{Label: "email", OriginDB: "app", OriginTable: "users", OriginColumn: "email"},
			{Label: "note", OriginDB: "app", OriginTable: "users", OriginColumn: "note"},
		},
		Rows: [][]any{{int64(1), "alice@example.com", "write to bob@example.org"}},
	}
}

type harness struct {
	s     *Server
	sess  *fakeSession
	io    *fakeIO
	root  string
	state string
	now   time.Time
	// hub is the fake lockhub the console is decided on (attachHub),
	// unless the test brought its own (withHub).
	hub *hubtest.Hub
}

type hopt func(*ServerConfig)

func newHarness(t *testing.T, p config.Profile, opts ...hopt) *harness {
	t.Helper()
	h := &harness{
		sess:  &fakeSession{origin: true, dbs: []string{"app", "other"}, plan: okPlan(), result: userResult()},
		io:    &fakeIO{},
		root:  t.TempDir(),
		state: t.TempDir(),
		now:   time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC),
	}
	log, err := audit.Open(h.state)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{
		Policy:      config.NewPolicy(p, []string{"app.users.email"}, nil),
		RulesPath:   filepath.Join(h.root, pii.RulesFile),
		StateDir:    h.state,
		ApprovedKey: config.ApprovedKey(h.root, p.Name),
		Session:     h.sess,
		DBUser:      p.User,
		Databases:   h.sess.dbs,
		Audit:       log,
		IO:          h.io,
		Now:         func() time.Time { return h.now },
		Version:     "test",
	}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.Hub == nil {
		// One mode: every console is decided on a hub.
		attachHub(t, &h.hub)(&cfg)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.s = s
	return h
}

func (h *harness) call(t *testing.T, method string, params any) ipc.Response {
	t.Helper()
	return h.callCtx(t, context.Background(), method, params)
}

func (h *harness) callCtx(t *testing.T, ctx context.Context, method string, params any) ipc.Response {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return h.s.Handle(ctx, ipc.Request{JSONRPC: "2.0", ID: 7, Method: method, Params: raw})
}

func (h *harness) ok(t *testing.T, method string, params, out any) {
	t.Helper()
	resp := h.call(t, method, params)
	if resp.Error != nil {
		t.Fatalf("%s: unexpected error %d %q", method, resp.Error.Code, resp.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			t.Fatalf("%s: decode result: %v", method, err)
		}
	}
}

func (h *harness) plan(t *testing.T, sql string, unmask bool) ipc.PlanResult {
	t.Helper()
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: sql, Unmask: unmask}, &pr)
	if pr.PlanID == "" {
		t.Fatal("empty plan id")
	}
	return pr
}

func wantCode(t *testing.T, resp ipc.Response, code int) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("want error %d, got result %s", code, resp.Result)
	}
	if resp.Error.Code != code {
		t.Fatalf("want error %d, got %d %q", code, resp.Error.Code, resp.Error.Message)
	}
	wantRefusalData(t, resp)
}

// wantRefusalData checks the structured form of a refusal: every refusal
// names a known code other than the fail-closed one, its retry rule and a
// hint; any other error carries none.
func wantRefusalData(t *testing.T, resp ipc.Response) {
	t.Helper()
	d := resp.Error.Data
	if resp.Error.Code != ipc.CodeRefused {
		if d != nil {
			t.Fatalf("error %d carries refusal data %+v", resp.Error.Code, d)
		}
		return
	}
	if d == nil {
		t.Fatalf("refusal without a code: %q", resp.Error.Message)
	}
	if !d.Code.Known() || d.Code == refusal.Policy {
		t.Fatalf("refusal %q has code %q", resp.Error.Message, d.Code)
	}
	if d.Retry != d.Code.Retry() || d.Hint == "" {
		t.Fatalf("refusal %q: %+v", resp.Error.Message, d)
	}
}

func (h *harness) auditLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const selectUsers = "SELECT id, email, note FROM users WHERE id = 1 LIMIT 10"

func TestApprovedRunReturnsMaskedRows(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	if pr.Class != "read" || pr.Verdict != "OK" || pr.Host != "db.uat.example.com" || pr.Profile != "uat" {
		t.Fatalf("plan result: %+v", pr)
	}
	if h.io.promptCount() != 0 {
		t.Fatal("plan must not prompt")
	}
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
	if len(rr.Rows) != 1 || len(rr.Columns) != 3 {
		t.Fatalf("run result: %+v", rr)
	}
	if got := rr.Rows[0][1]; !strings.HasPrefix(fmt.Sprint(got), "<redacted") {
		t.Errorf("email column not masked by rule: %v", got)
	}
	if got := rr.Rows[0][2]; got == "write to bob@example.org" || !strings.Contains(got.(string), "b***(") {
		t.Errorf("email detector not applied: %v", got)
	}
	if strings.Contains(rr.Text, "alice@example.com") || !strings.Contains(rr.Text, "<redacted") {
		t.Errorf("text rendering not masked: %q", rr.Text)
	}
	if h.io.promptCount() != 0 {
		t.Errorf("asked on the terminal: %q", h.io.prompts)
	}
	screen := ansi.ReplaceAllString(h.io.output(), "")
	for _, want := range []string{"UAT", "db.uat.example.com", "alice", "tier read", selectUsers, "verdict OK", "PII: masked",
		"reads: app.users", "PII columns touched: users.email (select)", "masked outputs: email → redact", "returns at most 10 rows"} {
		if !strings.Contains(screen, want) {
			t.Errorf("approval screen lacks %q:\n%s", want, screen)
		}
	}
	log := h.auditLog(t)
	if !strings.Contains(log, `"event":"approved"`) || strings.Contains(log, "alice@example.com") {
		t.Errorf("audit log:\n%s", log)
	}
}

// auditRecords decodes the audit log, one map per line.
func (h *harness) auditRecords(t *testing.T) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(h.auditLog(t)), "\n") {
		if l == "" {
			continue // no record yet
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		recs = append(recs, m)
	}
	return recs
}

// Every record of a client request names the requester: its uid, pid and
// account, from the kernel's peer credentials, but not its process name,
// which the agent chooses.
func TestAuditNamesTheRequester(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no uid on Windows: the peer of a record is a Unix socket credential")
	}
	h := newHarness(t, uatProfile())
	uid := os.Getuid()
	ctx := withPeer(context.Background(), ipc.Cred{UID: uid, GID: os.Getgid(), PID: 4242})
	if r := h.callCtx(t, ctx, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}); r.Error != nil {
		t.Fatal(r.Error.Message)
	}
	r := h.callCtx(t, ctx, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers})
	if r.Error != nil {
		t.Fatal(r.Error.Message)
	}
	var pr ipc.PlanResult
	if err := json.Unmarshal(r.Result, &pr); err != nil {
		t.Fatal(err)
	}
	wantCode(t, h.callCtx(t, ctx, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "DELETE FROM users WHERE id = 1"}), ipc.CodeRefused)
	// The run comes from another process than the plan: it is the one named.
	runCtx := withPeer(context.Background(), ipc.Cred{UID: uid, GID: os.Getgid(), PID: 4343})
	pendingTicket(t, h.callCtx(t, runCtx, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), "pending")
	// uid 0 is a uid, not an unknown one.
	root := withPeer(context.Background(), ipc.Cred{UID: 0, PID: 1})
	if r := h.callCtx(t, root, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}); r.Error != nil {
		t.Fatal(r.Error.Message)
	}

	name := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name = u.Username
	}
	want := map[string]float64{"catalog": 4242, "refused": 4242, "pending": 4343}
	seen := map[string]bool{}
	rootSeen := false
	for _, rec := range h.auditRecords(t) {
		ev, _ := rec["event"].(string)
		for k := range rec {
			if strings.Contains(k, "comm") || strings.Contains(k, "process") {
				t.Errorf("%s record carries the process name: %v", ev, rec)
			}
		}
		pid, ok := want[ev]
		if !ok {
			continue
		}
		if rec["peer_pid"] == float64(1) {
			rootSeen = rec["peer_uid"] == float64(0)
			continue
		}
		seen[ev] = true
		if rec["peer_uid"] != float64(uid) || rec["peer_pid"] != pid {
			t.Errorf("%s record: peer_uid %v peer_pid %v, want %d %v", ev, rec["peer_uid"], rec["peer_pid"], uid, pid)
		}
		if name != "" && rec["peer_user"] != name {
			t.Errorf("%s record: peer_user %v, want %q", ev, rec["peer_user"], name)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("records seen %v, want %v", seen, want)
	}
	if !rootSeen {
		t.Error("the catalog read of uid 0 does not record peer_uid 0")
	}
	// Without a peer in the request there is nothing to name.
	h2 := newHarness(t, uatProfile())
	h2.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	if log := h2.auditLog(t); strings.Contains(log, "peer_") {
		t.Errorf("a record without a peer names one:\n%s", log)
	}
}

// A database error is server text: it reaches the console screen escaped,
// so that it cannot drive the human's terminal.
func TestRunErrorIsEscapedOnScreen(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.runErr = errors.New("Deadlock found \x1b]0;approved\x07\x1b[2J when trying to get lock")
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	if r := h.approveRun(t, pr.PlanID); r.Error == nil {
		t.Fatal("the run error was not reported")
	}
	out := h.io.output()
	if strings.Contains(out, "\x1b]0;") || strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\x07") {
		t.Errorf("raw control sequences from the server reached the screen: %q", out)
	}
	if !strings.Contains(out, `\x1b]0;approved\x07`) {
		t.Errorf("escaped error text missing from the screen: %q", out)
	}
}

func TestPlanIsOneShotAndExpires(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y", "y"}
	h.okRun(t, pr.PlanID, nil)
	wantCode(t, h.approveRun(t, pr.PlanID), ipc.CodeNoSuchPlan)

	pr = h.plan(t, selectUsers, false)
	h.now = h.now.Add(PlanTTL + time.Second)
	wantCode(t, h.approveRun(t, pr.PlanID), ipc.CodeNoSuchPlan)
	wantCode(t, h.approveRun(t, "nope"), ipc.CodeNoSuchPlan)
	if n := h.sess.runCount(); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
}

func allowUnmask(c *ServerConfig) { c.AllowUnmask = true }

func TestClassAboveTierRefusedWithoutPrompt(t *testing.T) {
	h := newHarness(t, uatProfile())
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "DELETE FROM users WHERE id = 1"})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "tier") {
		t.Errorf("message %q", resp.Error.Message)
	}
	resp = h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT * FROM users; DROP TABLE users"})
	wantCode(t, resp, ipc.CodeRefused)
	if h.io.promptCount() != 0 || len(h.sess.explains) != 0 {
		t.Fatal("refused statement reached the prompt or the engine")
	}
	if !strings.Contains(h.auditLog(t), `"event":"refused"`) {
		t.Error("refusal not audited")
	}
}

func TestRefuseVerdictNeverPrompts(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.plan = heavyPlan()
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id FROM users LIMIT 10"})
	wantCode(t, resp, ipc.CodeRefused)
	if h.io.promptCount() != 0 || h.sess.runCount() != 0 {
		t.Fatal("REFUSE verdict prompted or ran")
	}
}

func TestUnknownDatabaseRefused(t *testing.T) {
	h := newHarness(t, uatProfile())
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "mysql", SQL: selectUsers}), ipc.CodeRefused)
	wantCode(t, h.call(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "nope"}), ipc.CodeRefused)
}

// An alias no longer hides a PII column: the analyser resolves it to its
// source, with or without engine-reported origins.
func TestAliasMaskedByProvenance(t *testing.T) {
	for _, origin := range []bool{false, true} {
		h := newHarness(t, uatProfile())
		h.sess.origin = origin
		h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "x"}}, Rows: [][]any{{"alice@example.com"}}}
		pr := h.plan(t, "SELECT x FROM (SELECT email AS x FROM users) s LIMIT 1", false)
		h.io.answers = []string{"y"}
		var rr ipc.RunResult
		h.okRun(t, pr.PlanID, &rr)
		if got := rr.Rows[0][0]; !strings.HasPrefix(fmt.Sprint(got), "<redacted") {
			t.Errorf("origin=%v: aliased PII column not masked: %v", origin, got)
		}
	}
	// A label the analysis did not expect drops the result.
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{"alice@example.com"}}}
	pr := h.plan(t, "SELECT email AS x FROM users LIMIT 1", false)
	h.io.answers = []string{"y"}
	wantCode(t, h.approveRun(t, pr.PlanID), ipc.CodeRefused)
}

func TestPIIAddWritesFile(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.users.phone"}, nil)
	r, err := pii.LoadRules(h.root)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Matches("app", "users", "phone") {
		t.Fatalf("pii.toml rules: %+v", r)
	}
	var list ipc.PIIListResult
	h.ok(t, ipc.MethodPIIList, nil, &list)
	if strings.Join(list.Mask, ",") != "app.users.email,app.users.phone" {
		t.Errorf("pii.list: %+v", list)
	}
	ap, err := config.LoadApproved(h.state, config.ApprovedKey(h.root, "uat"))
	if err != nil || len(ap.PIIMask) != 2 {
		t.Errorf("approved policy not updated: %+v %v", ap, err)
	}
	wantCode(t, h.call(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "a.b"}), ipc.CodeInvalidParams)
}

func TestChangeRequestDoesNotAlterPolicy(t *testing.T) {
	h := newHarness(t, uatProfile())
	var cr ipc.ChangeResult
	h.ok(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "tier=write"}, &cr)
	if !cr.Queued {
		t.Fatal("not queued")
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Tier != "read" {
		t.Fatalf("tier changed to %s", st.Tier)
	}
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "DELETE FROM users WHERE id = 1"}), ipc.CodeRefused)
	if !strings.Contains(h.io.output(), "tier=write") {
		t.Error("change request not shown to the human")
	}
	h.s.Command(context.Background(), ":review")
	if h.io.promptCount() != 0 {
		t.Error("reviewing a change request must not offer to apply it")
	}
}

const projectConfig = `[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
detectors = ["email"]

[profiles.uat.limits]
max_rows = %d
`

func writeProjectConfig(t *testing.T, root string, maxRows int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(projectConfig, "%d", itoa(maxRows), 1)
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestLooseningFileEditBlocksUntilReviewed(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	load := func() (config.Policy, error) {
		cfg, err := config.LoadFrom(root, "")
		if err != nil {
			return config.Policy{}, err
		}
		r, err := pii.LoadRules(root)
		if err != nil {
			return config.Policy{}, err
		}
		return config.NewPolicy(cfg.Profiles["uat"], r.Mask, r.Allow), nil
	}
	initial, err := load()
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, initial.Profile, func(c *ServerConfig) {
		c.Policy = initial
		c.RulesPath = filepath.Join(root, pii.RulesFile)
		c.ApprovedKey = config.ApprovedKey(root, "uat")
		c.LoadPolicy = load
	})

	// Tightening: applied at once, without a prompt.
	writeProjectConfig(t, root, 100)
	h.s.CheckPolicy()
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Limits.MaxRows != 100 || h.io.promptCount() != 0 {
		t.Fatalf("tightening not applied silently: max_rows=%d prompts=%d", st.Limits.MaxRows, h.io.promptCount())
	}

	// Loosening: queued, plans refused with -32006.
	writeProjectConfig(t, root, 5000)
	h.s.CheckPolicy()
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers}), ipc.CodePolicyPending)
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Limits.MaxRows != 100 {
		t.Fatalf("loosening applied without confirmation: max_rows=%d", st.Limits.MaxRows)
	}
	if !strings.Contains(h.io.output(), ":review") {
		t.Error("pending change not announced")
	}
	// Polling again does not re-announce or apply it.
	h.s.CheckPolicy()
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers}), ipc.CodePolicyPending)

	// :review accepted (the answer is case-insensitive) → applied and
	// recorded; the prompt rings the bell.
	h.io.answers = []string{"Y"}
	h.s.Command(context.Background(), ":review")
	if h.io.bells != 1 {
		t.Errorf("bells = %d, want 1 for the :review prompt", h.io.bells)
	}
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Limits.MaxRows != 5000 {
		t.Fatalf("accepted change not applied: max_rows=%d", st.Limits.MaxRows)
	}
	h.plan(t, selectUsers, false)
	ap, err := config.LoadApproved(h.state, config.ApprovedKey(root, "uat"))
	if err != nil || ap.Profile.Limits.MaxRows != 5000 {
		t.Fatalf("approved policy not saved: %+v %v", ap, err)
	}

	// A refused loosening keeps the approved policy and unblocks clients.
	writeProjectConfig(t, root, 9000)
	h.s.CheckPolicy()
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Limits.MaxRows != 5000 {
		t.Fatalf("refused change applied: %d", st.Limits.MaxRows)
	}
	h.plan(t, selectUsers, false)
	if !strings.Contains(h.auditLog(t), `"decision":"refused"`) {
		t.Error("refused policy change not audited")
	}
}

func TestCatalogNotPromptedButAudited(t *testing.T) {
	h := newHarness(t, uatProfile())
	var tr ipc.TablesResult
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, &tr)
	if len(tr.Tables) != 1 || tr.Tables[0] != "users" {
		t.Fatalf("tables: %+v", tr)
	}
	var ti engine.TableInfo
	h.ok(t, ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: "app", Table: "users"}, &ti)
	if ti.Table != "users" {
		t.Fatalf("describe: %+v", ti)
	}
	if h.io.promptCount() != 0 {
		t.Fatal("catalog prompted")
	}
	if n := strings.Count(h.auditLog(t), `"event":"catalog"`); n != 2 {
		t.Errorf("catalog audit records = %d, want 2", n)
	}
}

func TestHelloStatusLogout(t *testing.T) {
	h := newHarness(t, uatProfile())
	var hr ipc.HelloResult
	h.ok(t, ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr)
	if hr.Profile != "uat" || hr.ProtocolMajor != ipc.ProtocolMajor {
		t.Fatalf("hello: %+v", hr)
	}
	wantCode(t, h.call(t, ipc.MethodHello, ipc.HelloParams{ProtocolMajor: 99}), ipc.CodeInvalidRequest)
	wantCode(t, h.call(t, "nope", nil), ipc.CodeMethodNotFound)

	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.Profile != "uat" || st.Engine != "mariadb" || st.Tier != "read" || len(st.Databases) != 2 ||
		st.IdleTimeoutInS != 20*60 || st.SessionEndsInS != 4*3600 || st.Limits.IdleTimeout != 20*time.Minute || st.Limits.MaxSession != 4*time.Hour {
		t.Fatalf("status: %+v", st)
	}
	h.ok(t, ipc.MethodLogout, nil, nil)
	if reason, ended := h.s.Ended(); !ended || reason != "logout" {
		t.Fatalf("logout did not end the session: %q %v", reason, ended)
	}
}

// A profile that sets database serves that database only: the PII scan
// covers it alone, so another database the account can see would be read
// without its rules.
func TestProfileDatabaseServedOnly(t *testing.T) {
	p := uatProfile()
	p.Database = "app"
	h := newHarness(t, p)
	const want = `database "other" is not served: this profile serves "app" only (set database = "" to serve every database the account can see)`
	for _, c := range []struct {
		method string
		params any
	}{
		{ipc.MethodCatalogList, ipc.TablesParams{DB: "other"}},
		{ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: "other", Table: "users"}},
		{ipc.MethodQueryPlan, ipc.PlanParams{DB: "other", SQL: "SELECT id FROM users LIMIT 5"}},
	} {
		resp := h.call(t, c.method, c.params)
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error.Message != want {
			t.Errorf("%s: %q", c.method, resp.Error.Message)
		}
	}
	// A qualified name does not reach the other database either.
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT email FROM other.users LIMIT 5"})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "unknown table other.users") {
		t.Errorf("qualified name: %q", resp.Error.Message)
	}
	if n := len(h.sess.explains) + h.sess.catalog; n != 0 {
		t.Errorf("session reached %d times, want 0", n)
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !slices.Equal(st.Databases, []string{"app"}) {
		t.Errorf("status databases = %v, want [app]", st.Databases)
	}
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{}, nil)

	// Without a profile database, every listed database is served.
	h = newHarness(t, uatProfile())
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !slices.Equal(st.Databases, []string{"app", "other"}) {
		t.Errorf("status databases = %v, want [app other]", st.Databases)
	}
	for _, db := range []string{"app", "other"} {
		h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: db}, nil)
		h.ok(t, ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: db, Table: "users"}, nil)
		h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: db, SQL: "SELECT id FROM users LIMIT 5"}, nil)
	}
}

func TestServedDatabases(t *testing.T) {
	listed := []string{"app", "other"}
	if got := servedDatabases("app", listed); !slices.Equal(got, []string{"app"}) {
		t.Errorf("profile database: %v", got)
	}
	if got := servedDatabases("", listed); !slices.Equal(got, listed) {
		t.Errorf("no profile database: %v", got)
	}
}

func TestIdleAndMaxSession(t *testing.T) {
	idle := config.DefaultLimits(false).IdleTimeout
	h := newHarness(t, uatProfile())
	h.now = h.now.Add(idle - time.Second)
	h.s.Tick()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended before the idle timeout")
	}
	h.ok(t, ipc.MethodStatus, nil, nil)
	h.now = h.now.Add(idle + time.Second)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("idle: %q %v", reason, ended)
	}
}

// The profile's limits.idle_timeout and limits.max_session drive Tick, and
// a policy change applied while running takes effect at the next tick.
func TestCustomSessionLimits(t *testing.T) {
	p := uatProfile()
	p.Limits.IdleTimeout, p.Limits.MaxSession = 3*time.Minute, 10*time.Minute
	cur := config.NewPolicy(p, []string{"app.users.email"}, nil)
	h := newHarness(t, p, func(c *ServerConfig) {
		c.LoadPolicy = func() (config.Policy, error) { return cur, nil }
	})
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.IdleTimeoutInS != 180 || st.SessionEndsInS != 600 {
		t.Fatalf("status: idle %ds, ends in %ds", st.IdleTimeoutInS, st.SessionEndsInS)
	}
	h.s.Command(context.Background(), ":status")
	if out := h.io.output(); !strings.Contains(out, "(max_session 10m0s) · idle_timeout 3m0s") {
		t.Errorf(":status does not show the session limits:\n%s", out)
	}
	if got := strings.Join(describePolicy(cur), "\n"); !strings.Contains(got, "session: idle_timeout 3m0s · max_session 10m0s") {
		t.Errorf("describePolicy does not show the session limits:\n%s", got)
	}
	h.now = h.now.Add(3*time.Minute - time.Second)
	h.s.Tick()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended before the custom idle timeout")
	}
	h.ok(t, ipc.MethodStatus, nil, nil) // activity

	// A shorter idle timeout tightens: applied at once, used by the next tick.
	p.Limits.IdleTimeout = time.Minute
	cur = config.NewPolicy(p, []string{"app.users.email"}, nil)
	h.s.CheckPolicy()
	if h.io.promptCount() != 0 {
		t.Fatal("a shorter idle timeout asked for confirmation")
	}
	h.now = h.now.Add(time.Minute + time.Second)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("custom idle: %q %v", reason, ended)
	}

	h = newHarness(t, p)
	for range 10 {
		h.now = h.now.Add(59 * time.Second)
		h.ok(t, ipc.MethodStatus, nil, nil)
		h.s.Tick()
	}
	if _, ended := h.s.Ended(); ended { // 9m50s in, active
		t.Fatal("ended before the custom max_session")
	}
	h.now = h.now.Add(10 * time.Second)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "maximum session length" {
		t.Fatalf("custom max_session: %q %v", reason, ended)
	}
}

func TestRunErrorIsSanitisedAndConnLostMapped(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.runErr = errors.Join(engine.ErrConnLost, errors.New("broken pipe"))
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	wantCode(t, h.approveRun(t, pr.PlanID), ipc.CodeConnLost)
}

// A server error can quote a row value (a failed cast in WHERE): with
// masking on, it must reach neither the client nor the audit log.
func TestRunErrorTextIsRedacted(t *testing.T) {
	// EXTRACTVALUE is outside the function allowlist.
	h := newHarness(t, uatProfile(), allowUnmask)
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app",
		SQL: "SELECT 1 FROM users WHERE EXTRACTVALUE(1, CONCAT(0x7e, email)) LIMIT 1"}), ipc.CodeRefused)

	// A server message never reaches the client, masked or not; the console
	// and the audit log keep a redacted copy.
	for _, unmask := range []bool{false, true} {
		h.sess.runErr = errors.New(`mariadb: error 1105 (HY000): XPATH syntax error: '~zed.secret@example.com'`)
		pr := h.plan(t, "SELECT id FROM users WHERE id = 1 LIMIT 1", unmask)
		h.io.answers = []string{"y"}
		resp := h.approveRun(t, pr.PlanID)
		wantCode(t, resp, ipc.CodeInternal)
		if strings.Contains(resp.Error.Message, "zed.secret") || strings.Contains(resp.Error.Message, "1105") {
			t.Errorf("unmask=%v: client message: %q", unmask, resp.Error.Message)
		}
	}
	if strings.Contains(h.auditLog(t), "zed.secret") || strings.Contains(h.io.output(), "zed.secret") {
		t.Errorf("value in audit log or console:\n%s\n%s", h.auditLog(t), h.io.output())
	}
}

func writeRules(t *testing.T, root, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, pii.RulesFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The mask modes of pii.toml reach the policy, and a mode change other
// than back to redact waits for the human.
func TestPolicyFromFilesKeepsMaskModes(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 100)
	rulesPath := filepath.Join(root, pii.RulesFile)
	writeRules(t, root, "[[mask]]\ncolumn = \"app.users.email\"\nmode = \"partial\"\n")
	load := func() (config.Policy, error) { return policyFromFiles(root, "uat", rulesPath, "uat") }
	cur, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cur.PIIModes["app.users.email"]; got != "partial" {
		t.Fatalf("mode of app.users.email = %q, want partial (modes %v)", got, cur.PIIModes)
	}

	// Approved as redact, now partial: a loosening.
	writeRules(t, root, "[[mask]]\ncolumn = \"app.users.email\"\n")
	initial, err := load()
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, initial.Profile, func(c *ServerConfig) {
		c.Policy = initial
		c.RulesPath = rulesPath
		c.ApprovedKey = config.ApprovedKey(root, "uat")
		c.LoadPolicy = load
	})
	writeRules(t, root, "[[mask]]\ncolumn = \"app.users.email\"\nmode = \"partial\"\n")
	h.s.CheckPolicy()
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers}), ipc.CodePolicyPending)
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if got := h.s.approved.PIIModes["app.users.email"]; got != "partial" {
		t.Fatalf("accepted mode not applied: %q", got)
	}

	// Back to redact: applied at once, without a prompt.
	prompts := h.io.promptCount()
	writeRules(t, root, "[[mask]]\ncolumn = \"app.users.email\"\n")
	h.s.CheckPolicy()
	if h.s.pendingPolicy() || h.io.promptCount() != prompts {
		t.Fatal("a change back to redact waited for the human")
	}
	if _, ok := h.s.approved.PIIModes["app.users.email"]; ok {
		t.Fatalf("redact not applied: %v", h.s.approved.PIIModes)
	}
}

// A mask rule added by a client keeps the modes of the other rules.
func TestPIIAddKeepsMaskModes(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Policy = c.Policy.WithModes(map[string]string{"app.users.email": "partial"})
	})
	h.ok(t, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "app.users.phone"}, nil)
	if got := h.s.approved.PIIModes["app.users.email"]; got != "partial" {
		t.Fatalf("mode lost after pii add: %v", h.s.approved.PIIModes)
	}
}

// Unmasked output is off unless the human started the console with
// --allow-unmask: the agent cannot turn it on by itself.
func TestUnmaskOffByDefault(t *testing.T) {
	h := newHarness(t, uatProfile())
	resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Unmask: true})
	wantCode(t, resp, ipc.CodeRefused)
	if !strings.Contains(resp.Error.Message, "--allow-unmask") {
		t.Errorf("refusal does not name the option: %q", resp.Error.Message)
	}
	if h.io.promptCount() != 0 || h.sess.runCount() != 0 {
		t.Fatal("refused unmask request prompted or ran")
	}
	if !strings.Contains(h.auditLog(t), "--allow-unmask") {
		t.Error("refused unmask request not audited")
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.AllowUnmask {
		t.Error("status reports unmask allowed")
	}
	// A masked plan still works.
	h.plan(t, selectUsers, false)

	h = newHarness(t, uatProfile(), allowUnmask)
	if pr := h.plan(t, selectUsers, true); !pr.Unmask {
		t.Fatal("unmask flag lost with --allow-unmask")
	}
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !st.AllowUnmask {
		t.Error("status does not report unmask allowed")
	}
}

// A masked run never prints its rows in the console.
func TestMaskedResultNotShownInConsole(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.okRun(t, pr.PlanID, nil)
	if strings.Contains(h.io.output(), "alice@example.com") || strings.Contains(h.io.output(), "UNMASKED result") {
		t.Errorf("masked run printed rows:\n%s", h.io.output())
	}
}

func showResults(c *ServerConfig) { c.ShowResults = true }

// Without --show-results a masked run prints no row in the console.
func TestShowResultsOffByDefault(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.okRun(t, pr.PlanID, nil)
	out := h.io.output()
	if strings.Contains(out, "alice@example.com") || strings.Contains(out, "result in clear") || strings.Contains(out, "shown here in clear") {
		t.Errorf("clear rows or reminder without --show-results:\n%s", out)
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.ShowResults {
		t.Error("status reports show results on")
	}
}

// With --show-results the human sees the clear rows, the masked cells
// highlighted; the client still gets them masked.
func TestShowResultsPrintsClearRows(t *testing.T) {
	h := newHarness(t, uatProfile(), showResults)
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
	out := h.io.output()
	if !strings.Contains(out, "result: shown here in clear") {
		t.Errorf("approval screen lacks the reminder:\n%s", out)
	}
	if i, j := strings.Index(out, "result: shown here in clear"), strings.Index(out, "result in clear"); i < 0 || j < i {
		t.Errorf("reminder not before the result:\n%s", out)
	}
	for _, want := range []string{"result in clear (shown here only; the agent got it masked)", "alice@example.com", "write to bob@example.org", "(1 rows)"} {
		if !strings.Contains(out, want) {
			t.Errorf("console lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, paint.Yellow("alice@example.com")) {
		t.Errorf("masked cell not highlighted:\n%q", out)
	}
	if strings.Contains(out, paint.Yellow("1")+" ") {
		t.Errorf("unmasked id highlighted:\n%q", out)
	}
	// The client response is unchanged.
	if !strings.HasPrefix(fmt.Sprint(rr.Rows[0][1]), "<redacted") || strings.Contains(rr.Text, "alice@example.com") || strings.Contains(fmt.Sprint(rr.Rows), "bob@example.org") {
		t.Errorf("client got clear values: %+v", rr)
	}
	if strings.Contains(h.auditLog(t), "alice@example.com") || strings.Contains(h.auditLog(t), "bob@example.org") {
		t.Error("row data in the audit log")
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !st.ShowResults {
		t.Error("status does not report show results on")
	}
}

// The output caps apply to the clear rows as to the client's.
func TestShowResultsCapped(t *testing.T) {
	p := uatProfile()
	p.Limits.MaxCellChars = 5
	h := newHarness(t, p, showResults)
	pr := h.plan(t, selectUsers, false)
	h.okRun(t, pr.PlanID, nil)
	if strings.Contains(h.io.output(), "alice@example.com") {
		t.Errorf("cell not capped at max_cell_chars:\n%s", h.io.output())
	}
}

// No client can turn --show-results on: an extra plan parameter is refused.
func TestShowResultsNotSettableByClient(t *testing.T) {
	h := newHarness(t, uatProfile())
	wantCode(t, h.call(t, ipc.MethodQueryPlan, map[string]any{"db": "app", "sql": selectUsers, "show_results": true}), ipc.CodeInvalidParams)
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, map[string]any{"show_results": true}, &st)
	if st.ShowResults {
		t.Error("a status request turned show results on")
	}
	pr := h.plan(t, selectUsers, false)
	h.okRun(t, pr.PlanID, nil)
	if strings.Contains(h.io.output(), "alice@example.com") {
		t.Error("clear rows shown after a client asked for them")
	}
}

// No config file can turn it on either: the key is unknown, so refused.
func TestShowResultsNotSettableByConfig(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 100)
	path := filepath.Join(root, ".locksql", "config.toml")
	for _, extra := range []string{"show_results = true\n", "\n[console]\nshow_results = true\n"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(b) + extra // a top-level table
		if !strings.Contains(extra, "[") {
			// A key of the profile.
			body = strings.Replace(string(b), "user = \"alice\"\n", "user = \"alice\"\n"+extra, 1)
		}
		p := filepath.Join(t.TempDir(), ".locksql")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "config.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadFrom(filepath.Dir(p), ""); err == nil {
			t.Errorf("config with %q accepted", extra)
		}
	}
}

func TestFlagNoticesAndReadyLines(t *testing.T) {
	if n := flagNotices(Options{}, uatProfile()); len(n) != 0 {
		t.Errorf("notices without flags: %q", n)
	}
	n := strings.Join(flagNotices(Options{ShowResults: true}, uatProfile()), "\n")
	if !strings.Contains(n, "--show-results") || !strings.Contains(n, "in clear") {
		t.Errorf("no --show-results warning: %q", n)
	}
	prod := uatProfile()
	prod.Production = true
	n = strings.Join(flagNotices(Options{ShowResults: true}, prod), "\n")
	if !strings.HasPrefix(n, red) || !strings.Contains(n, "PRODUCTION") {
		t.Errorf("production warning not red: %q", n)
	}
	r := strings.Join(readyLines("/run/x.sock", "", true), "\n")
	if !strings.Contains(r, "shown in clear in this console (--show-results)") {
		t.Errorf("Ready block lacks the results line: %q", r)
	}
	if strings.Contains(strings.Join(readyLines("/run/x.sock", "", false), "\n"), "shown in clear") {
		t.Error("results line without the flag")
	}
}

// The agent's intent is one line shown on the approval screen, under the
// requester, and kept on every audit record of the plan.
func TestIntentShownAndAudited(t *testing.T) {
	const intent = "find why order 88123 was not emailed"
	h := newHarness(t, uatProfile())
	var pr ipc.PlanResult
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Intent: intent}, &pr)
	h.okRun(t, pr.PlanID, nil)
	screen := ansi.ReplaceAllString(h.io.output(), "")
	if !strings.Contains(screen, "│ agent: "+intent+"\n") {
		t.Errorf("approval screen lacks the intent:\n%s", screen)
	}

	// Refused at plan time and denied in lockhub: the intent is kept.
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "DELETE FROM users WHERE id = 1", Intent: intent}), ipc.CodeRefused)
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Intent: intent}, &pr)
	wantCode(t, h.decideRun(t, pr.PlanID, ticket.Denied, ""), ipc.CodeDenied)
	var events []string
	for _, r := range h.auditRecords(t) {
		events = append(events, fmt.Sprint(r["event"]))
		if r["intent"] != intent && r["event"] != "denied" {
			t.Errorf("%v record without the intent: %v", r["event"], r)
		}
	}
	if !slices.Equal(events, []string{"pending", "approved", "run", "refused", "pending", "denied"}) {
		t.Errorf("events %v", events)
	}

	// No intent, no line; control characters are escaped.
	before := len(h.io.out)
	pr = h.plan(t, selectUsers, false)
	h.okRun(t, pr.PlanID, nil)
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Intent: "a\x1b[2Jb"}, &pr)
	h.okRun(t, pr.PlanID, nil)
	screen = strings.Join(h.io.out[before:], "\n")
	if n := strings.Count(screen, "agent: "); n != 1 || strings.Contains(screen, "\x1b[2J") {
		t.Errorf("intent lines %d, screen:\n%q", n, screen)
	}
	if rec := h.auditRecords(t)[6]; rec["intent"] != nil {
		t.Errorf("empty intent audited: %v", rec)
	}
}

func TestIntentMustBeOneShortLine(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.ok(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Intent: strings.Repeat("x", 200)}, nil)
	for _, bad := range []string{strings.Repeat("x", 201), "two\nlines", "cr\rhere"} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Intent: bad})
		wantCode(t, resp, ipc.CodeInvalidParams)
		if resp.Error.Message != "intent must be one line of at most 200 bytes" {
			t.Errorf("%q: message %q", bad, resp.Error.Message)
		}
	}
}

func TestTerminalBell(t *testing.T) {
	var out strings.Builder
	NewTerminal(nil, &out).Bell()
	if out.String() != "\a" {
		t.Fatalf("bell wrote %q", out.String())
	}
}

// TestRunReportsCutCells checks that the agent is told a value was cut by
// the engine's cap, and that the cut email gets no reference.
func TestRunReportsCutCells(t *testing.T) {
	h := newHarness(t, uatProfile())
	res := userResult()
	res.Rows[0][1] = "alice@exa…"
	res.Rows[0][2] = strings.Repeat("7", 100) + "…"
	res.MarkCut(0, 1)
	res.MarkCut(0, 2)
	h.sess.result = res
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	var rr ipc.RunResult
	h.okRun(t, pr.PlanID, &rr)
	if rr.CutCells != 2 || !strings.Contains(rr.Text, "[2 cells cut") {
		t.Errorf("cut_cells = %d, text %q", rr.CutCells, rr.Text)
	}
	if got := fmt.Sprint(rr.Rows[0][1]); got != pii.Redacted {
		t.Errorf("cut email = %q, want plain %s", got, pii.Redacted)
	}
}
