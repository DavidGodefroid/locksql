package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// fakeSession is a scripted engine.Session.
type fakeSession struct {
	mu       sync.Mutex
	origin   bool
	dbs      []string
	plan     engine.Plan
	result   engine.Result
	runErr   error
	explains []string
	runs     []string
	catalog  int
	extra    []string // ExtraPrivileges warnings
	closed   bool
	// count answers the k-anonymity row counts (nil: the default result).
	count *engine.Result
	cols  []engine.ColumnInfo // appended to the catalog Columns answers
}

func (f *fakeSession) ServerVersion() string { return "11.4.0-MariaDB" }
func (f *fakeSession) Flavor() engine.Flavor { return engine.FlavorMariaDB }
func (f *fakeSession) OriginColumns() bool   { return f.origin }
func (f *fakeSession) ExtraPrivileges(context.Context, config.Tier) ([]string, error) {
	return f.extra, nil
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
	return engine.TableInfo{DB: db, Table: table, Columns: []engine.ColumnDesc{{Name: "id", Type: "int"}}, EstRows: 3}, nil
}
func (f *fakeSession) Columns(_ context.Context, db string) ([]engine.ColumnInfo, error) {
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
}

func (f *fakeIO) Println(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, s)
}

func (f *fakeIO) Ask(ctx context.Context, prompt string, _ time.Duration) (string, bool) {
	f.mu.Lock()
	f.prompts = append(f.prompts, prompt)
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

func (f *fakeIO) AskSecret(context.Context, string) ([]byte, error) {
	return []byte("not-used"), nil
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
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
	if len(rr.Rows) != 1 || len(rr.Columns) != 3 {
		t.Fatalf("run result: %+v", rr)
	}
	if got := rr.Rows[0][1]; got != pii.Redacted {
		t.Errorf("email column not masked by rule: %v", got)
	}
	if got := rr.Rows[0][2]; got == "write to bob@example.org" || !strings.Contains(got.(string), "b***(") {
		t.Errorf("email detector not applied: %v", got)
	}
	if strings.Contains(rr.Text, "alice@example.com") || !strings.Contains(rr.Text, pii.Redacted) {
		t.Errorf("text rendering not masked: %q", rr.Text)
	}
	prompt := strings.Join(h.io.prompts, "\n")
	if !strings.Contains(prompt, "[y/N]") {
		t.Errorf("prompt %q", prompt)
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

func TestDeniedAndTimeout(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"yes please"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeDenied)

	pr = h.plan(t, selectUsers, false)
	h.io.timeout = true
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeTimeout)
	if n := h.sess.runCount(); n != 0 {
		t.Fatalf("denied statements ran %d times", n)
	}
	log := h.auditLog(t)
	if !strings.Contains(log, `"event":"denied"`) || !strings.Contains(log, `"event":"timeout"`) {
		t.Errorf("audit log:\n%s", log)
	}
}

func TestPlanIsOneShotAndExpires(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y", "y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeNoSuchPlan)

	pr = h.plan(t, selectUsers, false)
	h.now = h.now.Add(PlanTTL + time.Second)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeNoSuchPlan)
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: "nope"}), ipc.CodeNoSuchPlan)
	if n := h.sess.runCount(); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
}

// TestPlanExpiringDuringApprovalDoesNotRun: the TTL is checked again once
// the human answers, so an approval that lands after it runs nothing.
func TestPlanExpiringDuringApprovalDoesNotRun(t *testing.T) {
	h := newHarness(t, uatProfile())
	pr := h.plan(t, selectUsers, false)
	h.now = h.now.Add(PlanTTL - time.Second)
	h.io.onAsk = func() { h.now = h.now.Add(2 * time.Second) }
	h.io.answers = []string{"y"}
	resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	wantCode(t, resp, ipc.CodeNoSuchPlan)
	if !strings.Contains(resp.Error.Message, "expired") {
		t.Errorf("message: %q", resp.Error.Message)
	}
	if n := h.sess.runCount(); n != 0 {
		t.Fatalf("expired plan ran %d times", n)
	}
	if log := h.auditLog(t); !strings.Contains(log, `"decision":"expired"`) || strings.Contains(log, `"event":"approved"`) {
		t.Errorf("audit log:\n%s", log)
	}
}

func TestProductionNeedsProfileName(t *testing.T) {
	h := newHarness(t, prodProfile())
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeDenied)

	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"prod"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if p := h.io.prompts[len(h.io.prompts)-1]; !strings.Contains(p, "prod") {
		t.Errorf("production prompt %q does not ask for the profile name", p)
	}
}

func skip(c *ServerConfig) { c.SkipPermissions = true }

func TestSkipPermissions(t *testing.T) {
	t.Run("auto on uat", func(t *testing.T) {
		h := newHarness(t, uatProfile(), skip)
		pr := h.plan(t, selectUsers, false)
		var rr ipc.RunResult
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		if h.io.promptCount() != 0 {
			t.Fatal("skip-permissions prompted on uat")
		}
		if rr.Rows[0][1] != pii.Redacted {
			t.Errorf("auto-approved rows not masked: %v", rr.Rows[0][1])
		}
		if !strings.Contains(h.auditLog(t), `"decision":"auto"`) {
			t.Error("auto-approval not audited")
		}
		if !strings.Contains(h.io.output(), "AUTO-APPROVE") {
			t.Error("no AUTO-APPROVE marker")
		}
	})
	t.Run("prompts on prod", func(t *testing.T) {
		h := newHarness(t, prodProfile(), skip)
		pr := h.plan(t, selectUsers, false)
		h.io.answers = []string{"prod"}
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
		if h.io.promptCount() != 1 {
			t.Fatal("skip-permissions must be ignored on production")
		}
	})
	t.Run("prompts on unmask", func(t *testing.T) {
		h := newHarness(t, uatProfile(), skip)
		pr := h.plan(t, selectUsers, true)
		if !pr.Unmask {
			t.Fatal("unmask flag lost")
		}
		h.io.answers = []string{"y"}
		var rr ipc.RunResult
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		if h.io.promptCount() != 1 {
			t.Fatal("unmask must always prompt")
		}
		if rr.Rows[0][1] != "alice@example.com" {
			t.Errorf("unmasked run masked: %v", rr.Rows[0][1])
		}
		if !strings.Contains(h.io.output(), "UNMASKED") {
			t.Error("approval screen does not say UNMASKED")
		}
		if !strings.Contains(h.auditLog(t), `"unmasked":true`) {
			t.Error("unmask not audited")
		}
	})
}

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
	h := newHarness(t, uatProfile(), skip)
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
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr)
		if got := rr.Rows[0][0]; got != pii.Redacted {
			t.Errorf("origin=%v: aliased PII column not masked: %v", origin, got)
		}
	}
	// A label the analysis did not expect drops the result.
	h := newHarness(t, uatProfile())
	h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{"alice@example.com"}}}
	pr := h.plan(t, "SELECT email AS x FROM users LIMIT 1", false)
	h.io.answers = []string{"y"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeRefused)
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

	// :review accepted → applied and recorded.
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
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
		st.IdleTimeoutInS != int(IdleTimeout/time.Second) || st.SessionEndsInS != int(MaxSession/time.Second) {
		t.Fatalf("status: %+v", st)
	}
	h.ok(t, ipc.MethodLogout, nil, nil)
	if reason, ended := h.s.Ended(); !ended || reason != "logout" {
		t.Fatalf("logout did not end the session: %q %v", reason, ended)
	}
}

func TestIdleAndMaxSession(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.now = h.now.Add(IdleTimeout - time.Second)
	h.s.Tick()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended before the idle timeout")
	}
	h.ok(t, ipc.MethodStatus, nil, nil)
	h.now = h.now.Add(IdleTimeout + time.Second)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("idle: %q %v", reason, ended)
	}
}

func TestRunErrorIsSanitisedAndConnLostMapped(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.sess.runErr = errors.Join(engine.ErrConnLost, errors.New("broken pipe"))
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	wantCode(t, h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}), ipc.CodeConnLost)
}

// TestClientGoneDuringApproval drives Serve over a real socket: a client
// that disconnects while its run waits for approval cancels the prompt, and
// the next client is served.
func TestClientGoneDuringApproval(t *testing.T) {
	h := newHarness(t, uatProfile())
	dir, err := os.MkdirTemp("", "lsc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	pr := h.plan(t, selectUsers, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- h.s.Serve(ctx, ln, nil) }()

	h.io.mu.Lock()
	h.io.block = true
	h.io.blocked = make(chan struct{})
	blocked := h.io.blocked
	h.io.mu.Unlock()

	c1, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(ipc.RunParams{PlanID: pr.PlanID})
	if err := ipc.WriteMsg(c1, ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodQueryRun, Params: params}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("approval prompt not reached")
	}
	c1.Close()

	c2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := ipc.WriteMsg(c2, ipc.Request{JSONRPC: "2.0", ID: 2, Method: ipc.MethodStatus}); err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp ipc.Response
	if err := ipc.ReadMsg(bufio.NewReader(c2), &resp); err != nil {
		t.Fatalf("second client not served: %v", err)
	}
	if resp.Error != nil || resp.ID != 2 {
		t.Fatalf("second client: %+v", resp)
	}
	if h.sess.runCount() != 0 {
		t.Fatal("abandoned run executed")
	}
	if !strings.Contains(h.auditLog(t), `"event":"abandoned"`) {
		t.Error("abandoned approval not audited")
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

// A server error can quote a row value (a failed cast in WHERE): with
// masking on, it must reach neither the client nor the audit log.
func TestRunErrorTextIsRedacted(t *testing.T) {
	// EXTRACTVALUE is outside the function allowlist.
	h := newHarness(t, uatProfile())
	wantCode(t, h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app",
		SQL: "SELECT 1 FROM users WHERE EXTRACTVALUE(1, CONCAT(0x7e, email)) LIMIT 1"}), ipc.CodeRefused)

	// A server message never reaches the client, masked or not; the console
	// and the audit log keep a redacted copy.
	for _, unmask := range []bool{false, true} {
		h.sess.runErr = errors.New(`mariadb: error 1105 (HY000): XPATH syntax error: '~zed.secret@example.com'`)
		pr := h.plan(t, "SELECT id FROM users WHERE id = 1 LIMIT 1", unmask)
		h.io.answers = []string{"y"}
		resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		wantCode(t, resp, ipc.CodeInternal)
		if strings.Contains(resp.Error.Message, "zed.secret") || strings.Contains(resp.Error.Message, "1105") {
			t.Errorf("unmask=%v: client message: %q", unmask, resp.Error.Message)
		}
	}
	if strings.Contains(h.auditLog(t), "zed.secret") || strings.Contains(h.io.output(), "zed.secret") {
		t.Errorf("value in audit log or console:\n%s\n%s", h.auditLog(t), h.io.output())
	}
}
