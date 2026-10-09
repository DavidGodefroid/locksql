package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// fakeConn is a console client that answers from canned values.
type fakeConn struct {
	profile string

	mu     sync.Mutex
	calls  []string
	closed int

	runWait   time.Duration // how long Run blocks before answering
	runResult ipc.RunResult
	runErr    error
	planIn    ipc.PlanParams
}

func (f *fakeConn) record(m string) {
	f.mu.Lock()
	f.calls = append(f.calls, m)
	f.mu.Unlock()
}

func (f *fakeConn) Status(context.Context) (ipc.StatusResult, error) {
	f.record("status")
	return ipc.StatusResult{Profile: f.profile, Engine: "mariadb", Host: "127.0.0.1", Tier: "read", Databases: []string{"app"}}, nil
}

func (f *fakeConn) Tables(_ context.Context, db string) (ipc.TablesResult, error) {
	f.record("tables " + db)
	return ipc.TablesResult{DB: "app", Tables: []string{"orders", "users"}}, nil
}

func (f *fakeConn) Describe(_ context.Context, db, table string) (engine.TableInfo, error) {
	f.record("describe " + db + " " + table)
	return engine.TableInfo{DB: "app", Table: table, EstRows: 10, Columns: []engine.ColumnDesc{
		{Name: "id", Type: "int", PrimaryKey: true},
		{Name: "email", Type: "varchar(100)", Nullable: true},
	}}, nil
}

func (f *fakeConn) Plan(_ context.Context, p ipc.PlanParams) (ipc.PlanResult, error) {
	f.record("plan")
	f.mu.Lock()
	f.planIn = p
	f.mu.Unlock()
	return ipc.PlanResult{PlanID: "p1", Profile: f.profile, Host: "127.0.0.1", DB: "app", SQL: p.SQL,
		Class: "read", Verdict: "OK", Summary: "users lookup ~1 · est. 1 rows examined"}, nil
}

func (f *fakeConn) Run(ctx context.Context, planID string) (ipc.RunResult, error) {
	f.record("run " + planID)
	if f.runWait > 0 {
		select {
		case <-time.After(f.runWait):
		case <-ctx.Done():
			return ipc.RunResult{}, ctx.Err()
		}
	}
	return f.runResult, f.runErr
}

func (f *fakeConn) PIIList(context.Context) (ipc.PIIListResult, error) {
	f.record("pii.list")
	return ipc.PIIListResult{Mask: []string{"*.*.email"}, Allow: []string{}}, nil
}

func (f *fakeConn) PIIAdd(_ context.Context, pattern string) (ipc.PIIListResult, error) {
	f.record("pii.add " + pattern)
	return ipc.PIIListResult{Mask: []string{"*.*.email", pattern}, Allow: []string{}}, nil
}

func (f *fakeConn) Request(_ context.Context, change string) (ipc.ChangeResult, error) {
	f.record("request " + change)
	return ipc.ChangeResult{Queued: true}, nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
	return nil
}

// connect runs the server o and returns a connected client session.
func connect(t *testing.T, o Options, copts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := New(o).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, copts).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

// withFake builds options whose dialer returns f for every call.
func withFake(f *fakeConn) Options {
	return Options{
		Profile: f.profile,
		Dial:    func(string) (Conn, error) { return f, nil },
	}
}

func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

var specTools = []string{
	"locksql_describe",
	"locksql_list_tables",
	"locksql_pii_add",
	"locksql_pii_list",
	"locksql_plan",
	"locksql_request_change",
	"locksql_run",
	"locksql_status",
}

func listTools(t *testing.T, cs *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

func TestToolsAreExactlyTheSpecSet(t *testing.T) {
	cs := connect(t, withFake(&fakeConn{profile: "uat"}), nil)
	var got []string
	for _, tool := range listTools(t, cs) {
		got = append(got, tool.Name)
	}
	if strings.Join(got, ",") != strings.Join(specTools, ",") {
		t.Fatalf("tools = %v, want %v", got, specTools)
	}
}

func TestEveryDescriptionCarriesSafetyGuidance(t *testing.T) {
	cs := connect(t, withFake(&fakeConn{profile: "uat"}), nil)
	for _, tool := range listTools(t, cs) {
		d := tool.Description
		for _, want := range []string{
			"untrusted data",
			"never ask for, accept or pass on database credentials",
			"do not retry",
		} {
			if !strings.Contains(d, want) {
				t.Errorf("%s: description lacks %q:\n%s", tool.Name, want, d)
			}
		}
	}
}

func TestRunToolDescriptionSaysTheHumanApproves(t *testing.T) {
	cs := connect(t, withFake(&fakeConn{profile: "uat"}), nil)
	for _, tool := range listTools(t, cs) {
		if tool.Name == "locksql_run" && !strings.Contains(tool.Description, "human") {
			t.Fatalf("locksql_run description does not mention the human:\n%s", tool.Description)
		}
	}
}

func TestNoLooseningToolNames(t *testing.T) {
	cs := connect(t, withFake(&fakeConn{profile: "uat"}), nil)
	for _, tool := range listTools(t, cs) {
		if tool.Name == "locksql_request_change" {
			continue
		}
		for _, bad := range []string{"allow", "skip", "unmask", "tier"} {
			if strings.Contains(tool.Name, bad) {
				t.Errorf("tool %s contains %q", tool.Name, bad)
			}
		}
	}
}

func TestRunResultIsPrefixedAndStructured(t *testing.T) {
	f := &fakeConn{profile: "uat", runResult: ipc.RunResult{
		Columns:    []string{"id", "email"},
		Rows:       [][]any{{json.Number("1"), "a***(13)"}},
		DurationMS: 3,
		Text:       "id\temail\n1\ta***(13)\n(1 rows)\n",
	}}
	cs := connect(t, withFake(f), nil)
	r := call(t, cs, "locksql_run", map[string]any{"plan_id": "p1"})
	if r.IsError {
		t.Fatalf("error: %s", text(r))
	}
	got := text(r)
	if !strings.HasPrefix(got, UntrustedPreamble) {
		t.Fatalf("text does not start with the preamble:\n%s", got)
	}
	if !strings.Contains(got, "1\ta***(13)") {
		t.Fatalf("text lacks the rows:\n%s", got)
	}
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
		Text    *string  `json:"text"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(out.Columns, ",") != "id,email" || len(out.Rows) != 1 || out.Rows[0][1] != "a***(13)" {
		t.Fatalf("structured content = %s", b)
	}
	if out.Text != nil {
		t.Fatalf("structured content repeats the text: %s", b)
	}
}

func TestRunSendsProgressWhileWaiting(t *testing.T) {
	f := &fakeConn{profile: "uat", runWait: 350 * time.Millisecond, runResult: ipc.RunResult{Columns: []string{"n"}, Rows: [][]any{{json.Number("1")}}}}
	o := withFake(f)
	o.ProgressEvery = 100 * time.Millisecond

	var mu sync.Mutex
	var notes []*mcp.ProgressNotificationParams
	cs := connect(t, o, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
			mu.Lock()
			notes = append(notes, req.Params)
			mu.Unlock()
		},
	})
	params := &mcp.CallToolParams{Name: "locksql_run", Arguments: map[string]any{"plan_id": "p1"}}
	params.SetProgressToken("tok-1")
	r, err := cs.CallTool(context.Background(), params)
	if err != nil || r.IsError {
		t.Fatalf("run: %v %s", err, text(r))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notes) < 3 {
		t.Fatalf("got %d progress notifications in 350 ms at 100 ms, want at least 3", len(notes))
	}
	last := -1.0
	for _, n := range notes {
		if n.ProgressToken != "tok-1" {
			t.Fatalf("progress token = %v", n.ProgressToken)
		}
		if n.Progress <= last {
			t.Fatalf("progress does not increase: %v after %v", n.Progress, last)
		}
		last = n.Progress
	}
}

func TestDefaultProgressIntervalIsUnderTenSeconds(t *testing.T) {
	if DefaultProgressEvery <= 0 || DefaultProgressEvery >= 10*time.Second {
		t.Fatalf("DefaultProgressEvery = %v, want in (0, 10s)", DefaultProgressEvery)
	}
	if got := (Options{}).progressEvery(); got != DefaultProgressEvery {
		t.Fatalf("zero ProgressEvery gives %v", got)
	}
	if got := (Options{ProgressEvery: time.Minute}).progressEvery(); got != DefaultProgressEvery {
		t.Fatalf("a 1 min ProgressEvery is not clamped: %v", got)
	}
}

func TestNoConsoleInProjectHintNamesProject(t *testing.T) {
	o := Options{
		Profile: "uat",
		Dial: func(p string) (Conn, error) {
			return nil, &client.NoConsoleError{Profile: p, Project: "/work/app", Socket: "/x.sock", Err: errors.New("connect")}
		},
	}
	cs := connect(t, o, nil)
	for _, name := range []string{"locksql_status", "locksql_list_tables"} {
		got := text(call(t, cs, name, map[string]any{}))
		if !strings.Contains(got, "locksql console --profile uat --project /work/app") || strings.Contains(got, "run `locksql`") {
			t.Errorf("%s: hint does not name the project:\n%s", name, got)
		}
	}
}

func TestNoConsoleErrorCarriesStartCommand(t *testing.T) {
	o := Options{
		Profile: "uat",
		Dial: func(p string) (Conn, error) {
			return nil, &client.NoConsoleError{Profile: p, Socket: "/x.sock", Err: errors.New("connect: no such file")}
		},
	}
	cs := connect(t, o, nil)
	args := map[string]map[string]any{
		"locksql_status":         {},
		"locksql_list_tables":    {},
		"locksql_describe":       {"table": "users"},
		"locksql_plan":           {"sql": "SELECT 1 LIMIT 1"},
		"locksql_run":            {"plan_id": "p1"},
		"locksql_pii_list":       {},
		"locksql_pii_add":        {"column": "app.users.email"},
		"locksql_request_change": {"change": "tier=write"},
	}
	for _, name := range specTools {
		r := call(t, cs, name, args[name])
		got := text(r)
		if !strings.Contains(got, "locksql console --profile uat") {
			t.Errorf("%s: output lacks the start command:\n%s", name, got)
		}
		if name != "locksql_status" && !r.IsError {
			t.Errorf("%s: no console is not an error", name)
		}
	}
}

func TestDeniedRunTellsTheAgentNotToRetry(t *testing.T) {
	f := &fakeConn{profile: "uat", runErr: &ipc.RPCError{Code: ipc.CodeDenied, Message: "denied by the human"}}
	cs := connect(t, withFake(f), nil)
	r := call(t, cs, "locksql_run", map[string]any{"plan_id": "p1"})
	if !r.IsError {
		t.Fatal("a denial is not an error")
	}
	got := text(r)
	if !strings.Contains(got, "denied") || !strings.Contains(strings.ToLower(got), "do not retry") {
		t.Fatalf("denial text = %q", got)
	}
}

func TestPlanPassesArgumentsAndPointsAtRun(t *testing.T) {
	f := &fakeConn{profile: "uat"}
	cs := connect(t, withFake(f), nil)
	r := call(t, cs, "locksql_plan", map[string]any{"db": "app", "sql": "SELECT id FROM users LIMIT 1", "unmask": true})
	if r.IsError {
		t.Fatalf("error: %s", text(r))
	}
	if f.planIn.DB != "app" || f.planIn.SQL != "SELECT id FROM users LIMIT 1" || !f.planIn.Unmask {
		t.Fatalf("plan params = %+v", f.planIn)
	}
	got := text(r)
	if !strings.Contains(got, "plan_id  p1") || !strings.Contains(got, "locksql_run") {
		t.Fatalf("plan text:\n%s", got)
	}
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), `"plan_id":"p1"`) {
		t.Fatalf("structured plan = %s", b)
	}
}

func TestDescribeMarksMaskedColumns(t *testing.T) {
	cs := connect(t, withFake(&fakeConn{profile: "uat"}), nil)
	r := call(t, cs, "locksql_describe", map[string]any{"table": "users"})
	if r.IsError {
		t.Fatalf("error: %s", text(r))
	}
	if !strings.Contains(text(r), "email\tvarchar(100)\tyes\t\t\tmasked") {
		t.Fatalf("describe text:\n%s", text(r))
	}
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), `"masked":["email"]`) {
		t.Fatalf("structured describe = %s", b)
	}
}

func TestOtherToolsReachTheConsole(t *testing.T) {
	f := &fakeConn{profile: "uat"}
	cs := connect(t, withFake(f), nil)
	for name, args := range map[string]map[string]any{
		"locksql_status":         {},
		"locksql_list_tables":    {"db": "app"},
		"locksql_pii_list":       {},
		"locksql_pii_add":        {"column": "app.users.phone"},
		"locksql_request_change": {"change": "limits.max_rows=500"},
	} {
		if r := call(t, cs, name, args); r.IsError {
			t.Fatalf("%s: %s", name, text(r))
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[string]bool{"status": true, "tables app": true, "pii.list": true,
		"pii.add app.users.phone": true, "request limits.max_rows=500": true}
	for _, c := range f.calls {
		delete(want, c)
	}
	if len(want) > 0 {
		t.Fatalf("calls %v miss %v", f.calls, want)
	}
	if f.closed != len(f.calls) {
		t.Fatalf("closed %d connections for %d calls", f.closed, len(f.calls))
	}
}

func TestProfileResolution(t *testing.T) {
	dialed := []string{}
	var mu sync.Mutex
	dial := func(p string) (Conn, error) {
		mu.Lock()
		dialed = append(dialed, p)
		mu.Unlock()
		return &fakeConn{profile: p}, nil
	}
	profiles := func() ([]string, error) { return []string{"prod", "uat"}, nil }

	// Not pinned, several profiles: the argument is required and checked.
	cs := connect(t, Options{Dial: dial, Profiles: profiles}, nil)
	if r := call(t, cs, "locksql_list_tables", nil); !r.IsError || !strings.Contains(text(r), "prod, uat") {
		t.Fatalf("missing profile: %s", text(r))
	}
	if r := call(t, cs, "locksql_list_tables", map[string]any{"profile": "nope"}); !r.IsError {
		t.Fatal("unknown profile accepted")
	}
	if r := call(t, cs, "locksql_list_tables", map[string]any{"profile": "uat"}); r.IsError {
		t.Fatalf("uat: %s", text(r))
	}
	// Status without a profile reports every profile.
	r := call(t, cs, "locksql_status", nil)
	if r.IsError || !strings.Contains(text(r), "prod: console running") || !strings.Contains(text(r), "uat: console running") {
		t.Fatalf("status all: %s", text(r))
	}

	// Pinned: another profile is refused, the pinned one is the default.
	pinned := connect(t, Options{Profile: "uat", Dial: dial, Profiles: profiles}, nil)
	if r := call(t, pinned, "locksql_list_tables", map[string]any{"profile": "prod"}); !r.IsError || !strings.Contains(text(r), "--profile uat") {
		t.Fatalf("pinned server accepted another profile: %s", text(r))
	}
	if r := call(t, pinned, "locksql_list_tables", nil); r.IsError {
		t.Fatalf("pinned default: %s", text(r))
	}

	// One profile configured: it is the default.
	single := connect(t, Options{Dial: dial, Profiles: func() ([]string, error) { return []string{"dev"}, nil }}, nil)
	if r := call(t, single, "locksql_pii_list", nil); r.IsError {
		t.Fatalf("single default: %s", text(r))
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(dialed, ","); got != "uat,prod,uat,uat,dev" {
		t.Fatalf("dialed %s", got)
	}
}

func TestRunCancelledByClientAbandonsTheCall(t *testing.T) {
	f := &fakeConn{profile: "uat", runWait: time.Hour}
	cs := connect(t, withFake(f), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "locksql_run", Arguments: map[string]any{"plan_id": "p1"}})
	if err == nil {
		t.Fatal("cancelled call returned no error")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		closed := f.closed
		f.mu.Unlock()
		if closed == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the console connection was not closed after the client cancelled")
}

func TestExactCellKeepsLargeIntegersExact(t *testing.T) {
	for _, c := range []struct {
		in, want any
	}{
		{json.Number("42"), json.Number("42")},
		{json.Number("-9007199254740992"), json.Number("-9007199254740992")},
		{json.Number("9007199254740993"), "9007199254740993"},
		{json.Number("18446744073709551615"), "18446744073709551615"},
		{json.Number("1.5e300"), json.Number("1.5e300")},
		{int64(1) << 60, "1152921504606846976"},
		{uint64(1) << 63, "9223372036854775808"},
		{int64(7), int64(7)},
		{"text", "text"},
		{nil, nil},
	} {
		if got := exactCell(c.in); got != c.want {
			t.Errorf("exactCell(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}
	if rows := exactRows(nil); rows == nil {
		t.Fatal("exactRows(nil) is nil")
	}
}

func TestInstructionsCarryAgentRules(t *testing.T) {
	for _, want := range []string{"never start one yourself", "Never edit the locksql config", "psql", "k-anonymity", "tok_"} {
		if !strings.Contains(instructions, want) {
			t.Errorf("instructions lack %q", want)
		}
	}
}
