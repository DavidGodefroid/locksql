package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// fakeSession is a scripted engine.Session.
type fakeSession struct{}

func (fakeSession) ServerVersion() string { return "11.4.0-MariaDB" }
func (fakeSession) Flavor() engine.Flavor { return engine.FlavorMariaDB }
func (fakeSession) OriginColumns() bool   { return true }
func (fakeSession) ExtraPrivileges(context.Context, config.Tier) ([]string, error) {
	return nil, nil
}
func (fakeSession) Databases(context.Context) ([]string, error) { return []string{"app"}, nil }
func (fakeSession) Tables(context.Context, string) ([]string, error) {
	return []string{"orders", "users"}, nil
}
func (fakeSession) Describe(_ context.Context, db, table string) (engine.TableInfo, error) {
	return engine.TableInfo{DB: db, Table: table, EstRows: 3,
		Columns: []engine.ColumnDesc{
			{Name: "id", Type: "int", PrimaryKey: true},
			{Name: "email", Type: "varchar(100)", Nullable: true},
		},
		Indexes: []engine.IndexDesc{{Name: "PRIMARY", Columns: []string{"id"}, Unique: true, Primary: true}},
	}, nil
}
func (fakeSession) Columns(_ context.Context, db string) ([]engine.ColumnInfo, error) {
	return []engine.ColumnInfo{
		{DB: db, Table: "users", Column: "id", Type: "int"},
		{DB: db, Table: "users", Column: "email", Type: "varchar(100)"},
	}, nil
}
func (fakeSession) Explain(context.Context, string, string) (engine.Plan, error) {
	return engine.Plan{Root: engine.PlanNode{Detail: "QUERY", EstRows: -1, Children: []engine.PlanNode{
		{Table: "users", Access: engine.AccessLookup, EstRows: 1},
	}}}, nil
}
func (fakeSession) Run(context.Context, string, sqlclass.Statement, int) (engine.Result, error) {
	return engine.Result{
		Columns: []engine.ResultColumn{
			{Label: "id", OriginDB: "app", OriginTable: "users", OriginColumn: "id"},
			{Label: "email", OriginDB: "app", OriginTable: "users", OriginColumn: "email"},
		},
		Rows: [][]any{{int64(1), "alice@example.com"}},
	}, nil
}
func (fakeSession) Ping(context.Context) error { return nil }
func (fakeSession) Close() error               { return nil }

// scriptIO answers approval prompts from a queue, after an optional delay.
type scriptIO struct {
	mu      sync.Mutex
	answers []string
	delay   time.Duration
	out     []string
}

func (f *scriptIO) Println(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, s)
}

func (f *scriptIO) Ask(ctx context.Context, _ string, _ time.Duration) (string, bool) {
	f.mu.Lock()
	delay := f.delay
	var a string
	ok := len(f.answers) > 0
	if ok {
		a, f.answers = f.answers[0], f.answers[1:]
	}
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", false
	case <-time.After(delay):
	}
	return a, ok
}

func (f *scriptIO) AskSecret(context.Context, string) ([]byte, error) { return nil, nil }

func (f *scriptIO) answer(a ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers = append(f.answers, a...)
}

const uatConfig = `
[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
database = "app"
`

const twoProfiles = uatConfig + `
[profiles.prod]
engine = "mariadb"
host = "db.example.com"
user = "alice"
production = true
`

// project creates a project dir with a config and points the socket dir
// at a short temp dir through LOCKSQL_RUNTIME_DIR.
func project(t *testing.T, cfg string) string {
	t.Helper()
	rd, err := os.MkdirTemp("/tmp", "lscmd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rd) })
	t.Setenv("LOCKSQL_RUNTIME_DIR", rd)
	// Keep the user config of the machine out of the test.
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	t.Setenv("AppData", home)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".locksql", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// startConsole serves profile from dir's config with an in-process console
// server and returns its scripted IO.
func startConsole(t *testing.T, dir, profile string) *scriptIO {
	t.Helper()
	cfg, err := config.LoadFrom(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.Profiles[profile]
	if !ok {
		t.Fatalf("no profile %s", profile)
	}
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	sio := &scriptIO{}
	s, err := console.NewServer(console.ServerConfig{
		Policy:    config.NewPolicy(p, []string{"app.users.email"}, nil),
		RulesPath: filepath.Join(dir, pii.RulesFile), StateDir: state, ApprovedKey: config.ApprovedKey(dir, profile),
		Session: fakeSession{}, DBUser: p.User, Databases: []string{"app"},
		Audit: log, IO: sio, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	path, err := ipc.SocketPath(config.ProjectKey(dir), profile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln, nil)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sio
}

type outcome struct {
	code           int
	stdout, stderr string
}

func cli(t *testing.T, dir, stdin string, args ...string) outcome {
	t.Helper()
	var out, errb bytes.Buffer
	code := runEnv(env{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, cwd: dir}, args)
	return outcome{code, out.String(), errb.String()}
}

func (o outcome) want(t *testing.T, code int, contains ...string) {
	t.Helper()
	if o.code != code {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", o.code, code, o.stdout, o.stderr)
	}
	all := o.stdout + o.stderr
	for _, c := range contains {
		if !strings.Contains(all, c) {
			t.Fatalf("output lacks %q\nstdout: %s\nstderr: %s", c, o.stdout, o.stderr)
		}
	}
}

func decodeJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("invalid JSON %q: %v", s, err)
	}
}

func TestStatusTextAndJSON(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	o := cli(t, dir, "", "status", "--profile", "uat")
	o.want(t, exitOK, "profile", "uat", "engine", "mariadb", "host", "db.uat.example.com",
		"tier", "read", "production", "no", "databases", "app", "max_rows 200")

	o = cli(t, dir, "", "status", "--profile", "uat", "--json")
	o.want(t, exitOK)
	var st ipc.StatusResult
	decodeJSON(t, o.stdout, &st)
	if st.Profile != "uat" || st.Tier != "read" || len(st.Databases) != 1 {
		t.Fatalf("status = %+v", st)
	}
}

func TestProfileDefaultsToTheOnlyProfile(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	cli(t, dir, "", "tables").want(t, exitOK, "orders\nusers\n")
}

func TestProfileRequiredWhenSeveral(t *testing.T) {
	dir := project(t, twoProfiles)
	o := cli(t, dir, "", "tables", "--db", "app")
	o.want(t, exitUsage, "--profile", "prod", "uat")
}

func TestStatusWithoutProfileListsEveryProfile(t *testing.T) {
	dir := project(t, twoProfiles)
	startConsole(t, dir, "uat")
	o := cli(t, dir, "", "status")
	o.want(t, exitOK, "uat", "console running", "prod", "no console", "locksql console --profile prod")

	o = cli(t, dir, "", "status", "--json")
	o.want(t, exitOK)
	var list []struct {
		Profile string            `json:"profile"`
		Running bool              `json:"running"`
		Status  *ipc.StatusResult `json:"status"`
		Start   string            `json:"start"`
	}
	decodeJSON(t, o.stdout, &list)
	if len(list) != 2 || list[0].Profile != "prod" || list[0].Running || list[0].Start != "locksql console --profile prod --project "+dir ||
		list[1].Profile != "uat" || !list[1].Running || list[1].Status == nil {
		t.Fatalf("status list = %+v", list)
	}
}

func TestTablesAndDescribe(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	cli(t, dir, "", "tables", "--profile", "uat", "--db", "app").want(t, exitOK, "orders\nusers\n")

	o := cli(t, dir, "", "tables", "--profile", "uat", "--db", "app", "--json")
	o.want(t, exitOK)
	var tr ipc.TablesResult
	decodeJSON(t, o.stdout, &tr)
	if tr.DB != "app" || len(tr.Tables) != 2 {
		t.Fatalf("tables = %+v", tr)
	}

	o = cli(t, dir, "", "describe", "--profile", "uat", "--db", "app", "users")
	o.want(t, exitOK, "app.users", "~3 rows", "column\ttype\tnull\tkey\tdefault\tpii",
		"id\tint\tno\tPK\t\t", "email\tvarchar(100)\tyes\t\t\tmasked", "PRIMARY (id) primary")

	o = cli(t, dir, "", "describe", "--profile", "uat", "--db", "app", "--json", "users")
	o.want(t, exitOK)
	var d struct {
		engine.TableInfo
		Masked []string `json:"masked"`
	}
	decodeJSON(t, o.stdout, &d)
	if d.Table != "users" || len(d.Columns) != 2 || len(d.Masked) != 1 || d.Masked[0] != "email" {
		t.Fatalf("describe = %+v", d)
	}
}

func TestPlanAndRun(t *testing.T) {
	dir := project(t, uatConfig)
	sio := startConsole(t, dir, "uat")

	o := cli(t, dir, "", "plan", "--profile", "uat", "--db", "app", "SELECT id, email FROM users WHERE id = 1 LIMIT 5")
	o.want(t, exitOK, "plan_id", "class    READ", "verdict  OK", "users lookup", "locksql run --profile uat ")

	o = cli(t, dir, "", "plan", "--profile", "uat", "--db", "app", "--json", "SELECT id, email FROM users WHERE id = 1 LIMIT 5")
	o.want(t, exitOK)
	var pl ipc.PlanResult
	decodeJSON(t, o.stdout, &pl)
	if pl.PlanID == "" || pl.Class != "read" || pl.Verdict != "OK" {
		t.Fatalf("plan = %+v", pl)
	}

	sio.answer("y")
	o = cli(t, dir, "", "run", "--profile", "uat", pl.PlanID)
	o.want(t, exitOK, "id\temail\n", "1\t<redacted:r1.1.2>")
	if strings.Contains(o.stdout, "alice@example.com") {
		t.Fatalf("unmasked output: %s", o.stdout)
	}

	// Plans are one-shot.
	cli(t, dir, "", "run", "--profile", "uat", pl.PlanID).want(t, exitFail, "no such plan")

	// JSON run, with the flag after the plan id.
	o = cli(t, dir, "", "plan", "--profile", "uat", "--json", "SELECT id, email FROM users WHERE id = 1 LIMIT 5")
	decodeJSON(t, o.stdout, &pl)
	sio.answer("y")
	o = cli(t, dir, "", "run", "--profile", "uat", pl.PlanID, "--json")
	o.want(t, exitOK)
	var rr ipc.RunResult
	decodeJSON(t, o.stdout, &rr)
	if len(rr.Columns) != 2 || len(rr.Rows) != 1 || rr.Text != "" || rr.Rows[0][1] != "<redacted:r2.1.2>" {
		t.Fatalf("run = %+v", rr)
	}
}

func TestPlanReadsSQLFromStdin(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	o := cli(t, dir, "SELECT id FROM users WHERE id = 1 LIMIT 1\n", "plan", "--profile", "uat", "--db", "app", "--json", "-")
	o.want(t, exitOK)
	var pl ipc.PlanResult
	decodeJSON(t, o.stdout, &pl)
	if pl.SQL != "SELECT id FROM users WHERE id = 1 LIMIT 1" {
		t.Fatalf("sql = %q", pl.SQL)
	}
	cli(t, dir, "   \n", "plan", "--profile", "uat", "-").want(t, exitUsage, "no SQL")
}

func TestPlanRefusedAndRunDenied(t *testing.T) {
	dir := project(t, uatConfig)
	sio := startConsole(t, dir, "uat")
	o := cli(t, dir, "", "plan", "--profile", "uat", "--db", "app", "DELETE FROM users")
	o.want(t, exitFail, "refused")

	o = cli(t, dir, "", "plan", "--profile", "uat", "--db", "app", "--json", "DELETE FROM users")
	o.want(t, exitFail)
	var e struct {
		Error struct {
			Kind    string `json:"kind"`
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decodeJSON(t, o.stdout, &e)
	if e.Error.Kind != "refused" || e.Error.Code != ipc.CodeRefused || e.Error.Message == "" {
		t.Fatalf("error = %+v", e)
	}

	o = cli(t, dir, "", "plan", "--profile", "uat", "--json", "SELECT id, email FROM users WHERE id = 1 LIMIT 1")
	var pl ipc.PlanResult
	decodeJSON(t, o.stdout, &pl)
	sio.answer("n")
	cli(t, dir, "", "run", "--profile", "uat", pl.PlanID).want(t, exitFail, "denied")
}

func TestRunWaitsForTheHuman(t *testing.T) {
	dir := project(t, uatConfig)
	sio := startConsole(t, dir, "uat")
	o := cli(t, dir, "", "plan", "--profile", "uat", "--json", "SELECT id, email FROM users WHERE id = 1 LIMIT 1")
	var pl ipc.PlanResult
	decodeJSON(t, o.stdout, &pl)
	sio.mu.Lock()
	sio.delay = 300 * time.Millisecond
	sio.mu.Unlock()
	sio.answer("y")
	cli(t, dir, "", "run", "--profile", "uat", pl.PlanID).want(t, exitOK, "id\temail")
}

func TestPIIAndRequest(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	cli(t, dir, "", "pii", "list", "--profile", "uat").want(t, exitOK, "mask\tapp.users.email")
	cli(t, dir, "", "pii", "add", "--profile", "uat", "app.users.note").want(t, exitOK, "mask rule added: app.users.note")
	o := cli(t, dir, "", "pii", "list", "--profile", "uat", "--json")
	o.want(t, exitOK)
	var pr ipc.PIIListResult
	decodeJSON(t, o.stdout, &pr)
	if len(pr.Mask) != 2 {
		t.Fatalf("pii = %+v", pr)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".locksql", "pii.toml")); err != nil || !strings.Contains(string(b), "app.users.note") {
		t.Fatalf("pii.toml = %q, %v", b, err)
	}
	cli(t, dir, "", "pii", "add", "--profile", "uat", "not a pattern").want(t, exitFail)

	cli(t, dir, "", "request", "--profile", "uat", "tier=write").want(t, exitOK, "queued", "tier=write", ":review")
	o = cli(t, dir, "", "request", "--profile", "uat", "--json", "limits.max_rows=500")
	o.want(t, exitOK)
	var cr ipc.ChangeResult
	decodeJSON(t, o.stdout, &cr)
	if !cr.Queued {
		t.Fatalf("change = %+v", cr)
	}
	// A request never changes the policy.
	o = cli(t, dir, "", "status", "--profile", "uat", "--json")
	var st ipc.StatusResult
	decodeJSON(t, o.stdout, &st)
	if st.Tier != "read" || st.Limits.MaxRows != 200 {
		t.Fatalf("status after request = %+v", st)
	}
}

func TestLogoutEndsTheConsole(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	cli(t, dir, "", "logout", "--profile", "uat").want(t, exitOK, "ended")
	deadline := time.Now().Add(5 * time.Second)
	for {
		o := cli(t, dir, "", "status", "--profile", "uat")
		if o.code == exitNoConsole {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("console still answers after logout: %+v", o)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLogoutJSON(t *testing.T) {
	dir := project(t, uatConfig)
	startConsole(t, dir, "uat")
	o := cli(t, dir, "", "logout", "--profile", "uat", "--json")
	o.want(t, exitOK)
	var r map[string]bool
	decodeJSON(t, o.stdout, &r)
	if !r["ok"] {
		t.Fatalf("logout = %v", r)
	}
}

func TestNoConsoleExitTwoWithHint(t *testing.T) {
	dir := project(t, uatConfig)
	for _, args := range [][]string{
		{"status", "--profile", "uat"},
		{"tables", "--profile", "uat", "--db", "app"},
		{"describe", "--profile", "uat", "--db", "app", "users"},
		{"plan", "--profile", "uat", "--db", "app", "SELECT 1 LIMIT 1"},
		{"run", "--profile", "uat", "abc"},
		{"pii", "list", "--profile", "uat"},
		{"pii", "add", "--profile", "uat", "app.users.email"},
		{"request", "--profile", "uat", "tier=write"},
		{"logout", "--profile", "uat"},
	} {
		o := cli(t, dir, "", args...)
		if o.code != exitNoConsole {
			t.Fatalf("%v: exit %d, want 2 (stderr %q)", args, o.code, o.stderr)
		}
		// dir is a project: the hint names it.
		if !strings.Contains(o.stderr, "locksql console --profile uat --project "+dir+"\n") {
			t.Fatalf("%v: stderr lacks the start command: %q", args, o.stderr)
		}
	}
	o := cli(t, dir, "", "status", "--profile", "uat", "--json")
	o.want(t, exitNoConsole)
	var e struct {
		Error struct {
			Kind  string `json:"kind"`
			Start string `json:"start"`
		} `json:"error"`
	}
	decodeJSON(t, o.stdout, &e)
	if e.Error.Kind != "no_console" || e.Error.Start != "locksql console --profile uat --project "+dir {
		t.Fatalf("error = %+v", e)
	}
}

func TestClientUsageErrors(t *testing.T) {
	dir := project(t, uatConfig)
	for _, args := range [][]string{
		{"describe", "--profile", "uat"},
		{"describe", "--profile", "uat", "a", "b"},
		{"plan", "--profile", "uat"},
		{"plan", "--profile", "uat", "SELECT 1", "extra"},
		{"run", "--profile", "uat"},
		{"pii"},
		{"pii", "bogus", "--profile", "uat"},
		{"pii", "add", "--profile", "uat"},
		{"pii", "list", "--profile", "uat", "extra"},
		{"request", "--profile", "uat"},
		{"logout", "--profile", "uat", "extra"},
		{"tables", "--bogus"},
		{"status", "--profile", "nosuch"},
		{"tables", "--profile", "../x"},
	} {
		if o := cli(t, dir, "", args...); o.code != exitUsage {
			t.Fatalf("%v: exit %d, want 3 (stderr %q)", args, o.code, o.stderr)
		}
	}
}
