//go:build integration && linux

package integration

import (
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	_ "github.com/DavidGodefroid/locksql/internal/engine/sqlite"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The auto mode per profile end to end (locksql#185), with the real
// binary: two consoles, each decided on a fake lockhub, and a decider that
// plays `lox run` in auto mode (an approval by an auto rule for every
// ticket the lock leaves to auto, a question to the human for every
// never-auto one). Profile local is full-auto: its read, write and schema
// change all run without a question. Profile prod keeps the defaults:
// its read runs without a question, its write is asked; an auto rule's
// approval of that write is refused by the lock and changes nothing, the
// human's approval runs it. `locksql profile rules --json` gives lox run
// the rules it shows at start, and the audit names the rule in force and
// what decided.
//
//	go test -tags integration -run TestAutoRulesEndToEnd ./test/integration
func TestAutoRulesEndToEnd(t *testing.T) {
	bin, err := buildLocksql()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"local.db", "prod.db"} {
		db, err := sql.Open("sqlite", filepath.Join(project, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)", "INSERT INTO items VALUES (1, 'a'), (2, 'b')"} {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		db.Close()
	}
	conf := `[profiles.local]
engine = "sqlite"
path = "local.db"
tier = "ddl"
auto = "full-auto"

[profiles.prod]
engine = "sqlite"
path = "prod.db"
tier = "write"
production = true
`
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Each console has a state directory of its own: each is decided on
	// a fake hub of its own, whose decisions start again at 1.
	envOf := func(profile string) []string {
		return []string{
			"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm",
			"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
			"XDG_STATE_HOME=" + filepath.Join(home, "state-"+profile),
			"XDG_RUNTIME_DIR=" + runDir,
		}
	}

	// What lox run shows at start.
	cmd := exec.Command(bin, "profile", "rules", "--json")
	cmd.Dir, cmd.Env = project, envOf("rules")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("profile rules: %v\n%s", err, out)
	}
	var rules struct {
		Lock     string `json:"lock"`
		Profiles []struct {
			Profile    string            `json:"profile"`
			Production bool              `json:"production"`
			Preset     string            `json:"preset"`
			Rules      map[string]string `json:"rules"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(out, &rules); err != nil || rules.Lock != "locksql" || len(rules.Profiles) != 2 {
		t.Fatalf("profile rules: %v\n%s", err, out)
	}
	if l := rules.Profiles[0]; l.Profile != "local" || l.Preset != "full-auto" || l.Rules["write"] != "auto" || l.Rules["ddl"] != "auto" {
		t.Fatalf("local rules: %+v", l)
	}
	if p := rules.Profiles[1]; p.Profile != "prod" || !p.Production || p.Rules["read"] != "auto" || p.Rules["write"] != "ask" || p.Rules["connect"] != "ask" {
		t.Fatalf("prod rules: %+v", p)
	}

	start := func(t *testing.T, profile string, answers ...string) (*consoleProc, *rpc) {
		t.Helper()
		c := startConsole(t, project, envOf(profile), "--profile", profile)
		for _, a := range answers {
			parts := strings.SplitN(a, "|", 2)
			c.expect(parts[0])
			c.send(parts[1] + "\n")
		}
		seen := c.expect("Listening…")
		if !strings.Contains(c.output(), "auto mode (lox run): ") {
			t.Errorf("the console does not show the auto rules in force:\n%s", c.output())
		}
		m := socketLine.FindStringSubmatch(seen)
		if m == nil {
			t.Fatalf("no socket path in %q", seen)
		}
		cl := dialConsole(t, m[1])
		var hr ipc.HelloResult
		if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
			t.Fatal(e)
		}
		return c, cl
	}
	// submit plans sql and runs the plan: the ticket the lock pushed.
	submit := func(t *testing.T, cl *rpc, sql string) string {
		t.Helper()
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "main", SQL: sql}, &pr); e != nil {
			t.Fatalf("plan %q: %v", sql, e)
		}
		var rr ipc.RunResult
		if e := cl.call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, &rr); e != nil || rr.Status != "pending" {
			t.Fatalf("run %q: %+v %v", sql, rr, e)
		}
		return rr.Ticket
	}
	// runTk runs a decided ticket once its decision reached the console.
	runTk := func(t *testing.T, cl *rpc, tk string, out any) *ipc.RPCError {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			e := cl.call(ipc.MethodQueryRun, ipc.RunParams{Ticket: tk}, out)
			if e == nil || !strings.Contains(e.Message, "no decision") || time.Now().After(deadline) {
				return e
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	label := func(t *testing.T, db string) string {
		t.Helper()
		h, err := sql.Open("sqlite", filepath.Join(project, db))
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		var l string
		if err := h.QueryRow("SELECT label FROM items WHERE id = 1").Scan(&l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	auditLog := func(t *testing.T, profile string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(home, "state-"+profile, "locksql", "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("full-auto local profile", func(t *testing.T) {
		c, cl := start(t, "local", "Apply these changes? [y/N]|y")
		for _, q := range []struct{ sql, kind string }{
			{"SELECT id, label FROM items WHERE id = 1 LIMIT 1", "read"},
			{"UPDATE items SET label = 'local-auto' WHERE id = 1", "write"},
			{"CREATE TABLE notes (id INTEGER PRIMARY KEY)", "ddl"},
		} {
			tk := submit(t, cl, q.sql)
			if asked := loxRunAuto(t, c.hub, tk, "auto."+q.kind); asked {
				t.Fatalf("%s: lox run would ask on a full-auto profile", q.kind)
			}
			var rr ipc.RunResult
			if e := runTk(t, cl, tk, &rr); e != nil {
				t.Fatalf("%s: %v", q.kind, e)
			}
		}
		if l := label(t, "local.db"); l != "local-auto" {
			t.Fatalf("local write not applied: %q", l)
		}
		log := auditLog(t, "local")
		for _, want := range []string{`"auto_rule":"auto.write = auto"`, `"decided_by":"auto:auto.write"`, `"auto_rule":"auto.ddl = auto"`, `"decided_by":"auto:auto.ddl"`} {
			if !strings.Contains(log, want) {
				t.Errorf("audit lacks %s:\n%s", want, log)
			}
		}
		c.send("\x03")
		_ = c.wait()
	})

	t.Run("write-asked prod profile", func(t *testing.T) {
		c, cl := start(t, "prod", "Apply these changes? [y/N]|y", `Type the profile name "prod" to continue: |prod`)
		// The read: auto.
		tk := submit(t, cl, "SELECT id, label FROM items WHERE id = 1 LIMIT 1")
		if loxRunAuto(t, c.hub, tk, "auto.read") {
			t.Fatal("lox run would ask for a read of prod")
		}
		var rr ipc.RunResult
		if e := runTk(t, cl, tk, &rr); e != nil || len(rr.Rows) != 1 {
			t.Fatalf("auto read: %+v %v", rr, e)
		}
		// The write: asked. An auto approval is refused by the lock.
		const upd = "UPDATE items SET label = 'prod-human' WHERE id = 1"
		tk = submit(t, cl, upd)
		if !loxRunAuto(t, c.hub, tk, "") {
			t.Fatal("lox run would auto-approve a write of prod")
		}
		autoApprove(t, c.hub, tk, "rogue")
		if e := runTk(t, cl, tk, nil); e == nil || e.Code != ipc.CodeDenied || !strings.Contains(e.Message, "approved by an auto rule") {
			t.Fatalf("auto approval of an asked write: %+v", e)
		}
		if l := label(t, "prod.db"); l != "a" {
			t.Fatalf("an auto approval changed prod: %q", l)
		}
		// The human approves the next ticket: it runs.
		tk = submit(t, cl, upd)
		c.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) {
			d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleHuman}
		})
		if e := runTk(t, cl, tk, &rr); e != nil {
			t.Fatalf("human-approved write: %v", e)
		}
		if l := label(t, "prod.db"); l != "prod-human" {
			t.Fatalf("prod write not applied: %q", l)
		}
		log := auditLog(t, "prod")
		for _, want := range []string{`"auto_rule":"auto.read = auto"`, `"decided_by":"auto:auto.read"`, `"auto_rule":"auto.write = ask"`, `"decided_by":"auto:rogue"`, `"decided_by":"human"`} {
			if !strings.Contains(log, want) {
				t.Errorf("audit lacks %s:\n%s", want, log)
			}
		}
		c.send("\x03")
		_ = c.wait()
	})
}

// loxRunAuto decides ticket tk as `lox run` does in auto mode: a ticket
// the lock left to auto is approved by the auto rule id at once; a
// never-auto one waits for the human (it returns true: asked).
func loxRunAuto(t *testing.T, hub *hubtest.Hub, tk, id string) (asked bool) {
	t.Helper()
	var v struct {
		Flags struct {
			NeverAuto bool `json:"never_auto"`
		} `json:"flags"`
	}
	raw := hub.Ticket(tk)
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("ticket %s: %v: %s", tk, err, raw)
	}
	if v.Flags.NeverAuto {
		return true
	}
	if id == "" {
		t.Fatalf("ticket %s left to auto without a rule", tk)
	}
	autoApprove(t, hub, tk, id)
	return false
}

// autoApprove approves tk as auto rule id of a decider.
func autoApprove(t *testing.T, hub *hubtest.Hub, tk, id string) {
	t.Helper()
	hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) {
		d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleAuto, ID: id}
	})
}
