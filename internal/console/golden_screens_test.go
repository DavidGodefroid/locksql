package console

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden approval screens in testdata/screens")

// The approval screens, byte for byte: what the human sees on the console
// while the request goes to lockhub (lines, bells, colours included), what
// the client gets back and the decision records. A change to any of them
// must be deliberate: run the test with -update and review the diff of
// testdata/screens.
func TestGoldenApprovalScreens(t *testing.T) {
	const pii = "SELECT id, email FROM users WHERE email = 'alice@example.com' LIMIT 1"
	const plain = "SELECT id FROM users LIMIT 5"
	for _, tc := range []struct {
		name    string
		profile func() config.Profile
		opts    []hopt
		set     func(*harness)
		sql     string
		unmask  bool
	}{
		{name: "approved", profile: uatProfile, sql: pii},
		{name: "plain-approved", profile: uatProfile, sql: plain},
		{name: "production", profile: prodProfile, sql: plain},
		{name: "unmask", profile: uatProfile, opts: []hopt{allowUnmask}, sql: pii, unmask: true},
		{name: "refused-on-screen", profile: uatProfile, set: func(h *harness) { h.sess.plan = heavyPlan() },
			sql: "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"},
		{name: "k-anonymity", profile: func() config.Profile { p := uatProfile(); p.Limits.KAnonymity = 5; return p },
			set: func(h *harness) {
				h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
				h.sess.count = countResult(int64(2))
			},
			sql: "SELECT id FROM users WHERE email = 'alice@example.com' LIMIT 1"},
		{name: "write", profile: func() config.Profile { p := uatProfile(); p.Tier = config.TierWrite; return p },
			set: func(h *harness) { h.sess.result = engine.Result{Affected: 1} },
			sql: "UPDATE users SET status = 'x' WHERE id = 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.profile(), tc.opts...)
			if tc.sql == plain {
				h.sess.result = engine.Result{Columns: []engine.ResultColumn{{Label: "id"}}, Rows: [][]any{{int64(1)}}}
			}
			if tc.set != nil {
				tc.set(h)
			}
			recs := len(goldenRecords(t, h))
			h.io.mu.Lock()
			h.io.transcript = nil
			h.io.mu.Unlock()
			pr := h.plan(t, tc.sql, tc.unmask)
			resp := h.call(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
			compareGolden(t, tc.name, goldenText(t, h, resp, recs))
		})
	}
}

// goldenText is a run's transcript, its answer and its decision records
// (the fields that do not vary from run to run).
func goldenText(t *testing.T, h *harness, resp ipc.Response, recs int) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("== screen\n")
	h.io.mu.Lock()
	for _, l := range h.io.transcript {
		l = ticketID.ReplaceAllString(durationMS.ReplaceAllString(l, "in N ms"), "ticket T")
		b.WriteString(strconv.Quote(l) + "\n")
	}
	h.io.mu.Unlock()
	b.WriteString("== response\n")
	if resp.Error != nil {
		fmt.Fprintf(&b, "error %d %q\n", resp.Error.Code, resp.Error.Message)
	} else {
		var rr ipc.RunResult
		if err := json.Unmarshal(resp.Result, &rr); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "ok rows=%d text=%q\n", len(rr.Rows), rr.Text)
	}
	b.WriteString("== audit\n")
	for _, r := range goldenRecords(t, h)[recs:] {
		var parts []string
		for _, k := range []string{"event", "decision", "approval", "reason", "error", "code", "class", "verdict", "unmasked", "warnings", "intent", "sql"} {
			if v, ok := r[k]; ok {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		b.WriteString(strings.Join(parts, " ") + "\n")
	}
	return b.String()
}

// durationMS is the run time printed on the console, which varies.
var durationMS = regexp.MustCompile(`in [0-9]+ ms`)

// ticketID is a hub ticket printed on the console, which varies.
var ticketID = regexp.MustCompile(`ticket [0-9A-Z]{26}`)

// goldenRecords are the audit records written so far (none: empty).
func goldenRecords(t *testing.T, h *harness) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(h.auditLog(t), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "screens", name+".golden")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("screen %s differs from %s:\n--- got\n%s\n--- want\n%s", name, path, got, want)
	}
}
