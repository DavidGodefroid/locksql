package console

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// events lists "event:decision" of the audit records.
func (h *harness) events(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range h.auditRecords(t) {
		out = append(out, fmt.Sprint(r["event"], ":", r["decision"]))
	}
	return out
}

// Ctrl-O switches the clear results: audited, announced, on the status
// line and on the next run.
func TestCtrlOTogglesResults(t *testing.T) {
	h := newHarness(t, uatProfile())
	if h.s.showResults() || !strings.Contains(h.io.statusLine(), "results masked") {
		t.Fatalf("results on at start; status %q", h.io.statusLine())
	}
	h.s.Key(KeyCtrlO)
	if !h.s.showResults() || !strings.Contains(h.io.statusLine(), "results clear") {
		t.Fatalf("results not on; status %q", h.io.statusLine())
	}
	pr := h.plan(t, selectUsers, false)
	if r := h.approveRun(t, pr.PlanID); r.Error != nil {
		t.Fatal(r.Error.Message)
	}
	if out := h.io.output(); !strings.Contains(out, "result in clear") || !strings.Contains(out, "alice@example.com") {
		t.Errorf("no clear result:\n%s", out)
	}
	h.s.Key(KeyCtrlO)
	before := len(h.io.out)
	pr = h.plan(t, selectUsers, false)
	if r := h.approveRun(t, pr.PlanID); r.Error != nil {
		t.Fatal(r.Error.Message)
	}
	if out := strings.Join(h.io.out[before:], "\n"); strings.Contains(out, "alice@example.com") {
		t.Errorf("clear result after Ctrl-O off:\n%s", out)
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.ShowResults {
		t.Error("status reports results on")
	}
	if ev := h.events(t); ev[0] != "results:shown" || !slices.Contains(ev, "results:hidden") {
		t.Errorf("audit events %v", ev)
	}
}

// :results is the typed equivalent of Ctrl-O; :status shows the switches.
func TestResultsCommand(t *testing.T) {
	h := newHarness(t, uatProfile())
	ctx := context.Background()
	h.s.Command(ctx, ":results")
	if !h.s.showResults() {
		t.Fatal("command did not switch")
	}
	before := len(h.io.out)
	h.s.Command(ctx, ":status")
	out := ansi.ReplaceAllString(strings.Join(h.io.out[before:], "\n"), "")
	for _, want := range []string{"results", "shown here in clear", "unmask", "refused", "plans open"} {
		if !strings.Contains(out, want) {
			t.Errorf(":status lacks %q:\n%s", want, out)
		}
	}
	h.s.Command(ctx, ":help")
	if last := h.io.out[len(h.io.out)-1]; !strings.Contains(last, ":results") {
		t.Errorf("help %q", last)
	}
}

// The status line names what widens the session and what awaits the human.
func TestStatusLineContent(t *testing.T) {
	h := newHarness(t, uatProfile(), allowUnmask)
	st := h.io.statusLine()
	for _, want := range []string{"UAT", "tier read", "results masked", "unmask allowed"} {
		if !strings.Contains(st, want) {
			t.Errorf("status lacks %q: %q", want, st)
		}
	}
	h.plan(t, selectUsers, false)
	h.s.refreshStatus()
	if st := h.io.statusLine(); !strings.Contains(st, "1 plan open") {
		t.Errorf("status %q", st)
	}
	h.ok(t, ipc.MethodChangeRequest, ipc.ChangeParams{Change: "raise max_rows"}, nil)
	h.s.refreshStatus()
	if st := h.io.statusLine(); !strings.Contains(st, "1 change request") {
		t.Errorf("status %q", st)
	}
	h2 := newHarness(t, prodProfile())
	if st := h2.io.statusLine(); !strings.HasPrefix(st, "PROD") {
		t.Errorf("production status %q", st)
	}
}

func TestLayoutTable(t *testing.T) {
	rows := [][]cell{
		{{text: "1"}, {text: "alice@example.com", masked: true}, {text: "short"}},
		{{text: "22"}, {text: "bob@example.org", masked: true}, {text: "a much longer note than the column allows"}},
	}
	lines := layoutTable([]string{"id", "email", "note"}, rows, 60)
	plain := make([]string, len(lines))
	for i, l := range lines {
		plain[i] = ansi.ReplaceAllString(l, "")
	}
	want := []string{
		"id │ email             │ note",
		"───┼───────────────────┼────────────────────────────────────",
		"1  │ alice@example.com │ short",
		"22 │ bob@example.org   │ a much longer note than the column…",
	}
	if strings.Join(plain, "\n") != strings.Join(want, "\n") {
		t.Errorf("table:\n%s\nwant:\n%s", strings.Join(plain, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(lines[0], paint.Yellow("email")) || !strings.Contains(lines[2], paint.Yellow("alice@example.com")) || strings.Contains(lines[2], paint.Yellow("1")) {
		t.Errorf("highlights:\n%q", lines)
	}
	// Too narrow: the widest columns give way, never below 4.
	narrow := layoutTable([]string{"id", "email", "note"}, rows, 20)
	for _, l := range narrow {
		if n := len([]rune(ansi.ReplaceAllString(l, ""))); n > 20 {
			t.Errorf("line of %d columns: %q", n, l)
		}
	}
}

// :unmask allows unmasked output while the console runs, after a typed y;
// turning it off needs no confirmation and refuses the open unmask plans.
// Each change is audited.
func TestUnmaskCommandTogglesLive(t *testing.T) {
	h := newHarness(t, uatProfile())
	ctx := context.Background()

	// Anything but y leaves it off, unaudited.
	h.io.answers = []string{"n"}
	h.s.Command(ctx, ":unmask")
	if h.s.allowUnmask() {
		t.Fatal("unmask allowed without a y")
	}
	if out := h.io.output(); !strings.Contains(out, "still off") {
		t.Errorf("no refusal:\n%s", out)
	}
	if log := h.auditLog(t); strings.TrimSpace(log) != "" {
		t.Fatalf("audited without a change:\n%s", log)
	}

	h.io.answers = []string{"y"}
	h.s.Command(ctx, ":unmask")
	if !h.s.allowUnmask() || !strings.Contains(h.io.statusLine(), "unmask allowed") {
		t.Fatalf("unmask not allowed; status %q", h.io.statusLine())
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !st.AllowUnmask {
		t.Error("status does not report unmask allowed")
	}
	pr := h.plan(t, selectUsers, true)
	if !pr.Unmask {
		t.Fatal("unmask plan refused once allowed")
	}

	// Off again: at once, no prompt, and the open unmask plan is refused.
	prompts := h.io.promptCount()
	h.s.Command(ctx, ":unmask")
	if h.s.allowUnmask() || strings.Contains(h.io.statusLine(), "unmask allowed") {
		t.Fatalf("unmask still allowed; status %q", h.io.statusLine())
	}
	if h.io.promptCount() != prompts {
		t.Error("turning unmask off prompted")
	}
	resp := h.approveRun(t, pr.PlanID)
	wantCode(t, resp, ipc.CodeRefused)
	if h.sess.runCount() != 0 {
		t.Fatal("unmask plan ran after :unmask off")
	}
	resp = h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: selectUsers, Unmask: true})
	wantCode(t, resp, ipc.CodeRefused)

	want := []string{"unmask:allowed", "unmask:off", "refused:", "refused:"}
	got := h.events(t)
	if len(got) != len(want) {
		t.Fatalf("audit events %v, want %v", got, want)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("audit events %v, want %v", got, want)
			break
		}
	}
}

// No client method reaches a switch: the methods named after them do not
// exist, and the status request changes nothing.
func TestSwitchesNotReachableFromClients(t *testing.T) {
	h := newHarness(t, uatProfile())
	for _, m := range []string{"mode", "results", "unmask", "console.mode", "console.unmask", "console.results", "key"} {
		resp := h.call(t, m, map[string]any{"auto": true, "allow_unmask": true, "show_results": true})
		if resp.Error == nil {
			t.Errorf("method %q answered without an error", m)
		}
	}
	h.ok(t, ipc.MethodStatus, nil, nil)
	if h.s.showResults() || h.s.allowUnmask() {
		t.Fatal("a client request changed a switch")
	}
	if log := h.auditLog(t); strings.TrimSpace(log) != "" {
		t.Errorf("audited:\n%s", log)
	}
}

func fingerHarness(t *testing.T, v *fingerprint.Fake) *harness {
	t.Helper()
	return newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Fingerprint = true
		c.Approver = newFingerprintApprover(c.IO, v, "left-index-finger", time.Second)
	})
}

// Level 2: results stay masked; showing them is refused without a prompt,
// hiding them is immediate.
func TestLevel2ShowResultsRefused(t *testing.T) {
	v := &fingerprint.Fake{}
	h := fingerHarness(t, v)
	h.s.Key(KeyCtrlO)
	if h.s.showResults() || len(h.io.prompts) != 0 || v.Calls != 0 {
		t.Fatalf("showResults = %v, prompts %q", h.s.showResults(), h.io.prompts)
	}
	if out := h.io.output(); !strings.Contains(out, "results stay masked at level 2: the window is on the agent's desktop") {
		t.Errorf("no refusal:\n%s", out)
	}
}

// Level 1 (typed approvals on the desktop): the results stay masked: the agent's account can read the window. Ctrl-O
// and :results are refused without a prompt or an audit record; hiding
// stays free.
func TestLevel1ShowResultsRefused(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) { c.Boundary = "your desktop: the agent can read this window and type into it" })
	h.s.Key(KeyCtrlO)
	h.s.Command(context.Background(), ":results")
	if h.s.showResults() || len(h.io.prompts) != 0 {
		t.Fatalf("results = %v, prompts %q", h.s.showResults(), h.io.prompts)
	}
	if out := h.io.output(); strings.Count(out, "results stay masked at level 1: the agent's account can read this window") != 2 {
		t.Errorf("refusals:\n%s", out)
	}
	if st := h.io.statusLine(); !strings.Contains(st, "level 1") || !strings.Contains(st, "masked") {
		t.Errorf("status %q", st)
	}
	for _, r := range h.auditRecords(t) {
		if r["event"] == "results" {
			t.Errorf("refused switch audited: %v", r)
		}
	}
}

// A desktop server never starts with the clear results on, whatever its
// config says.
func TestDesktopServerIgnoresShowResults(t *testing.T) {
	h := newHarness(t, uatProfile(), func(c *ServerConfig) {
		c.Boundary = "your desktop: the agent can read this window and type into it"
		c.ShowResults = true
	})
	if h.s.showResults() {
		t.Fatal("results clear at start on the desktop")
	}
}

// The session shape (level 0) toggles the results freely, as before.
func TestLevel0TogglesResults(t *testing.T) {
	h := newHarness(t, uatProfile())
	h.s.Key(KeyCtrlO)
	if !h.s.showResults() {
		t.Fatal("results refused at level 0")
	}
}
