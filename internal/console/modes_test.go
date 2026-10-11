package console

import (
	"context"
	"fmt"
	"strings"
	"testing"

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

// Shift+Tab switches between manual and auto mode: audited, announced,
// shown on the status line, and in effect for the next statement.
func TestShiftTabTogglesMode(t *testing.T) {
	h := newHarness(t, uatProfile())
	if h.s.autoApprove() || !strings.Contains(h.io.statusLine(), "mode manual") {
		t.Fatalf("not manual at start; status %q", h.io.statusLine())
	}
	h.s.Key(KeyShiftTab)
	if !h.s.autoApprove() {
		t.Fatal("still manual")
	}
	if out := h.io.output(); !strings.Contains(out, "auto mode") {
		t.Errorf("no announcement:\n%s", out)
	}
	if st := h.io.statusLine(); !strings.Contains(st, "mode AUTO") {
		t.Errorf("status %q", st)
	}
	pr := h.plan(t, selectUsers, false)
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.io.promptCount() != 0 {
		t.Errorf("auto mode prompted: %q", h.io.prompts)
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if !st.AutoApprove {
		t.Error("status does not report auto mode")
	}

	h.s.Key(KeyShiftTab)
	if h.s.autoApprove() || !strings.Contains(h.io.statusLine(), "mode manual") {
		t.Fatalf("not back to manual; status %q", h.io.statusLine())
	}
	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if h.io.promptCount() != 1 {
		t.Errorf("manual mode did not prompt: %q", h.io.prompts)
	}
	want := []string{"mode:auto", "auto:auto", "run:ok", "mode:manual", "approved:approved", "run:ok"}
	if got := h.events(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("audit events %v, want %v", got, want)
	}
}

// A production profile stays in manual mode: the key says so and nothing
// is audited.
func TestAutoModeUnavailableOnProduction(t *testing.T) {
	h := newHarness(t, prodProfile(), skip)
	if h.s.autoApprove() {
		t.Fatal("auto on production")
	}
	h.s.Key(KeyShiftTab)
	if h.s.autoApprove() {
		t.Fatal("Shift+Tab turned auto on, on production")
	}
	if out := h.io.output(); !strings.Contains(out, "not available on a production profile") {
		t.Errorf("no refusal:\n%s", out)
	}
	if st := h.io.statusLine(); !strings.Contains(st, "mode manual") || strings.Contains(st, "Tab") {
		t.Errorf("status %q", st)
	}
	if log := h.auditLog(t); strings.TrimSpace(log) != "" {
		t.Errorf("audited:\n%s", log)
	}
}

// Ctrl-O switches the clear results: audited, announced, on the status
// line and on the next run.
func TestCtrlOTogglesResults(t *testing.T) {
	h := newHarness(t, uatProfile())
	if h.s.showResults || !strings.Contains(h.io.statusLine(), "results masked") {
		t.Fatalf("results on at start; status %q", h.io.statusLine())
	}
	h.s.Key(KeyCtrlO)
	if !h.s.showResults || !strings.Contains(h.io.statusLine(), "results clear") {
		t.Fatalf("results not on; status %q", h.io.statusLine())
	}
	pr := h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if out := h.io.output(); !strings.Contains(out, "result in clear") || !strings.Contains(out, "alice@example.com") {
		t.Errorf("no clear result:\n%s", out)
	}
	h.s.Key(KeyCtrlO)
	before := len(h.io.out)
	pr = h.plan(t, selectUsers, false)
	h.io.answers = []string{"y"}
	h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	if out := strings.Join(h.io.out[before:], "\n"); strings.Contains(out, "alice@example.com") {
		t.Errorf("clear result after Ctrl-O off:\n%s", out)
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.ShowResults {
		t.Error("status reports results on")
	}
	if ev := h.events(t); ev[0] != "results:shown" || ev[3] != "results:hidden" {
		t.Errorf("audit events %v", ev)
	}
}

// :mode and :results are the typed equivalents of the keys; :status shows
// both switches.
func TestModeAndResultsCommands(t *testing.T) {
	h := newHarness(t, uatProfile())
	ctx := context.Background()
	h.s.Command(ctx, ":mode")
	h.s.Command(ctx, ":results")
	if !h.s.autoApprove() || !h.s.showResults {
		t.Fatal("commands did not switch")
	}
	before := len(h.io.out)
	h.s.Command(ctx, ":status")
	out := ansi.ReplaceAllString(strings.Join(h.io.out[before:], "\n"), "")
	for _, want := range []string{"mode", "auto: statements allowed", "results", "shown here in clear", "unmask", "refused", "plans open"} {
		if !strings.Contains(out, want) {
			t.Errorf(":status lacks %q:\n%s", want, out)
		}
	}
	h.s.Command(ctx, ":help")
	if last := h.io.out[len(h.io.out)-1]; !strings.Contains(last, ":mode") || !strings.Contains(last, ":results") {
		t.Errorf("help %q", last)
	}
}

// The status line names what widens the session and what awaits the human.
func TestStatusLineContent(t *testing.T) {
	h := newHarness(t, uatProfile(), allowUnmask)
	st := h.io.statusLine()
	for _, want := range []string{"UAT", "tier read", "mode manual", "results masked", "unmask allowed"} {
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
		{{text: "1"}, {text: "alice@example.com", masked: true, ref: "r1.1.2"}, {text: "short"}},
		{{text: "22"}, {text: "bob@example.org", masked: true}, {text: "a much longer note than the column allows"}},
	}
	lines := layoutTable([]string{"id", "email", "note"}, rows, 60)
	plain := make([]string, len(lines))
	for i, l := range lines {
		plain[i] = ansi.ReplaceAllString(l, "")
	}
	want := []string{
		"id │ email                      │ note",
		"───┼────────────────────────────┼───────────────────────────",
		"1  │ alice@example.com ‹r1.1.2› │ short",
		"22 │ bob@example.org            │ a much longer note than t…",
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
