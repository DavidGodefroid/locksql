//go:build unix

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/verbs"
)

// fixScenario is TestDoctorFix's machine: codex to wire for this account
// (a repair of this account) and the agent's account to add to the clients
// group (a root repair). It returns the env, its stdout and stderr, and the
// root scripts run.
func fixScenario(t *testing.T) (env, *bytes.Buffer, *bytes.Buffer, *[]string) {
	t.Helper()
	e, _, _ := onboardEnv(t, "codex")
	d := fakeDoctor(separatedSys())
	member := false
	d.inGroup = func(uid int, _ string) bool { return member && uid == 1000 }
	d.agents = e.agentEnv
	e.doc = &d
	scripts := &[]string{}
	e.root = func(s string) error {
		*scripts = append(*scripts, s)
		member = true
		return nil
	}
	var stdout, stderr bytes.Buffer
	e.stdout, e.stderr, e.tty = &stdout, &stderr, false
	return e, &stdout, &stderr, scripts
}

// `doctor --fix --yes --json`, as lox init calls it: one verbs.Doctor on
// stdout with the repairs made, the human text on stderr.
func TestDoctorJSONFix(t *testing.T) {
	e, stdout, stderr, scripts := fixScenario(t)
	code := runEnv(e, []string{"doctor", "--json"})
	var before verbs.Doctor
	oneJSONLine(t, stdout.String(), &before)
	if before.Lock != "locksql" || before.OK != (code == exitOK) || len(before.Checks) == 0 || before.Fixed == nil || len(before.Fixed) != 0 {
		t.Fatalf("code %d, report %+v", code, before)
	}
	failing := slices.IndexFunc(before.Checks, func(c verbs.Check) bool { return c.Status != verbs.StatusOK })
	if failing < 0 || before.Checks[failing].Fix == "" {
		t.Errorf("no check to repair, or no fix said: %+v", before.Checks)
	}
	for _, c := range before.Checks {
		if c.Status != verbs.StatusOK && c.Status != verbs.StatusWarn && c.Status != verbs.StatusFail {
			t.Errorf("status %q", c.Status)
		}
		if c.Status == verbs.StatusOK && c.Fix != "" {
			t.Errorf("an ok check with a fix: %+v", c)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := runEnv(e, []string{"doctor", "--fix", "--yes", "--json"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, stderr)
	}
	var after verbs.Doctor
	oneJSONLine(t, stdout.String(), &after)
	rootFix := slices.ContainsFunc(after.Fixed, func(s string) bool { return strings.HasPrefix(s, "add agent to locksql-clients") })
	if !after.OK || !slices.Contains(after.Fixed, "wire codex for this account") || !rootFix {
		t.Errorf("report %+v", after)
	}
	if len(*scripts) != 1 || !strings.Contains(stderr.String(), "repaired:") {
		t.Errorf("scripts %q\nstderr %s", *scripts, stderr)
	}
}

// The flag rules: --yes needs --fix; --fix without a terminal needs --yes;
// doctor takes flags only. Each is a usage error, a verbs.Error with
// --json, and repairs nothing.
func TestDoctorFlagRules(t *testing.T) {
	for _, args := range [][]string{
		{"doctor", "--yes", "--json"},
		{"doctor", "--fix", "--json"},
		{"doctor", "--json", "--bogus"},
		{"doctor", "--json", "glsa_CanarySecretToken123"},
		{"doctor", "--json", "--profile"},
	} {
		e, stdout, stderr, scripts := fixScenario(t)
		if code := runEnv(e, args); code != exitUsage {
			t.Errorf("%v: code %d", args, code)
		}
		var fail verbs.Error
		oneJSONLine(t, stdout.String(), &fail)
		if fail.Lock != "locksql" || fail.Code != verbs.CodeUsage || !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("%v: %+v\n%s", args, fail, stderr)
		}
		if strings.Contains(stdout.String()+stderr.String(), "Canary") || len(*scripts) != 0 {
			t.Errorf("%v: quotes the argument or repaired: %q\n%s", args, *scripts, stderr)
		}
	}
	// Without --json: nothing on stdout.
	e, stdout, _, _ := fixScenario(t)
	if code := runEnv(e, []string{"doctor", "--yes"}); code != exitUsage || stdout.Len() != 0 {
		t.Errorf("--yes without --fix: code %d, stdout %q", code, stdout)
	}
}

// On a terminal, --fix asks before each repair: a declined one is not made.
func TestDoctorFixAsksEachRepair(t *testing.T) {
	e, stdout, stderr, scripts := fixScenario(t)
	e.tty = true
	e.stdin = strings.NewReader("n\ny\n") // decline the wiring, accept the root repair
	runEnv(e, []string{"doctor", "--fix"})
	out := stdout.String()
	for _, want := range []string{"Repair: wire codex for this account? [y/N]", "not repaired: wire codex for this account (declined)",
		"Repair as root (sudo): add agent to locksql-clients", "usermod -aG", "repaired: add agent to locksql-clients"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s%s", want, out, stderr)
		}
	}
	if len(*scripts) != 1 {
		t.Errorf("root scripts %q", *scripts)
	}

	// Both declined: nothing repaired, no root script.
	e, stdout, _, scripts = fixScenario(t)
	e.tty = true
	e.stdin = strings.NewReader("n\nn\n")
	runEnv(e, []string{"doctor", "--fix", "--json"})
	var rep verbs.Doctor
	oneJSONLine(t, stdout.String(), &rep)
	if len(rep.Fixed) != 0 || len(*scripts) != 0 {
		t.Errorf("fixed %q, scripts %q", rep.Fixed, *scripts)
	}
}
