package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// onboardEnv isolates every directory locksql or an agent could write to
// and fakes the agents named in onPath. The fake `claude mcp add` writes
// the user-scope entry the way Claude Code does.
func onboardEnv(t *testing.T, onPath ...string) (env, *bytes.Buffer, string) {
	home := t.TempDir()
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"} {
		t.Setenv(k, home)
	}
	var out bytes.Buffer
	ae := agentinit.Env{Home: home, Getenv: func(string) string { return "" },
		LookPath: func(n string) (string, error) {
			if slices.Contains(onPath, n) {
				return n, nil
			}
			return "", exec.ErrNotFound
		},
		Run: func(name string, args ...string) ([]byte, error) {
			if name == "claude" && len(args) > 1 && args[0] == "mcp" && args[1] == "add" {
				return nil, os.WriteFile(filepath.Join(home, ".claude.json"),
					[]byte(`{"mcpServers":{"locksql":{"command":"locksql","args":["mcp"]}}}`), 0o600)
			}
			return nil, nil
		}}
	e := env{stdout: &out, stderr: &out, cwd: t.TempDir(), tty: true,
		agentEnv: func() (agentinit.Env, error) { return ae, nil },
		sys:      func() (*sysconf.Config, error) { return nil, nil }}
	return e, &out, home
}

func userConfig(t *testing.T) string {
	t.Helper()
	p, err := config.UserConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBareWithoutTTYPrintsUsage(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	e.tty = false
	if code := runEnv(e, nil); code != exitUsage || !strings.Contains(out.String(), "usage") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("wired agents without a terminal: %v", entries)
	}
}

func TestWireAgentsReportsAndIsIdempotent(t *testing.T) {
	e, out, home := onboardEnv(t, "codex", "claude")
	wireAgents(e)
	for _, want := range []string{"Agents found: claude, codex", "~/.codex/config.toml", `user MCP server "locksql"`, "~/.claude/settings.json"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("first run lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	wireAgents(e)
	if out.Len() != 0 {
		t.Fatalf("second run printed (so wrote) again:\n%s", out)
	}
}

func TestWireAgentsReportsFailureAndGoesOn(t *testing.T) {
	e, out, home := onboardEnv(t, "codex", "gemini")
	// An unparsable codex config cannot be merged into.
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[[[ not toml"), 0o600)
	wireAgents(e)
	if !strings.Contains(out.String(), "not wired") || !strings.Contains(out.String(), "~/.gemini/settings.json") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestWireAgentsSkippedForServiceAccount(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	e.sys = func() (*sysconf.Config, error) {
		u, _ := user.Current()
		return &sysconf.Config{ServiceUser: u.Username}, nil
	}
	wireAgents(e)
	if entries, _ := os.ReadDir(home); len(entries) != 0 || out.Len() != 0 {
		t.Fatalf("service account wired agents: %v\n%s", entries, out)
	}
}

func TestOnboardSeparatedClientOnlyWires(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	e.sys = func() (*sysconf.Config, error) { return &sysconf.Config{ServiceUser: "locksql-nobody-xyz"}, nil }
	if code := runOnboard(e); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "locksql session") || !strings.Contains(out.String(), "~/.codex/config.toml") {
		t.Fatalf("no hint or no wiring:\n%s", out)
	}
	if _, err := os.Stat(userConfig(t)); err == nil {
		t.Fatal("client account wrote a profile")
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); err != nil {
		t.Fatal(err)
	}
}

func TestClientCommandsNeverWire(t *testing.T) {
	e, _, home := onboardEnv(t, "codex", "claude")
	for _, args := range [][]string{{"tables", "--db", "x"}, {"status"}, {"version"}, {"init", "--bogus"}} {
		runEnv(e, args)
	}
	for _, rel := range []string{".codex", ".claude", ".claude.json"} {
		if _, err := os.Stat(filepath.Join(home, rel)); err == nil {
			t.Fatalf("%s written by a client command", rel)
		}
	}
}

type answerIO struct {
	t      *testing.T
	answer string
	asked  bool
}

func (a *answerIO) Println(string)                                    {}
func (a *answerIO) AskSecret(context.Context, string) ([]byte, error) { return nil, nil }
func (a *answerIO) Ask(context.Context, string, time.Duration) (string, bool) {
	if a.answer == "" {
		a.t.Fatal("asked with a single profile")
	}
	a.asked = true
	return a.answer, true
}

func TestChooseProfile(t *testing.T) {
	e, _, _ := onboardEnv(t)
	cfg := userConfig(t)
	if n, err := chooseProfile(e, &answerIO{t: t}); err != nil || n != "" {
		t.Fatalf("none: %q %v", n, err)
	}
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("[profiles.a]\nengine = \"sqlite\"\npath = \"/tmp/a.db\"\n"), 0o600)
	if n, err := chooseProfile(e, &answerIO{t: t}); err != nil || n != "a" {
		t.Fatalf("single: %q %v", n, err)
	}
	os.WriteFile(cfg, []byte("[profiles.a]\nengine = \"sqlite\"\npath = \"/tmp/a.db\"\n[profiles.b]\nengine = \"sqlite\"\npath = \"/tmp/b.db\"\n"), 0o600)
	io := &answerIO{t: t, answer: "2"}
	if n, err := chooseProfile(e, io); err != nil || n != "b" || !io.asked {
		t.Fatalf("several: %q %v", n, err)
	}
	if n, err := chooseProfile(e, &answerIO{t: t, answer: "a"}); err != nil || n != "a" {
		t.Fatalf("by name: %q %v", n, err)
	}
}

func TestInitDetectsAgents(t *testing.T) {
	e, out, _ := onboardEnv(t, "codex")
	os.Mkdir(filepath.Join(e.cwd, ".git"), 0o755)
	if code := runEnv(e, []string{"init"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.cwd, "AGENTS.md")); err != nil {
		t.Fatalf("codex not initialised: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.cwd, ".mcp.json")); err == nil {
		t.Fatal("claude initialised without being detected")
	}

	e, out, _ = onboardEnv(t)
	if code := runEnv(e, []string{"init"}); code != exitUsage || !strings.Contains(out.String(), "name at least one agent") {
		t.Fatalf("none detected: code %d\n%s", code, out)
	}
}

// separatedClient makes e a client account in separated mode.
func separatedClient(e *env) {
	e.sys = func() (*sysconf.Config, error) { return &sysconf.Config{ServiceUser: "locksql-nobody-xyz"}, nil }
}

// separatedService makes e the service account in separated mode.
func separatedService(e *env) {
	e.sys = func() (*sysconf.Config, error) {
		u, _ := user.Current()
		return &sysconf.Config{ServiceUser: u.Username}, nil
	}
}

func TestSeparatedClientGetsProjectSteps(t *testing.T) {
	e, out, _ := onboardEnv(t, "codex")
	separatedClient(&e)
	if code := runOnboard(e); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{"~/.codex/config.toml", ".locksql/config.toml", "locksql init", "locksql console --project"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "add a database") {
		t.Fatalf("still points at the user config:\n%s", out)
	}
}

func TestSeparatedServiceBareIsConsoleWithoutPrompts(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	separatedService(&e)
	// No profile visible: no prompt (answerIO would fail the test), a
	// pointer to the project config and --project.
	if code := runOnboard(e); code != exitUsage {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{".locksql/config.toml", "--project"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(userConfig(t)); err == nil {
		t.Fatal("service account prompted and wrote a profile")
	}
	if _, err := os.Stat(filepath.Join(home, ".codex")); err == nil {
		t.Fatal("service account wired agents")
	}
}

func TestConsoleWithoutProfileSameUserRefused(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	if err := os.MkdirAll(filepath.Join(e.cwd, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "[profiles.a]\nengine = \"sqlite\"\npath = \"a.db\"\n\n[profiles.b]\nengine = \"sqlite\"\npath = \"b.db\"\n"
	if err := os.WriteFile(filepath.Join(e.cwd, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runEnv(e, []string{"console"}); code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{"separate account", "sudo locksql install", "locksql doctor"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "Profile") {
		t.Fatalf("asked for a profile before refusing:\n%s", out)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("wrote %v before refusing", entries)
	}
}

func TestSysconfErrorStopsEarly(t *testing.T) {
	for _, args := range [][]string{nil, {"console"}} {
		e, out, home := onboardEnv(t, "codex")
		e.sys = func() (*sysconf.Config, error) {
			return nil, errors.New("sysconf: /etc/locksql/system.toml: not owned by root")
		}
		var code int
		if args == nil {
			code = runOnboard(e)
		} else {
			code = runEnv(e, args)
		}
		if code != exitUsage || !strings.Contains(out.String(), "not owned by root") {
			t.Fatalf("%v: code %d\n%s", args, code, out)
		}
		if entries, _ := os.ReadDir(home); len(entries) != 0 {
			t.Fatalf("%v: wrote %v", args, entries)
		}
	}
}

func TestWireAgentsReportsPartialWritesBeforeError(t *testing.T) {
	e, out, _ := onboardEnv(t, "claude")
	orig := e.agentEnv
	e.agentEnv = func() (agentinit.Env, error) {
		ae, err := orig()
		ae.Run = func(string, ...string) ([]byte, error) { return []byte("config locked"), errors.New("exit 1") }
		return ae, err
	}
	wireAgents(e)
	s := out.String()
	i, j := strings.Index(s, "~/.claude/settings.json"), strings.Index(s, "not wired")
	if i < 0 || j < 0 || i > j || !strings.Contains(s, "config locked") {
		t.Fatalf("written paths not listed before the error:\n%s", s)
	}
}

func TestWireAgentsSkippedAsRoot(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	e.euid = func() int { return 0 }
	wireAgents(e)
	if !strings.Contains(out.String(), "not wiring agents as root") {
		t.Fatalf("output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex")); err == nil {
		t.Fatal("wired as root")
	}
}

// installSpy replaces the install step of the onboarding.
func installSpy(e *env, answer string) *[]string {
	var calls []string
	e.stdin = strings.NewReader(answer)
	e.install = func(args []string) int {
		calls = append(calls, strings.Join(args, " "))
		return exitOK
	}
	return &calls
}

func TestOnboardSameUserOffersInstall(t *testing.T) {
	e, out, home := onboardEnv(t, "codex")
	calls := installSpy(&e, "y\n")
	if code := runOnboard(e); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if len(*calls) != 1 {
		t.Fatalf("install calls %v", *calls)
	}
	for _, want := range []string{"~/.codex/config.toml", "separate account", ".locksql/config.toml", "locksql console --project"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); err != nil {
		t.Fatal("agents not wired:", err)
	}
	if _, err := os.Stat(userConfig(t)); err == nil {
		t.Fatal("onboarding wrote a user profile")
	}
}

func TestOnboardSameUserInstallDeclined(t *testing.T) {
	for _, answer := range []string{"n\n", "\n", ""} {
		e, out, _ := onboardEnv(t)
		calls := installSpy(&e, answer)
		if code := runOnboard(e); code != exitOK {
			t.Fatalf("answer %q: code %d\n%s", answer, code, out)
		}
		if len(*calls) != 0 {
			t.Fatalf("answer %q ran install", answer)
		}
		if !strings.Contains(out.String(), "sudo locksql install") || !strings.Contains(out.String(), "locksql console --project") {
			t.Fatalf("answer %q: no steps:\n%s", answer, out)
		}
	}
}

func TestOnboardSameUserExistingProfileNotUsed(t *testing.T) {
	e, out, _ := onboardEnv(t)
	os.MkdirAll(filepath.Dir(userConfig(t)), 0o700)
	os.WriteFile(userConfig(t), []byte("[profiles.dev]\nengine = \"sqlite\"\npath = \"/tmp/x.db\"\n"), 0o600)
	installSpy(&e, "n\n")
	if code := runOnboard(e); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), ".locksql/config.toml") {
		t.Fatalf("no pointer to the project config:\n%s", out)
	}
}

func TestAddIsGone(t *testing.T) {
	e, out, _ := onboardEnv(t)
	if code := runEnv(e, []string{"add"}); code != exitUsage || !strings.Contains(out.String(), "unknown command") {
		t.Fatalf("code %d\n%s", code, out)
	}
}
