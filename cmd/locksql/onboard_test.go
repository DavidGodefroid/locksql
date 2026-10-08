package main

import (
	"bytes"
	"context"
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

func (a *answerIO) Println(string) {}
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

func TestAddProfileWritesUserConfig(t *testing.T) {
	e, out, _ := onboardEnv(t)
	name, err := addProfile(e, &scriptIO{answers: []string{"sqlite://./x.db", "", "", "", ""}})
	if err != nil || name != "dev" {
		t.Fatalf("%q %v\n%s", name, err, out)
	}
	data, err := os.ReadFile(userConfig(t))
	if err != nil || !strings.Contains(string(data), `[profiles."dev"]`) {
		t.Fatalf("%v\n%s", err, data)
	}
	if !strings.Contains(out.String(), "(profile dev)") {
		t.Fatalf("output:\n%s", out)
	}

	// A second profile gets a free default name; Ctrl-D writes nothing.
	if name, err := addProfile(e, &scriptIO{answers: []string{"sqlite://./y.db", "", "", "", ""}}); err != nil || name != "dev2" {
		t.Fatalf("%q %v", name, err)
	}
	before, _ := os.ReadFile(userConfig(t))
	if _, err := addProfile(e, &scriptIO{answers: []string{"sqlite://./z.db"}}); err == nil {
		t.Fatal("aborted prompts succeeded")
	}
	if after, _ := os.ReadFile(userConfig(t)); !bytes.Equal(before, after) {
		t.Fatal("aborted prompts wrote")
	}
}

func TestAddUsage(t *testing.T) {
	e, out, _ := onboardEnv(t)
	if code := runEnv(e, []string{"add", "extra"}); code != exitUsage {
		t.Fatalf("args: code %d\n%s", code, out)
	}
	e.tty = false
	if code := runEnv(e, []string{"add"}); code != exitUsage || !strings.Contains(out.String(), "terminal") {
		t.Fatalf("no tty: code %d\n%s", code, out)
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
