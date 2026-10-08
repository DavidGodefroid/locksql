package agentinit

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func fakeEnv(t *testing.T, onPath ...string) (Env, *[][]string) {
	t.Helper()
	home := t.TempDir()
	var calls [][]string
	wired := false
	e := Env{
		Home:   home,
		Getenv: func(k string) string { return map[string]string{}[k] },
		LookPath: func(n string) (string, error) {
			if slices.Contains(onPath, n) {
				return "/usr/bin/" + n, nil
			}
			return "", exec.ErrNotFound
		},
		Run: func(n string, a ...string) ([]byte, error) {
			calls = append(calls, append([]string{n}, a...))
			if len(a) >= 2 && a[0] == "mcp" && a[1] == "get" && !wired {
				return []byte("not found"), errors.New("exit 1")
			}
			if len(a) >= 2 && a[0] == "mcp" && a[1] == "add" {
				wired = true
			}
			return nil, nil
		},
	}
	return e, &calls
}

func TestDetect(t *testing.T) {
	e, _ := fakeEnv(t, "claude", "cursor-agent")
	os.MkdirAll(filepath.Join(e.Home, ".gemini"), 0o755)
	os.MkdirAll(filepath.Join(e.Home, ".claude"), 0o755) // irrelevant: claude needs the command
	if got := Detect(e); !slices.Equal(got, []string{"claude", "cursor", "gemini"}) {
		t.Fatalf("Detect = %v", got)
	}
}

func TestInitUserCodex(t *testing.T) {
	e, _ := fakeEnv(t, "codex")
	cfg := filepath.Join(e.Home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	os.WriteFile(cfg, []byte("# my settings\nmodel = \"o3\"\n"), 0o600)
	res, err := InitUser(e, "codex")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(b), "# my settings\nmodel = \"o3\"\n") || !strings.Contains(string(b), "[mcp_servers.locksql]") {
		t.Fatalf("config.toml:\n%s", b)
	}
	var m map[string]any
	if _, err := toml.Decode(string(b), &m); err != nil {
		t.Fatalf("not valid TOML: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".codex", "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	if len(res.Actions) != 2 || res.Actions[0].Path != "~/.codex/config.toml" {
		t.Fatalf("actions %+v", res.Actions)
	}
	if p, _ := PendingUser(e, "codex"); p {
		t.Fatal("still pending after InitUser")
	}
}

func TestInitUserCodexKeepsExistingEntry(t *testing.T) {
	e, _ := fakeEnv(t, "codex")
	cfg := filepath.Join(e.Home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	own := "mcp_servers.locksql = { command = \"/opt/locksql\", args = [\"mcp\"] }\n"
	os.WriteFile(cfg, []byte(own), 0o600)
	if _, err := InitUser(e, "codex"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != own {
		t.Fatalf("existing entry rewritten:\n%s", b)
	}
}

func TestInitUserCodexHomeAndUnparsable(t *testing.T) {
	e, _ := fakeEnv(t, "codex")
	ch := t.TempDir()
	e.Getenv = func(k string) string {
		if k == "CODEX_HOME" {
			return ch
		}
		return ""
	}
	os.WriteFile(filepath.Join(ch, "config.toml"), []byte("this is = = not toml"), 0o600)
	if _, err := InitUser(e, "codex"); err == nil {
		t.Fatal("unparsable config accepted")
	}
	if b, _ := os.ReadFile(filepath.Join(ch, "config.toml")); string(b) != "this is = = not toml" {
		t.Fatal("unparsable file rewritten")
	}
}

func TestInitUserFollowsSymlink(t *testing.T) {
	e, _ := fakeEnv(t, "gemini")
	dots := t.TempDir()
	real := filepath.Join(dots, "settings.json")
	os.WriteFile(real, []byte("{\"theme\": \"dark\"}\n"), 0o644)
	os.MkdirAll(filepath.Join(e.Home, ".gemini"), 0o755)
	os.Symlink(real, filepath.Join(e.Home, ".gemini", "settings.json"))
	if _, err := InitUser(e, "gemini"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(real)
	if !strings.Contains(string(b), "\"theme\"") || !strings.Contains(string(b), "locksql") {
		t.Fatalf("settings.json:\n%s", b)
	}
}

func TestInitUserClaude(t *testing.T) {
	e, calls := fakeEnv(t, "claude")
	st := filepath.Join(e.Home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(st), 0o755)
	os.WriteFile(st, []byte("{\"permissions\":{\"allow\":[\"Bash(ls:*)\"]},\"model\":\"opus\"}\n"), 0o644)
	if _, err := InitUser(e, "claude"); err != nil {
		t.Fatal(err)
	}
	want := []string{"claude", "mcp", "add", "--scope", "user", "locksql", "--", "locksql", "mcp"}
	if !slices.ContainsFunc(*calls, func(c []string) bool { return slices.Equal(c, want) }) {
		t.Fatalf("calls %v", *calls)
	}
	var s struct {
		Permissions struct{ Allow []string } `json:"permissions"`
		Model       string                   `json:"model"`
	}
	b, _ := os.ReadFile(st)
	json.Unmarshal(b, &s)
	if s.Model != "opus" || s.Permissions.Allow[0] != "Bash(ls:*)" || !slices.Contains(s.Permissions.Allow, "mcp__locksql__locksql_plan") {
		t.Fatalf("settings.json:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".claude", "skills", "locksql", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if p, _ := PendingUser(e, "claude"); p {
		t.Fatal("still pending")
	}
}

func TestPendingUserWritesNothing(t *testing.T) {
	e, calls := fakeEnv(t, "claude", "codex")
	for _, a := range []string{"claude", "codex", "gemini", "cursor"} {
		if p, err := PendingUser(e, a); err != nil || !p {
			t.Errorf("%s: pending=%v err=%v", a, p, err)
		}
	}
	if entries, _ := os.ReadDir(e.Home); len(entries) != 0 {
		t.Fatalf("PendingUser wrote %v", entries)
	}
	for _, c := range *calls {
		if slices.Contains(c, "add") {
			t.Fatalf("PendingUser ran %v", c)
		}
	}
}

func TestInitUserClaudeAddFails(t *testing.T) {
	e, _ := fakeEnv(t, "claude")
	e.Run = func(n string, a ...string) ([]byte, error) {
		if a[1] == "add" {
			return []byte("\n  boom: config locked  \nmore\n"), errors.New("exit 1")
		}
		return nil, errors.New("exit 1")
	}
	_, err := InitUser(e, "claude")
	if err == nil || err.Error() != "claude mcp add failed: boom: config locked" {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".claude", "settings.json")); err != nil {
		t.Fatalf("files are written before the command: %v", err)
	}
}
