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
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

func fakeEnv(t *testing.T, onPath ...string) (Env, *[][]string) {
	t.Helper()
	home := t.TempDir()
	var calls [][]string
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
			if len(a) >= 2 && a[0] == "mcp" && a[1] == "add" {
				// What Claude Code does: a top-level user-scope entry.
				err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"locksql":{"type":"stdio","command":"locksql","args":["mcp"]}}}`), 0o600)
				return nil, err
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
	if st, err := os.Lstat(filepath.Join(e.Home, ".gemini", "settings.json")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
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
	n := len(*calls)
	if p, _ := PendingUser(e, "claude"); p {
		t.Fatal("still pending")
	}
	if len(*calls) != n {
		t.Fatalf("PendingUser ran %v", (*calls)[n:])
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
	if len(*calls) != 0 {
		t.Fatalf("PendingUser ran %v", *calls)
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

func TestClaudeProjectEntryIsNotUserScope(t *testing.T) {
	e, calls := fakeEnv(t, "claude")
	cj := filepath.Join(e.Home, ".claude.json")
	own := `{"projects":{"/x":{"mcpServers":{"locksql":{}}}}}`
	os.WriteFile(cj, []byte(own), 0o600)
	if p, err := PendingUser(e, "claude"); err != nil || !p {
		t.Fatalf("pending=%v err=%v", p, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("PendingUser ran %v", *calls)
	}
	if b, _ := os.ReadFile(cj); string(b) != own {
		t.Fatalf(".claude.json written:\n%s", b)
	}
}

func TestClaudeJSONUnderClaudeConfigDir(t *testing.T) {
	e, _ := fakeEnv(t, "claude")
	cd := t.TempDir()
	e.Getenv = func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return cd
		}
		return ""
	}
	// The entry in the home directory is not the one Claude Code reads.
	os.WriteFile(filepath.Join(e.Home, ".claude.json"), []byte(`{"mcpServers":{"locksql":{}}}`), 0o600)
	os.WriteFile(filepath.Join(cd, "settings.json"), []byte(`{"permissions":{"allow":`+string(mustJSON(t, claudeAllow))+`}}`), 0o600)
	os.MkdirAll(filepath.Join(cd, "skills", "locksql"), 0o755)
	os.WriteFile(filepath.Join(cd, "skills", "locksql", "SKILL.md"), mustTemplateBytes(t, "templates/skill.md"), 0o644)
	if p, _ := PendingUser(e, "claude"); !p {
		t.Fatal("home .claude.json counted under CLAUDE_CONFIG_DIR")
	}
	os.WriteFile(filepath.Join(cd, ".claude.json"), []byte(`{"mcpServers":{"locksql":{}}}`), 0o600)
	if p, err := PendingUser(e, "claude"); err != nil || p {
		t.Fatalf("pending=%v err=%v", p, err)
	}
}

func TestClaudeJSONUnparsableIsNotWired(t *testing.T) {
	e, calls := fakeEnv(t, "claude")
	cj := filepath.Join(e.Home, ".claude.json")
	os.WriteFile(cj, []byte("{not json"), 0o600)
	if p, err := PendingUser(e, "claude"); err != nil || !p {
		t.Fatalf("pending=%v err=%v", p, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("PendingUser ran %v", *calls)
	}
}

func TestInitUserCodexInlineMCPServers(t *testing.T) {
	e, _ := fakeEnv(t, "codex")
	cfg := filepath.Join(e.Home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	own := "mcp_servers = { other = { command = \"x\" } }\n"
	os.WriteFile(cfg, []byte(own), 0o600)
	_, err := InitUser(e, "codex")
	if err == nil || !strings.Contains(err.Error(), "~/.codex/config.toml") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != own {
		t.Fatalf("config.toml rewritten:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".codex", "AGENTS.md")); err == nil {
		t.Fatal("AGENTS.md written despite the error")
	}
}

func TestSystemRunTimesOut(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep command")
	}
	_, err := runWithTimeout(50*time.Millisecond, time.Second)("sleep", "5")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustTemplateBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := templates.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAssignsPrefix(t *testing.T) {
	for doc, want := range map[string]bool{
		"mcp_servers = { other = { command = \"x\" } }\n": true,
		"  \"mcp_servers\" = {}\n":                        true,
		"mcp_servers = 3\n":                               true,
		"mcp_servers.other = { command = \"x\" }\n":       false,
		"[mcp_servers.other]\ncommand = \"x\"\n":          false,
		"[x]\nmcp_servers = {}\n":                         false,
		"model = \"o3\"\n":                                false,
	} {
		if got := assignsPrefix([]byte(doc), "mcp_servers.locksql"); got != want {
			t.Errorf("%q: got %v", doc, got)
		}
	}
}

// A wired Claude (user MCP entry and skill) is left alone: a permission the
// human removed is not added back.
func TestClaudeWiredKeepsRemovedPermission(t *testing.T) {
	e, calls := fakeEnv(t, "claude")
	os.WriteFile(filepath.Join(e.Home, ".claude.json"), []byte(`{"mcpServers":{"locksql":{}}}`), 0o600)
	skill := filepath.Join(e.Home, ".claude", "skills", "locksql", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	os.WriteFile(skill, []byte("my own skill\n"), 0o644)
	st := filepath.Join(e.Home, ".claude", "settings.json")
	own := `{"permissions":{"allow":["mcp__locksql__locksql_status"]}}`
	os.WriteFile(st, []byte(own), 0o644)
	if p, err := PendingUser(e, "claude"); err != nil || p {
		t.Fatalf("pending=%v err=%v", p, err)
	}
	res, err := InitUser(e, "claude")
	if err != nil || len(res.Actions) != 0 {
		t.Fatalf("InitUser on a wired claude: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(st); string(b) != own {
		t.Fatalf("settings.json rewritten:\n%s", b)
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %v", *calls)
	}
	// Without the skill, Claude is wired again, permissions included.
	os.Remove(skill)
	if p, _ := PendingUser(e, "claude"); !p {
		t.Fatal("not pending without the skill")
	}
	if _, err := InitUser(e, "claude"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(st); !strings.Contains(string(b), "mcp__locksql__locksql_plan") {
		t.Fatalf("permissions not merged on a wiring run:\n%s", b)
	}
}

func TestInitUserRefusesReadOnlyFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write a 0444 file")
	}
	e, _ := fakeEnv(t, "codex")
	cfg := filepath.Join(e.Home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	own := "model = \"o3\"\n"
	os.WriteFile(cfg, []byte(own), 0o444)
	_, err := InitUser(e, "codex")
	if err == nil || !strings.Contains(err.Error(), "~/.codex/config.toml") || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != own {
		t.Fatalf("read-only file replaced:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".codex", "AGENTS.md")); err == nil {
		t.Fatal("AGENTS.md written despite the refusal")
	}
	// An unchanged read-only file is fine.
	os.Chmod(cfg, 0o644)
	if _, err := InitUser(e, "codex"); err != nil {
		t.Fatal(err)
	}
	os.Chmod(cfg, 0o444)
	if p, err := PendingUser(e, "codex"); err != nil || p {
		t.Fatalf("wired codex with a read-only config: pending=%v err=%v", p, err)
	}
}

func TestInitUserRefusesReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write a 0555 directory")
	}
	e, _ := fakeEnv(t, "gemini")
	dir := filepath.Join(e.Home, ".gemini")
	os.MkdirAll(dir, 0o555)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	_, err := InitUser(e, "gemini")
	if err == nil || !strings.Contains(err.Error(), "~/.gemini/settings.json") || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("bare system error: %v", err)
	}
}

func TestFirstLineSanitises(t *testing.T) {
	got := firstLine([]byte("\n\x1b[31mError:\x1b[0m bad\x07 thing\r\nmore"))
	if got != "Error: bad thing" {
		t.Fatalf("firstLine = %q", got)
	}
	long := strings.Repeat("é", 150) // 300 bytes
	got = firstLine([]byte(long))
	if len(got) > 200 || !utf8.ValidString(got) {
		t.Fatalf("cut: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

func TestSystemRunBoundWithGrandchild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	start := time.Now()
	// The grandchild keeps the output pipe open after sh is killed.
	_, err := runWithTimeout(50*time.Millisecond, 100*time.Millisecond)("sh", "-c", "sleep 10 & sleep 10")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}
