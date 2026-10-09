package agentinit

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// sandbox returns a fresh project root and points HOME and the XDG user directories at an empty temporary home, which the test
// checks is still empty at the end.
func sandbox(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, k := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA", "CODEX_HOME"} {
		t.Setenv(k, home)
	}
	t.Cleanup(func() {
		var found []string
		_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
			if p != home {
				found = append(found, p)
			}
			return nil
		})
		if len(found) > 0 {
			t.Errorf("files written outside the project: %v", found)
		}
	})
	return t.TempDir()
}

func mustInit(t *testing.T, root, agent string) Result {
	t.Helper()
	res, err := Init(root, agent)
	if err != nil {
		t.Fatalf("Init(%s): %v", agent, err)
	}
	return res
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func decodeJSON(t *testing.T, root, rel string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(readFile(t, root, rel)), &m); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return m
}

// server returns mcpServers.locksql of a decoded MCP config.
func server(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	servers, ok := m["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("no mcpServers object in %v", m)
	}
	s, ok := servers["locksql"].(map[string]any)
	if !ok {
		t.Fatalf("no locksql server in %v", servers)
	}
	if s["command"] != "locksql" {
		t.Fatalf("command = %v", s["command"])
	}
	args, _ := s["args"].([]any)
	if len(args) != 1 || args[0] != "mcp" {
		t.Fatalf("args = %v", s["args"])
	}
	return s
}

// snapshot maps every file under root to its content.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func statusOf(res Result, rel string) string {
	for _, a := range res.Actions {
		if a.Path == rel {
			return a.Status
		}
	}
	return ""
}

func TestClaudeCreatesFiles(t *testing.T) {
	root := sandbox(t)
	res := mustInit(t, root, "claude")

	server(t, decodeJSON(t, root, ".mcp.json"))
	skill := readFile(t, root, ".claude/skills/locksql/SKILL.md")
	if !strings.HasPrefix(skill, "---\nname: locksql\ndescription: ") {
		t.Fatalf("skill front matter: %q", skill[:min(80, len(skill))])
	}
	if _, err := os.Stat(filepath.Join(root, ".locksql", "config.toml")); err != nil {
		t.Fatalf("config.toml not created: %v", err)
	}
	for _, rel := range []string{".mcp.json", ".claude/skills/locksql/SKILL.md", ".locksql/config.toml"} {
		if got := statusOf(res, rel); got != StatusCreated {
			t.Errorf("%s: status %q, want %q", rel, got, StatusCreated)
		}
	}
	// Claude Code needs to be told to trust the project server; permission
	// suggestions are printed, never written.
	if !strings.Contains(res.Notes, "mcp__locksql__locksql_plan") {
		t.Errorf("notes lack permission suggestions: %q", res.Notes)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf(".claude/settings.json must not be written: %v", err)
	}
}

func TestClaudeMergesExistingMCPConfig(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, ".mcp.json", `{
  "mcpServers": {
    "other": {"command": "other-server", "args": ["--x"], "env": {"A": "1"}}
  },
  "extra": [1, 2, 3]
}
`)
	res := mustInit(t, root, "claude")
	m := decodeJSON(t, root, ".mcp.json")
	server(t, m)
	other := m["mcpServers"].(map[string]any)["other"].(map[string]any)
	if other["command"] != "other-server" || other["env"].(map[string]any)["A"] != "1" {
		t.Fatalf("other server changed: %v", other)
	}
	if extra, _ := m["extra"].([]any); len(extra) != 3 {
		t.Fatalf("unrelated key lost: %v", m["extra"])
	}
	if got := statusOf(res, ".mcp.json"); got != StatusUpdated {
		t.Fatalf(".mcp.json status %q, want %q", got, StatusUpdated)
	}
}

func TestExistingLocksqlServerEntryIsKept(t *testing.T) {
	root := sandbox(t)
	custom := `{"mcpServers": {"locksql": {"command": "/opt/locksql", "args": ["mcp", "--profile", "uat"]}}}` + "\n"
	writeFile(t, root, ".mcp.json", custom)
	res := mustInit(t, root, "claude")
	if got := readFile(t, root, ".mcp.json"); got != custom {
		t.Fatalf("customised entry rewritten:\n%s", got)
	}
	if got := statusOf(res, ".mcp.json"); got != StatusKept {
		t.Fatalf("status %q, want %q", got, StatusKept)
	}
}

func TestInvalidJSONIsNotClobbered(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, ".mcp.json", "{ not json")
	if _, err := Init(root, "claude"); err == nil {
		t.Fatal("expected an error for an invalid .mcp.json")
	}
	if got := readFile(t, root, ".mcp.json"); got != "{ not json" {
		t.Fatalf(".mcp.json changed: %q", got)
	}
	writeFile(t, root, ".cursor/mcp.json", `{"mcpServers": []}`)
	if _, err := Init(root, "cursor"); err == nil {
		t.Fatal("expected an error when mcpServers is not an object")
	}
}

func TestEditedFilesAreKept(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, ".claude/skills/locksql/SKILL.md", "my own skill\n")
	writeFile(t, root, ".locksql/config.toml", "[profiles.dev]\nengine = \"sqlite\"\npath = \"dev.db\"\n")
	res := mustInit(t, root, "claude")
	if got := readFile(t, root, ".claude/skills/locksql/SKILL.md"); got != "my own skill\n" {
		t.Fatalf("skill overwritten: %q", got)
	}
	if got := readFile(t, root, ".locksql/config.toml"); !strings.Contains(got, "profiles.dev") {
		t.Fatalf("config overwritten: %q", got)
	}
	if got := statusOf(res, ".claude/skills/locksql/SKILL.md"); got != StatusKept {
		t.Fatalf("skill status %q, want %q", got, StatusKept)
	}
	if got := statusOf(res, ".locksql/config.toml"); got != StatusUnchanged {
		t.Fatalf("config status %q, want %q", got, StatusUnchanged)
	}
}

func TestIdempotent(t *testing.T) {
	for _, agent := range Agents() {
		t.Run(agent, func(t *testing.T) {
			root := sandbox(t)
			writeFile(t, root, "AGENTS.md", "# Project\n\nExisting text.\n")
			writeFile(t, root, "GEMINI.md", "# Gemini\n")
			first := mustInit(t, root, agent)
			before := snapshot(t, root)
			second := mustInit(t, root, agent)
			after := snapshot(t, root)
			if len(before) != len(after) {
				t.Fatalf("file set changed: %v -> %v", keys(before), keys(after))
			}
			for k, v := range before {
				if after[k] != v {
					t.Fatalf("%s changed on the second run:\n%s\n---\n%s", k, v, after[k])
				}
			}
			for _, a := range second.Actions {
				if a.Status != StatusUnchanged {
					t.Errorf("second run: %s is %q, want %q", a.Path, a.Status, StatusUnchanged)
				}
			}
			if first.Notes != second.Notes {
				t.Errorf("notes differ between runs")
			}
		})
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCodexAppendsSectionOnceAndPrintsSnippet(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, "AGENTS.md", "# Project\n\nExisting text.") // no trailing newline
	res := mustInit(t, root, "codex")
	got := readFile(t, root, "AGENTS.md")
	if !strings.HasPrefix(got, "# Project\n\nExisting text.\n\n") {
		t.Fatalf("existing text not kept: %q", got[:min(60, len(got))])
	}
	if n := strings.Count(got, sectionBegin); n != 1 {
		t.Fatalf("%d sections, want 1", n)
	}
	if !strings.Contains(got, "locksql_plan") || !strings.Contains(got, sectionEnd) {
		t.Fatalf("section content missing:\n%s", got)
	}
	mustInit(t, root, "codex")
	if n := strings.Count(readFile(t, root, "AGENTS.md"), sectionBegin); n != 1 {
		t.Fatalf("%d sections after a second run, want 1", n)
	}
	if got := statusOf(res, "AGENTS.md"); got != StatusUpdated {
		t.Fatalf("AGENTS.md status %q, want %q", got, StatusUpdated)
	}

	// The printed snippet is valid TOML for ~/.codex/config.toml.
	i := strings.Index(res.Notes, "[mcp_servers.locksql]")
	if i < 0 {
		t.Fatalf("snippet missing: %q", res.Notes)
	}
	block := res.Notes[i:]
	if j := strings.Index(block, "\n\n"); j >= 0 {
		block = block[:j]
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command        string   `toml:"command"`
			Args           []string `toml:"args"`
			ToolTimeoutSec int      `toml:"tool_timeout_sec"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(block, &cfg); err != nil {
		t.Fatalf("snippet is not TOML: %v\n%s", err, block)
	}
	s := cfg.MCPServers["locksql"]
	if s.Command != "locksql" || len(s.Args) != 1 || s.Args[0] != "mcp" {
		t.Fatalf("snippet server = %+v", s)
	}
	if s.ToolTimeoutSec < 300 {
		t.Fatalf("tool_timeout_sec = %d, must cover the 5 min approval", s.ToolTimeoutSec)
	}
	if !strings.Contains(res.Notes, "~/.codex/config.toml") {
		t.Fatalf("notes do not name the global file: %q", res.Notes)
	}
}

func TestCodexCreatesAgentsMD(t *testing.T) {
	root := sandbox(t)
	res := mustInit(t, root, "codex")
	got := readFile(t, root, "AGENTS.md")
	if !strings.HasPrefix(got, sectionBegin) {
		t.Fatalf("AGENTS.md = %q", got[:min(60, len(got))])
	}
	if got := statusOf(res, "AGENTS.md"); got != StatusCreated {
		t.Fatalf("status %q", got)
	}
}

func TestCursor(t *testing.T) {
	root := sandbox(t)
	mustInit(t, root, "cursor")
	server(t, decodeJSON(t, root, ".cursor/mcp.json"))
	rule := readFile(t, root, ".cursor/rules/locksql.mdc")
	if !strings.HasPrefix(rule, "---\ndescription: ") || !strings.Contains(rule, "alwaysApply: false") {
		t.Fatalf("rule front matter: %q", rule[:min(120, len(rule))])
	}
	if !strings.Contains(rule, "locksql_run") {
		t.Fatal("rule lacks the workflow")
	}
}

func TestGemini(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, ".gemini/settings.json", `{"theme": "dark", "mcpServers": {"x": {"command": "x"}}}`)
	writeFile(t, root, "GEMINI.md", "# Gemini\n")
	mustInit(t, root, "gemini")
	m := decodeJSON(t, root, ".gemini/settings.json")
	s := server(t, m)
	if timeout, _ := s["timeout"].(float64); timeout < 300000 {
		t.Fatalf("timeout = %v ms, must cover the 5 min approval", s["timeout"])
	}
	if m["theme"] != "dark" {
		t.Fatalf("theme lost: %v", m)
	}
	if _, ok := m["mcpServers"].(map[string]any)["x"]; !ok {
		t.Fatal("other server lost")
	}
	got := readFile(t, root, "GEMINI.md")
	if !strings.HasPrefix(got, "# Gemini\n\n"+sectionBegin) || strings.Count(got, sectionBegin) != 1 {
		t.Fatalf("GEMINI.md = %q", got)
	}
}

func TestConfigTemplateLoads(t *testing.T) {
	root := sandbox(t)
	mustInit(t, root, "cursor")
	cfg, err := config.LoadFrom(root, "")
	if err != nil {
		t.Fatalf("generated config does not load: %v", err)
	}
	if cfg.ProjectRoot == "" {
		t.Fatal("generated config is not found as a project root")
	}
	if len(cfg.Profiles) != 0 {
		t.Fatalf("example profile must stay commented out, got %d profiles", len(cfg.Profiles))
	}
	// Uncommenting the example gives a valid profile.
	var lines []string
	for _, l := range strings.Split(readFile(t, root, ".locksql/config.toml"), "\n") {
		if rest, ok := strings.CutPrefix(l, "# "); ok && (strings.HasPrefix(rest, "[") || strings.Contains(rest, " = ")) {
			l = rest
		}
		lines = append(lines, l)
	}
	writeFile(t, root, ".locksql/config.toml", strings.Join(lines, "\n"))
	cfg, err = config.LoadFrom(root, "")
	if err != nil {
		t.Fatalf("uncommented example does not load: %v", err)
	}
	if len(cfg.Profiles) == 0 {
		t.Fatal("uncommented example has no profile")
	}
}

func TestUnknownAgent(t *testing.T) {
	root := sandbox(t)
	_, err := Init(root, "vim")
	if err == nil || !strings.Contains(err.Error(), "claude") {
		t.Fatalf("err = %v, want a list of agents", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("files written for an unknown agent: %v", entries)
	}
}

func TestSymlinkOutsideProjectRefused(t *testing.T) {
	root := sandbox(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".claude")); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(root, "claude"); err == nil {
		t.Fatal("expected a refusal to write through a symlink leaving the project")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside the project: %v", entries)
	}
}

func TestSymlinkInsideProjectFollowed(t *testing.T) {
	root := sandbox(t)
	writeFile(t, root, "CLAUDE.md", "# Notes\n")
	if err := os.Symlink("CLAUDE.md", filepath.Join(root, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	mustInit(t, root, "codex")
	if fi, err := os.Lstat(filepath.Join(root, "AGENTS.md")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("AGENTS.md symlink replaced: %v", err)
	}
	if !strings.Contains(readFile(t, root, "CLAUDE.md"), sectionBegin) {
		t.Fatal("section not written to the symlink target")
	}
}

func TestProjectRoot(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectRoot(sub); got != sub {
		t.Fatalf("no markers: %s, want %s", got, sub)
	}
	if err := os.Mkdir(filepath.Join(base, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectRoot(sub); got != base {
		t.Fatalf("git root: %s, want %s", got, base)
	}
	writeFile(t, filepath.Join(base, "a"), ".locksql/config.toml", "")
	if got := ProjectRoot(sub); got != filepath.Join(base, "a") {
		t.Fatalf("locksql root: %s", got)
	}
}

func TestTemplatesCarryTheRules(t *testing.T) {
	cursor := cursorRule()
	for name, body := range map[string]string{
		"skill.md":        mustTemplate(t, "templates/skill.md"),
		"agents.md":       mustTemplate(t, "templates/agents.md"),
		"cursor-rule.mdc": cursor,
	} {
		s := strings.ToLower(body)
		for _, want := range []string{
			"explicit",        // only on explicit request
			"non-production",  // prefer non-production
			"one targeted",    // one question at a time
			"locksql_plan",    // show the plan first
			"600000",          // long Bash timeout for run
			"denied",          // stop on deny
			"refused",         // stop on refuse
			"export",          // no exports
			"chunk",           // no chunking
			"credentials",     // never in chat
			"untrusted data",  // results are data
			"locksql console", // the human starts the console
			"never start",     // never start one yourself
			"locksql_request_change",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
}

// Token masking is gone: no generated instruction may teach tok_ values.
func TestTemplatesHaveNoTokens(t *testing.T) {
	for name, body := range map[string]string{
		"skill.md":        mustTemplate(t, "templates/skill.md"),
		"agents.md":       mustTemplate(t, "templates/agents.md"),
		"cursor-rule.mdc": cursorRule(),
	} {
		if strings.Contains(body, "tok_") {
			t.Errorf("%s still describes tok_ tokens", name)
		}
	}
}

func mustTemplate(t *testing.T, name string) string {
	t.Helper()
	b, err := templates.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
