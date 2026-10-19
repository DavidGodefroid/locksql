//go:build unix

package agentinit

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/wired_golden.json")

// wired is what wiring one agent produced: the files, what init reported
// and the commands it ran.
type wired struct {
	Files   map[string]string `json:"files"`
	Actions []Action          `json:"actions"`
	Notes   string            `json:"notes,omitempty"`
	Calls   [][]string        `json:"calls,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// wiredCase wires agent once in a fresh project and a fresh home; prep
// writes files first (into the project for scope "project", the home
// otherwise).
type wiredCase struct {
	name, scope, agent string
	prep               map[string]string
}

var wiredCases = []wiredCase{
	{name: "project claude", scope: "project", agent: "claude"},
	{name: "project codex", scope: "project", agent: "codex"},
	{name: "project cursor", scope: "project", agent: "cursor"},
	{name: "project gemini", scope: "project", agent: "gemini"},
	{name: "project claude merge", scope: "project", agent: "claude", prep: map[string]string{
		".mcp.json": `{"z":1,"mcpServers":{"other":{"command":"x"}},"a":[1]}`}},
	{name: "project claude own entry", scope: "project", agent: "claude", prep: map[string]string{
		".mcp.json": `{"mcpServers":{"locksql":{"command":"mine"}}}`}},
	{name: "project claude bad json", scope: "project", agent: "claude", prep: map[string]string{".mcp.json": `{nope`}},
	{name: "project gemini bad servers", scope: "project", agent: "gemini", prep: map[string]string{".gemini/settings.json": `{"mcpServers":[1]}`}},
	{name: "project codex existing", scope: "project", agent: "codex", prep: map[string]string{"AGENTS.md": "# Mine\nno newline"}},
	{name: "project edited skill", scope: "project", agent: "claude", prep: map[string]string{".claude/skills/locksql/SKILL.md": "mine\n"}},
	{name: "user claude", scope: "user", agent: "claude"},
	{name: "user claude perms", scope: "user", agent: "claude", prep: map[string]string{
		".claude/settings.json": `{"permissions":{"allow":["Bash(ls:*)","mcp__locksql__locksql_plan"],"deny":[]},"x":true}`}},
	{name: "user claude bad perms", scope: "user", agent: "claude", prep: map[string]string{".claude/settings.json": `{"permissions":{"allow":"x"}}`}},
	{name: "user codex", scope: "user", agent: "codex"},
	{name: "user codex existing", scope: "user", agent: "codex", prep: map[string]string{".codex/config.toml": "model = \"o3\"\n[mcp_servers.other]\ncommand = \"x\"\n"}},
	{name: "user codex defined", scope: "user", agent: "codex", prep: map[string]string{".codex/config.toml": "[mcp_servers.locksql]\ncommand = \"y\"\n"}},
	{name: "user codex bad toml", scope: "user", agent: "codex", prep: map[string]string{".codex/config.toml": "[[x"}},
	{name: "user codex inline", scope: "user", agent: "codex", prep: map[string]string{".codex/config.toml": "mcp_servers = { other = { command = \"x\" } }\n"}},
	{name: "user cursor", scope: "user", agent: "cursor"},
	{name: "user gemini", scope: "user", agent: "gemini"},
}

func runWired(t *testing.T, c wiredCase) wired {
	t.Helper()
	var w wired
	var dir string
	if c.scope == "project" {
		dir = sandbox(t)
		prep(t, dir, c.prep)
		res, err := Init(dir, c.agent)
		w.Actions, w.Notes = res.Actions, res.Notes
		if err != nil {
			w.Error = strings.ReplaceAll(err.Error(), dir, "<root>")
		}
	} else {
		e, calls := fakeEnv(t, c.agent)
		dir = e.Home
		prep(t, dir, c.prep)
		res, err := InitUser(e, c.agent)
		w.Actions, w.Notes, w.Calls = res.Actions, res.Notes, *calls
		if err != nil {
			w.Error = strings.ReplaceAll(err.Error(), dir, "<home>")
		}
	}
	w.Files = snapshot(t, dir)
	for k := range c.prep {
		if w.Files[k] == c.prep[k] {
			w.Files[k] = "<as prepared>"
		}
	}
	return w
}

func prep(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		writeFile(t, dir, rel, content)
	}
}

// TestWiredFilesUnchanged pins, byte for byte, what locksql writes for each
// agent, in a project and in the user's home, and what it reports: moving
// the mechanics to lockkit must not change a single file.
func TestWiredFilesUnchanged(t *testing.T) {
	got := map[string]wired{}
	for _, c := range wiredCases {
		got[c.name] = runWired(t, c)
	}
	path := filepath.Join("testdata", "wired_golden.json")
	if *updateGolden {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]wired
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("golden has %d cases, test %d", len(want), len(got))
	}
	for name, g := range got {
		gj, _ := json.MarshalIndent(g, "", "  ")
		wj, _ := json.MarshalIndent(want[name], "", "  ")
		if string(gj) != string(wj) {
			t.Errorf("%s changed:\n got %s\nwant %s", name, gj, wj)
		}
	}
}
