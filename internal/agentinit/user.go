// User scope: wires agents through files under the home directory (and
// `claude mcp add --scope user`). Symlinks are followed: these are the
// human's own files, often managed as dotfiles.
package agentinit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Env is the user account init works on, and how it looks for and runs
// the agents' commands.
type Env struct {
	Home     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
	// Run runs a command and returns its combined output.
	Run func(name string, args ...string) ([]byte, error)
}

// SystemEnv is the current account: its home directory, environment and
// PATH.
func SystemEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{
		Home: home, Getenv: os.Getenv, LookPath: exec.LookPath,
		Run: func(n string, a ...string) ([]byte, error) { return exec.Command(n, a...).CombinedOutput() },
	}, nil
}

// dir is the directory named by envVar when it is set and absolute, else
// def under the home directory.
func (e Env) dir(envVar, def string) string {
	if v := e.Getenv(envVar); v != "" && filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(e.Home, def)
}

func (e Env) has(cmds ...string) bool {
	for _, c := range cmds {
		if _, err := e.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// Detect lists the installed agents, in Agents() order.
func Detect(e Env) []string {
	var out []string
	if e.has("claude") {
		out = append(out, "claude")
	}
	if e.has("codex") || isDir(e.dir("CODEX_HOME", ".codex")) {
		out = append(out, "codex")
	}
	if e.has("cursor", "cursor-agent") || isDir(filepath.Join(e.Home, ".cursor")) {
		out = append(out, "cursor")
	}
	if e.has("gemini") || isDir(filepath.Join(e.Home, ".gemini")) {
		out = append(out, "gemini")
	}
	return out
}

// userBase roots a user-scope step at dir; paths display with ~ under home.
func (e Env) userBase(dir string) base {
	return base{root: dir, contained: false, display: func(rel string) string {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if r, err := filepath.Rel(e.Home, p); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "~/" + filepath.ToSlash(r)
		}
		return p
	}}
}

// claudeAllow are the calls that never touch data without the console's
// approval; run is approved per statement in the console as well.
var claudeAllow = []string{
	"mcp__locksql__locksql_status", "mcp__locksql__locksql_list_tables",
	"mcp__locksql__locksql_describe", "mcp__locksql__locksql_plan",
	"mcp__locksql__locksql_pii_list",
	"Bash(locksql status:*)", "Bash(locksql tables:*)", "Bash(locksql describe:*)", "Bash(locksql plan:*)",
}

type group struct {
	b     base
	steps []func(base) (change, error)
}

func (e Env) groups(agent string) ([]group, error) {
	mcp := map[string]any{"command": "locksql", "args": []string{"mcp"}}
	switch agent {
	case "claude":
		cd := e.dir("CLAUDE_CONFIG_DIR", ".claude")
		return []group{{e.userBase(cd), []func(base) (change, error){
			fileIfAbsent("skills/locksql/SKILL.md", "templates/skill.md"),
			jsonStrings("settings.json", []string{"permissions", "allow"}, claudeAllow),
			claudeMCP(e),
		}}}, nil
	case "codex":
		return []group{{e.userBase(e.dir("CODEX_HOME", ".codex")), []func(base) (change, error){
			tomlTable("config.toml", "mcp_servers.locksql",
				"[mcp_servers.locksql]\ncommand = \"locksql\"\nargs = [\"mcp\"]\n# covers the console's 5 minute approval timeout\ntool_timeout_sec = 600\n"),
			section("AGENTS.md"),
		}}}, nil
	case "cursor":
		return []group{{e.userBase(filepath.Join(e.Home, ".cursor")), []func(base) (change, error){
			mcpEntry("mcp.json", mcp),
		}}}, nil
	case "gemini":
		g := map[string]any{"command": "locksql", "args": []string{"mcp"}, "timeout": 600000}
		return []group{{e.userBase(filepath.Join(e.Home, ".gemini")), []func(base) (change, error){
			mcpEntry("settings.json", g),
			section("GEMINI.md"),
		}}}, nil
	}
	return nil, fmt.Errorf("unknown agent %q (want one of %s)", agent, strings.Join(Agents(), ", "))
}

// InitUser wires agent for the current account, in every project.
func InitUser(e Env, agent string) (Result, error) {
	gs, err := e.groups(agent)
	if err != nil {
		return Result{}, err
	}
	var res Result
	for _, g := range gs {
		acts, _, err := apply(g.b, g.steps, false, e.Run)
		res.Actions = append(res.Actions, acts...)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// PendingUser reports whether InitUser would write or run anything.
func PendingUser(e Env, agent string) (bool, error) {
	gs, err := e.groups(agent)
	if err != nil {
		return false, err
	}
	for _, g := range gs {
		_, pending, err := apply(g.b, g.steps, true, e.Run)
		if err != nil || pending {
			return pending, err
		}
	}
	return false, nil
}

// tomlTable appends block to a TOML file unless key (dotted) is already
// defined, as a table or inline. An unparsable file is an error.
func tomlTable(rel, key, block string) func(base) (change, error) {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		var m map[string]any
		if exists {
			md, err := toml.Decode(string(data), &m)
			if err != nil {
				return change{}, fmt.Errorf("%s: not valid TOML; fix it or add the locksql server by hand", b.display(rel))
			}
			if md.IsDefined(strings.Split(key, ".")...) {
				c.action.Status = StatusUnchanged
				return c, nil
			}
		}
		s := string(data)
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		if s != "" {
			s += "\n"
		}
		c.content = []byte(s + block)
		c.action.Status = StatusCreated
		if exists {
			c.action.Status = StatusUpdated
		}
		return c, nil
	}
}

// jsonStrings adds the missing items to the string array at path in a JSON
// object file, keeping every other key in its place.
func jsonStrings(rel string, path []string, items []string) func(base) (change, error) {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		bad := fmt.Errorf("%s: %s is not an object holding an array of strings; fix it or add the locksql entries by hand", b.display(rel), strings.Join(path, "."))
		var top, parent orderedObject
		if exists && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &top); err != nil {
				return change{}, fmt.Errorf("%s: not a JSON object (%v); fix it or add the locksql entries by hand", b.display(rel), err)
			}
		}
		if raw, ok := top.get(path[0]); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &parent); err != nil {
				return change{}, bad
			}
		}
		var have []string
		if raw, ok := parent.get(path[1]); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &have); err != nil {
				return change{}, bad
			}
		}
		added := false
		for _, it := range items {
			if !slices.Contains(have, it) {
				have, added = append(have, it), true
			}
		}
		if !added {
			c.action.Status = StatusUnchanged
			return c, nil
		}
		arr, err := json.Marshal(have)
		if err != nil {
			return change{}, err
		}
		parent.set(path[1], arr)
		pj, err := json.Marshal(&parent)
		if err != nil {
			return change{}, err
		}
		top.set(path[0], pj)
		out, err := json.MarshalIndent(&top, "", "  ")
		if err != nil {
			return change{}, err
		}
		c.content = append(out, '\n')
		c.action.Status = StatusCreated
		if exists {
			c.action.Status = StatusUpdated
		}
		return c, nil
	}
}

// claudeMCP registers the user-scope MCP server through Claude Code's own
// CLI, which owns ~/.claude.json.
func claudeMCP(e Env) func(base) (change, error) {
	return func(b base) (change, error) {
		c := change{action: Action{Path: `user MCP server "locksql"`}}
		if _, err := e.Run("claude", "mcp", "get", "locksql"); err == nil {
			c.action.Status = StatusUnchanged
			return c, nil
		}
		c.exec = []string{"claude", "mcp", "add", "--scope", "user", "locksql", "--", "locksql", "mcp"}
		c.action.Status = StatusCreated
		return c, nil
	}
}
