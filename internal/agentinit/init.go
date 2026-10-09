// Package agentinit implements `locksql init <agent>`: it writes the files
// that connect a coding agent to locksql inside one project, and prints the
// steps for any file outside it.
//
// Init writes project files only. It never overwrites a file the human may
// have edited: an existing skill or rule is kept, an MCP config gets the
// locksql entry merged in (other servers and keys are kept), and a Markdown
// instructions file gets one marked section appended. Running it again
// changes nothing. Every path is resolved through symlinks and refused if it
// leaves the project.
package agentinit

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/config"
)

//go:embed templates
var templates embed.FS

// Action statuses.
const (
	StatusCreated   = "created"   // the file did not exist
	StatusUpdated   = "updated"   // locksql was merged into an existing file
	StatusUnchanged = "unchanged" // the file already holds the locksql content
	StatusKept      = "kept"      // the file differs and was left as the human wrote it
)

// Markers around the section appended to AGENTS.md and GEMINI.md.
const (
	sectionBegin = "<!-- locksql:begin -->"
	sectionEnd   = "<!-- locksql:end -->"
)

// Action reports what Init did to one file.
type Action struct {
	Path   string // slash-separated, relative to the project root (or ~/... in the user scope)
	Status string
	Detail string // why a file was kept, when it was
}

// Result is the outcome of Init.
type Result struct {
	Root    string
	Actions []Action
	Notes   string // agent-specific steps for the human, such as a global file to edit
}

// Agents returns the supported agent names.
func Agents() []string { return []string{"claude", "codex", "cursor", "gemini"} }

// ProjectRoot returns the directory init writes to: the nearest ancestor of
// cwd holding .locksql/config.toml, else the nearest one holding .git, else
// cwd itself.
func ProjectRoot(cwd string) string {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = filepath.Clean(cwd)
	}
	if root, ok := config.FindProjectRoot(abs); ok {
		return root
	}
	for dir := abs; ; {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs
		}
		dir = parent
	}
}

// base is where a set of steps writes: a root directory, whether every
// path must stay inside it, and how a relative path is shown to the human.
type base struct {
	root      string
	contained bool
	display   func(rel string) string
}

// change is one planned file write, or one command to run.
type change struct {
	rel     string
	target  string // resolved absolute path
	content []byte // nil when nothing is written
	mode    fs.FileMode
	exec    []string // a command apply runs after the file writes, instead of writing a file
	action  Action
}

// Init writes the integration files of agent into the project at root.
// Every change is computed and checked before the first write, so an
// invalid existing file or an escaping symlink leaves the project untouched.
func Init(root, agent string) (Result, error) {
	var steps []func(base) (change, error)
	var notes string
	switch agent {
	case "claude":
		steps = []func(base) (change, error){
			mcpEntry(".mcp.json", map[string]any{"type": "stdio", "command": "locksql", "args": []string{"mcp"}}),
			fileIfAbsent(".claude/skills/locksql/SKILL.md", "templates/skill.md"),
		}
		notes = claudeNotes
	case "codex":
		steps = []func(base) (change, error){section("AGENTS.md")}
		notes = codexNotes
	case "cursor":
		steps = []func(base) (change, error){
			mcpEntry(".cursor/mcp.json", map[string]any{"command": "locksql", "args": []string{"mcp"}}),
			cursorRuleFile(".cursor/rules/locksql.mdc"),
		}
		notes = cursorNotes
	case "gemini":
		steps = []func(base) (change, error){
			// Gemini CLI's timeout is in milliseconds; it must cover the
			// console's 5 minute approval timeout.
			mcpEntry(".gemini/settings.json", map[string]any{"command": "locksql", "args": []string{"mcp"}, "timeout": 600000}),
			section("GEMINI.md"),
		}
	default:
		return Result{}, fmt.Errorf("unknown agent %q (want one of %s)", agent, strings.Join(Agents(), ", "))
	}
	steps = append(steps, configIfAbsent(".locksql/config.toml"))

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Result{}, fmt.Errorf("project root: %w", err)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return Result{}, fmt.Errorf("project root: %w", err)
	}
	b := base{root: realRoot, contained: true, display: func(r string) string { return r }}
	acts, _, err := apply(b, steps, false, nil)
	if err != nil && acts == nil { // a step failed: nothing was written
		return Result{}, err
	}
	return Result{Root: root, Actions: acts, Notes: notes}, err
}

// apply computes every change of steps, then, unless dry, writes the files
// and runs the commands, in that order. It returns the actions and whether
// anything would be (or was) written or run. A step error leaves everything
// untouched; after a write or command error, the actions of the changes
// already made are returned with it.
func apply(b base, steps []func(base) (change, error), dry bool, run func(string, ...string) ([]byte, error)) ([]Action, bool, error) {
	changes := make([]change, 0, len(steps))
	pending := false
	for _, step := range steps {
		c, err := step(b)
		if err != nil {
			return nil, false, err
		}
		if c.content != nil || c.exec != nil {
			pending = true
		}
		if c.content != nil && !b.contained {
			// The user scope writes into the human's own dotfiles: never
			// replace a file of another account, which a rename in a
			// writable directory would do.
			if err := writable(c.target, b.display(c.rel)); err != nil {
				return nil, false, err
			}
		}
		changes = append(changes, c)
	}
	if dry {
		acts := make([]Action, 0, len(changes))
		for _, c := range changes {
			acts = append(acts, c.action)
		}
		return acts, pending, nil
	}

	done := make([]bool, len(changes))
	made := func() []Action {
		acts := []Action{}
		for i, c := range changes {
			if done[i] {
				acts = append(acts, c.action)
			}
		}
		return acts
	}
	for i, c := range changes {
		if c.exec != nil {
			continue
		}
		if c.content != nil {
			if err := writeAtomic(c.target, c.content, c.mode); err != nil {
				return made(), pending, fmt.Errorf("%s: %w", b.display(c.rel), err)
			}
		}
		done[i] = true
	}
	for i, c := range changes {
		if c.exec == nil {
			continue
		}
		if out, err := run(c.exec[0], c.exec[1:]...); err != nil {
			msg := firstLine(out)
			if msg == "" {
				msg = err.Error()
			}
			return made(), pending, fmt.Errorf("%s failed: %s", strings.Join(c.exec[:min(3, len(c.exec))], " "), msg)
		}
		done[i] = true
	}
	return made(), pending, nil
}

// ansiRe matches terminal escape sequences (CSI and OSC).
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-_])`)

// firstLine returns the first non-empty line of out, without escape
// sequences or control characters, cut to at most 200 bytes on a rune
// boundary. It relays another program's output to the human's terminal.
func firstLine(out []byte) string {
	clean := ansiRe.ReplaceAllString(strings.ToValidUTF8(string(out), ""), "")
	for _, l := range strings.Split(clean, "\n") {
		l = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return -1
			}
			return r
		}, l)
		if l = strings.TrimSpace(l); l != "" {
			for len(l) > 200 {
				_, size := utf8.DecodeLastRuneInString(l)
				l = l[:len(l)-size]
			}
			return l
		}
	}
	return ""
}

// resolve maps rel to an absolute path under b.root, following symlinks of
// every existing component. When b is contained, a path that leaves the
// root is refused.
func resolve(b base, rel string) (string, error) {
	p := filepath.Join(b.root, filepath.FromSlash(rel))
	existing, rest := p, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s: %w", rel, err)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("%s: no existing ancestor", rel)
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	real, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("%s: %w", rel, err)
	}
	target := filepath.Join(real, rest)
	if !b.contained {
		return target, nil
	}
	r, err := filepath.Rel(b.root, target)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", fmt.Errorf("%s: resolves outside the project (%s); refusing to write there", rel, target)
	}
	return target, nil
}

// read resolves rel and returns its content, or nil when it does not exist.
func read(b base, rel string) (target string, data []byte, mode fs.FileMode, exists bool, err error) {
	target, err = resolve(b, rel)
	if err != nil {
		return "", nil, 0, false, err
	}
	st, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return target, nil, 0o644, false, nil
	}
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("%s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		return "", nil, 0, false, fmt.Errorf("%s: not a regular file", rel)
	}
	data, err = os.ReadFile(target)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("%s: %w", rel, err)
	}
	return target, data, st.Mode().Perm(), true, nil
}

func template(name string) []byte {
	b, err := templates.ReadFile(name)
	if err != nil {
		panic("agentinit: missing embedded template " + name)
	}
	return b
}

// fileIfAbsent creates rel from a template. An existing file is unchanged
// when it already matches, and kept otherwise.
func fileIfAbsent(rel, tmpl string) func(base) (change, error) {
	return func(b base) (change, error) {
		return plainFile(b, rel, template(tmpl))
	}
}

func cursorRuleFile(rel string) func(base) (change, error) {
	return func(b base) (change, error) {
		return plainFile(b, rel, []byte(cursorRule()))
	}
}

func plainFile(b base, rel string, want []byte) (change, error) {
	target, data, mode, exists, err := read(b, rel)
	if err != nil {
		return change{}, err
	}
	c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
	switch {
	case !exists:
		c.content, c.action.Status = want, StatusCreated
	case bytes.Equal(data, want):
		c.action.Status = StatusUnchanged
	default:
		c.action.Status = StatusKept
		c.action.Detail = "differs from the template; delete it and run init again to regenerate it"
	}
	return c, nil
}

// cursorRule is the Cursor rule: its front matter plus the shared
// instructions.
func cursorRule() string {
	return string(template("templates/cursor-rule.mdc")) + string(template("templates/agents.md"))
}

// configIfAbsent creates the commented example project config. Any existing
// config is the human's and is left alone.
func configIfAbsent(rel string) func(base) (change, error) {
	return func(b base) (change, error) {
		target, _, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel), Status: StatusUnchanged}}
		if !exists {
			c.content, c.action.Status = template("templates/config.toml"), StatusCreated
		}
		return c, nil
	}
}

// section appends the shared instructions to a Markdown file, once,
// between markers.
func section(rel string) func(base) (change, error) {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		block := sectionBegin + "\n" + string(template("templates/agents.md")) + sectionEnd + "\n"
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		switch {
		case !exists || len(bytes.TrimSpace(data)) == 0:
			c.content, c.action.Status = []byte(block), StatusCreated
			if exists {
				c.action.Status = StatusUpdated
			}
		case bytes.Contains(data, []byte(sectionBegin)):
			c.action.Status = StatusUnchanged
		default:
			s := string(data)
			if !strings.HasSuffix(s, "\n") {
				s += "\n"
			}
			c.content, c.action.Status = []byte(s+"\n"+block), StatusUpdated
		}
		return c, nil
	}
}

// mcpEntry merges mcpServers.locksql into a JSON MCP config, keeping every
// other key in its place. An existing locksql entry is never replaced.
func mcpEntry(rel string, entry map[string]any) func(base) (change, error) {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			return change{}, err
		}
		var top orderedObject
		if exists && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &top); err != nil {
				return change{}, fmt.Errorf("%s: not a JSON object (%v); fix it or add the locksql server by hand", b.display(rel), err)
			}
		}
		var servers orderedObject
		if raw, ok := top.get("mcpServers"); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &servers); err != nil {
				return change{}, fmt.Errorf("%s: mcpServers is not a JSON object; fix it or add the locksql server by hand", b.display(rel))
			}
		}
		if cur, ok := servers.get("locksql"); ok {
			if jsonEqual(cur, entryJSON) {
				c.action.Status = StatusUnchanged
			} else {
				c.action.Status = StatusKept
				c.action.Detail = "already has a locksql server entry of its own"
			}
			return c, nil
		}
		servers.set("locksql", entryJSON)
		sj, err := json.Marshal(&servers)
		if err != nil {
			return change{}, err
		}
		top.set("mcpServers", sj)
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

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// orderedObject is a JSON object that keeps its key order.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func (o *orderedObject) get(k string) (json.RawMessage, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *orderedObject) set(k string, v json.RawMessage) {
	if o.vals == nil {
		o.vals = map[string]json.RawMessage{}
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedObject) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("expected an object")
	}
	*o = orderedObject{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("expected an object key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		o.set(key, v)
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data after the object")
	}
	return nil
}

func (o *orderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory, so a crash never leaves a half-written config.
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".locksql-init-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

const claudeNotes = `Claude Code asks once whether to use the project MCP server "locksql"; approve it.
Optional: the calls below never touch data without the console's approval. To stop
Claude Code prompting for them, add them to "permissions.allow" in
.claude/settings.local.json (personal) or .claude/settings.json (shared):

  "mcp__locksql__locksql_status",
  "mcp__locksql__locksql_list_tables",
  "mcp__locksql__locksql_describe",
  "mcp__locksql__locksql_plan",
  "mcp__locksql__locksql_pii_list",
  "Bash(locksql status:*)",
  "Bash(locksql tables:*)",
  "Bash(locksql describe:*)",
  "Bash(locksql plan:*)"

"mcp__locksql__locksql_run" and "Bash(locksql run:*)" may be added too: every run
is still approved by the human in the console.

`

const codexNotes = `locksql init writes no file outside the project. To give Codex the MCP tools,
add this to ~/.codex/config.toml (tool_timeout_sec covers the console's
5 minute approval timeout):

[mcp_servers.locksql]
command = "locksql"
args = ["mcp"]
tool_timeout_sec = 600

`

const cursorNotes = `Enable the "locksql" server in Cursor's MCP settings if Cursor asks.

`
