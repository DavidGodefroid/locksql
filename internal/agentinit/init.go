// Package agentinit implements `locksql init <agent>` and the user-scope
// wiring of bare `locksql` and `locksql doctor --fix`: it holds locksql's
// texts (templates/) and wires them through lockkit's agentwire, which owns
// the file mechanics.
//
// Init writes project files only. It never overwrites a file the human may
// have edited: an existing skill or rule is kept, an MCP config gets the
// locksql entry merged in (other servers and keys are kept), and a Markdown
// instructions file gets one marked section appended. Running it again
// changes nothing. Every path is resolved through symlinks and refused if it
// leaves the project.
package agentinit

import (
	"embed"

	"github.com/DavidGodefroid/lockkit/agentwire"

	"github.com/DavidGodefroid/locksql/internal/product"
)

//go:embed templates
var templates embed.FS

// Action statuses.
const (
	StatusCreated   = agentwire.StatusCreated
	StatusUpdated   = agentwire.StatusUpdated
	StatusUnchanged = agentwire.StatusUnchanged
	StatusKept      = agentwire.StatusKept
)

// Markers around the section appended to AGENTS.md and GEMINI.md.
const (
	sectionBegin = "<!-- locksql:begin -->"
	sectionEnd   = "<!-- locksql:end -->"
)

type (
	// Action reports what Init did to one file.
	Action = agentwire.Action
	// Result is the outcome of Init.
	Result = agentwire.Result
)

// claudeAllow are the calls that never touch data without the console's
// approval; run is approved per statement in the console as well.
var claudeAllow = []string{
	"mcp__locksql__locksql_status", "mcp__locksql__locksql_list_tables",
	"mcp__locksql__locksql_describe", "mcp__locksql__locksql_plan",
	"mcp__locksql__locksql_pii_list",
	"Bash(locksql status:*)", "Bash(locksql tables:*)", "Bash(locksql describe:*)", "Bash(locksql plan:*)",
}

// wiring is locksql's agentwire: its MCP command and texts.
var wiring = agentwire.Wiring{Product: product.P, Assets: agentwire.Assets{
	MCPCommand:        []string{"locksql", "mcp"},
	Skill:             template("templates/skill.md"),
	Instructions:      template("templates/agents.md"),
	CursorFrontMatter: template("templates/cursor-rule.mdc"),
	ProjectConfig:     template("templates/config.toml"),
	ClaudeAllow:       claudeAllow,
	ClaudeNote: `"mcp__locksql__locksql_run" and "Bash(locksql run:*)" may be added too: every run
is still approved by the human in the console.`,
}}

// Agents returns the supported agent names.
func Agents() []string { return agentwire.Agents() }

// ProjectRoot returns the directory init writes to: the nearest ancestor of
// cwd holding .locksql/config.toml, else the nearest one holding .git, else
// cwd itself.
func ProjectRoot(cwd string) string { return agentwire.ProjectRoot(product.P, cwd) }

// Init writes the integration files of agent into the project at root.
// Every change is computed and checked before the first write, so an
// invalid existing file or an escaping symlink leaves the project untouched.
func Init(root, agent string) (Result, error) { return wiring.Init(root, agent) }

func template(name string) []byte {
	b, err := templates.ReadFile(name)
	if err != nil {
		panic("agentinit: missing embedded template " + name)
	}
	return b
}

// cursorRule is the Cursor rule: its front matter plus the shared
// instructions.
func cursorRule() string {
	return string(template("templates/cursor-rule.mdc")) + string(template("templates/agents.md"))
}
