// User scope: wires agents through files under the home directory (and
// `claude mcp add --scope user`). Symlinks are followed: these are the
// human's own files, often managed as dotfiles.
package agentinit

import "github.com/DavidGodefroid/lockkit/agentwire"

// Env is the user account init works on, and how it looks for and runs
// the agents' commands.
type Env = agentwire.Env

// SystemEnv is the current account: its home directory, environment and
// PATH.
func SystemEnv() (Env, error) { return agentwire.SystemEnv() }

// Detect lists the installed agents, in Agents() order.
func Detect(e Env) []string { return agentwire.Detect(e) }

// InitUser wires agent for the current account, in every project.
func InitUser(e Env, agent string) (Result, error) { return wiring.InitUser(e, agent) }

// PendingUser reports whether InitUser would write or run anything.
func PendingUser(e Env, agent string) (bool, error) { return wiring.PendingUser(e, agent) }
