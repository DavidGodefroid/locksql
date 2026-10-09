package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// sysConfig is the separated-mode setup, nil in same-user mode.
func sysConfig(e env) (*sysconf.Config, error) {
	if e.sys == nil {
		return nil, nil
	}
	return e.sys()
}

// isServiceAccount reports whether separated mode is set up and whether
// this process runs as its service account. A system config that does not
// load counts as same-user mode here: callers that must not guess check
// sysConfig first (see sysFail).
func isServiceAccount(e env) (separated, service bool) {
	sys, err := sysConfig(e)
	if err != nil || sys == nil {
		return false, false
	}
	uid, err := sys.ServiceUID()
	return true, err == nil && uid == os.Getuid()
}

// sysFail reports a system config that does not load, before any prompt or
// wiring: without it, locksql cannot tell whether this is the service
// account. It returns false when the config loads (or is absent).
func sysFail(e env, name string) (int, bool) {
	if _, err := sysConfig(e); err != nil {
		fmt.Fprintf(e.stderr, "locksql%s: %v\n", name, err)
		return exitUsage, true
	}
	return 0, false
}

func (e env) geteuid() int {
	if e.euid != nil {
		return e.euid()
	}
	return os.Geteuid()
}

// wireAgents wires every detected agent that is not wired yet, one line
// per agent that had a file written. It never fails: an agent that cannot
// be wired gets one line and the others go on.
func wireAgents(e env) {
	if _, err := sysConfig(e); err != nil {
		return // cannot tell whether this is the service account
	}
	if _, service := isServiceAccount(e); service {
		return // the agents live in the other account's home
	}
	if e.agentEnv == nil {
		return
	}
	if e.geteuid() == 0 {
		fmt.Fprintln(e.stdout, "not wiring agents as root; run locksql from your own account")
		return
	}
	ae, err := e.agentEnv()
	if err != nil {
		return
	}
	found := agentinit.Detect(ae)
	var lines []string
	for _, a := range found {
		pending, err := agentinit.PendingUser(ae, a)
		if err == nil && !pending {
			continue
		}
		var res agentinit.Result
		if err == nil {
			res, err = agentinit.InitUser(ae, a)
		}
		var paths []string
		for _, act := range res.Actions {
			if act.Status == agentinit.StatusCreated || act.Status == agentinit.StatusUpdated {
				paths = append(paths, act.Path)
			}
		}
		// Files written before a failure are listed first: they stay.
		if len(paths) > 0 {
			lines = append(lines, fmt.Sprintf("  %-7s  %s", a, strings.Join(paths, ", ")))
		}
		if err != nil {
			lines = append(lines, fmt.Sprintf("  %-7s  not wired: %v (see docs/usage.md, Agent wiring)", a, err))
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(e.stdout, "Agents found: %s\n", e.paint.Bold(strings.Join(found, ", ")))
	for _, l := range lines {
		fmt.Fprintln(e.stdout, l)
	}
}

// projectDirHint names the project of cwd, or a placeholder outside one.
func projectDirHint(e env) string {
	if root, ok := config.FindProjectRoot(e.cwd); ok {
		return client.ShellQuote(root)
	}
	return "DIR"
}

// separatedSteps is printed to an account other than the service account
// in separated mode. The console reads the service account's user config,
// which the agents' account cannot see: both sides share a project config
// instead, and the console serves that project.
func separatedSteps(e env) string {
	account := sysconf.DefaultServiceUser
	if sys, err := sysConfig(e); err == nil && sys != nil {
		account = sys.ServiceUser
	}
	dir := projectDirHint(e)
	return fmt.Sprintf(`Separated mode: the console runs as %s and serves one project at a time.
  1. Put the database profile in %s/.locksql/config.toml (`+"`locksql init <agent>`"+` writes a
     commented example there).
  2. In the locksql session (account %s), run:  locksql console --project %s
Agents working in that project then reach the console.
`, account, dir, account, dir)
}

// sameUserSteps is printed when no separated setup exists: the console
// refuses to run in the agent's account.
const sameUserSteps = `The console must run in a separate account, apart from your agents: it alone
holds the database password, and the agent's account cannot read its terminal.
`

// offerInstall asks whether to run locksql install now. It never fails:
// any answer but y continues with the steps.
func offerInstall(e env) {
	fmt.Fprint(e.stdout, "Set it up now with sudo locksql install? [y/N] ")
	// One reader for both prompts: install must not lose buffered input.
	br := bufio.NewReader(e.stdin)
	e.stdin = br
	ans, _ := br.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(ans)) != "y" {
		fmt.Fprintln(e.stdout, "\nLater: run sudo locksql install, then locksql doctor.")
		return
	}
	run := e.install
	if run == nil {
		run = func(args []string) int { return runInstall(e, args) }
	}
	run(nil)
}

// runOnboard is bare `locksql` in a terminal: wire the agents, then lead
// to the separated setup. The service account gets the console.
func runOnboard(e env) int {
	if code, failed := sysFail(e, ""); failed {
		return code
	}
	separated, service := isServiceAccount(e)
	if separated && service {
		return runConsole(e, nil)
	}
	fmt.Fprint(e.stdout, e.paint.Banner(version))
	fmt.Fprintln(e.stdout)
	wireAgents(e)
	if !separated {
		fmt.Fprint(e.stdout, "\n"+sameUserSteps)
		offerInstall(e)
	}
	fmt.Fprint(e.stdout, "\n"+separatedSteps(e))
	return exitOK
}

// tildePath shows p with the home directory as ~.
func tildePath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if r, err := filepath.Rel(home, p); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "~/" + filepath.ToSlash(r)
	}
	return p
}
