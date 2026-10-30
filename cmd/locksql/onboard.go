package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
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
// be wired gets one line and the others go on. It returns the agents
// found.
func wireAgents(e env) []string {
	if _, err := sysConfig(e); err != nil {
		return nil // cannot tell whether this is the service account
	}
	if _, service := isServiceAccount(e); service {
		return nil // the agents live in the other account's home
	}
	if e.agentEnv == nil {
		return nil
	}
	if e.geteuid() == 0 {
		fmt.Fprintln(e.stdout, "not wiring agents as root; run locksql from your own account")
		return nil
	}
	ae, err := e.agentEnv()
	if err != nil {
		return nil
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
		return found
	}
	fmt.Fprintf(e.stdout, "Agents found: %s\n", e.paint.Bold(strings.Join(found, ", ")))
	for _, l := range lines {
		fmt.Fprintln(e.stdout, l)
	}
	return found
}

// projectDirHint names the project of cwd, or a placeholder outside one.
func projectDirHint(e env) string {
	if root, ok := config.FindProjectRoot(e.cwd); ok {
		return client.ShellQuote(root)
	}
	return "DIR"
}
