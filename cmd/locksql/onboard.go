package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/setup"
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

// chooseProfile returns the only profile, asks among several, or returns
// "" when none is configured.
func chooseProfile(e env, io setup.IO) (string, error) {
	cfg, err := config.Load(e.cwd)
	if err != nil {
		return "", usageError{err.Error()}
	}
	names := profileNames(cfg)
	switch len(names) {
	case 0:
		return "", nil
	case 1:
		return names[0], nil
	}
	for i, n := range names {
		io.Println(fmt.Sprintf("  %d) %s", i+1, n))
	}
	for {
		l, ok := io.Ask(context.Background(), "Profile: ", 30*time.Minute)
		if !ok {
			return "", setup.ErrAborted
		}
		l = strings.TrimSpace(l)
		if n, err := strconv.Atoi(l); err == nil && n >= 1 && n <= len(names) {
			return names[n-1], nil
		}
		if slices.Contains(names, l) {
			return l, nil
		}
		io.Println(fmt.Sprintf("  answer a number from 1 to %d or a profile name", len(names)))
	}
}

// addProfile runs the prompts and appends the profile to the user config.
func addProfile(e env, io setup.IO) (string, error) {
	cfg, err := config.Load(e.cwd)
	if err != nil {
		return "", usageError{err.Error()}
	}
	a, err := setup.Prompt(context.Background(), io, e.cwd, profileNames(cfg))
	if err != nil {
		return "", err
	}
	path, err := config.UserConfigPath()
	if err != nil {
		return "", err
	}
	if err := setup.AppendProfile(path, a); err != nil {
		return "", err
	}
	fmt.Fprintln(e.stdout, e.paint.OK(fmt.Sprintf("created %s (profile %s)", tildePath(path), a.Name)))
	return a.Name, nil
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

// separatedNoAdd is why the database prompts are off in separated mode.
const separatedNoAdd = "separated mode: a profile in the user config is seen by one account only; put it in the project's .locksql/config.toml (locksql init <agent> writes an example) and run locksql console --project DIR in the locksql session"

// runOnboard is bare `locksql` in a terminal: wire the agents, add a
// database when none is configured, start the console. In separated mode
// a client account gets the project-mode steps, and the service account
// the console without prompts.
func runOnboard(e env) int {
	if code, failed := sysFail(e, ""); failed {
		return code
	}
	separated, service := isServiceAccount(e)
	if separated && !service {
		wireAgents(e)
		fmt.Fprint(e.stdout, "\n"+separatedSteps(e))
		return exitOK
	}
	if separated {
		return runConsole(e, nil)
	}
	fmt.Fprint(e.stdout, e.paint.Banner(version))
	fmt.Fprintln(e.stdout)
	wireAgents(e)
	term := console.NewTerminal(os.Stdin, e.stdout)
	name, err := chooseProfile(e, term)
	if err == nil && name == "" {
		fmt.Fprintln(e.stdout)
		name, err = addProfile(e, term)
	}
	if err != nil {
		return onboardFail(e, err)
	}
	fmt.Fprintln(e.stdout, "\n"+e.paint.Step("Starting the console. Keep this terminal open; use your agents in any other."))
	return openConsole(e, name, false, "", term)
}

// runAdd is `locksql add`: the database prompts only.
func runAdd(e env, args []string) int {
	const usage = "locksql add"
	if len(args) > 0 {
		return usageFail(e, "add", usage, "takes no arguments")
	}
	if code, failed := sysFail(e, " add"); failed {
		return code
	}
	if separated, _ := isServiceAccount(e); separated {
		return usageFail(e, "add", usage, separatedNoAdd)
	}
	if !e.tty {
		return usageFail(e, "add", usage, "must run in a terminal: it asks questions")
	}
	if _, err := addProfile(e, console.NewTerminal(os.Stdin, e.stdout)); err != nil {
		return onboardFail(e, err)
	}
	return exitOK
}

// onboardFail reports an onboarding error: exit 3 for a configuration
// error, 1 otherwise.
func onboardFail(e env, err error) int {
	if errors.Is(err, setup.ErrAborted) {
		fmt.Fprintln(e.stderr, "locksql: aborted, no profile written")
		return exitFail
	}
	fmt.Fprintln(e.stderr, "locksql:", err)
	var ue usageError
	if errors.As(err, &ue) {
		return exitUsage
	}
	return exitFail
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
