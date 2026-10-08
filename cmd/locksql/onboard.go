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
// load counts as same-user mode here: the console reports it on start.
func isServiceAccount(e env) (separated, service bool) {
	sys, err := sysConfig(e)
	if err != nil || sys == nil {
		return false, false
	}
	uid, err := sys.ServiceUID()
	return true, err == nil && uid == os.Getuid()
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
		switch {
		case err != nil:
			lines = append(lines, fmt.Sprintf("  %-7s  not wired: %v (see docs/usage.md, Agent wiring)", a, err))
		case len(paths) > 0:
			lines = append(lines, fmt.Sprintf("  %-7s  %s", a, strings.Join(paths, ", ")))
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(e.stdout, "Agents found: %s\n", strings.Join(found, ", "))
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
	fmt.Fprintf(e.stdout, "  created  %s (profile %s)\n", tildePath(path), a.Name)
	return a.Name, nil
}

// separatedHint is printed to an account other than the service account
// in separated mode: only the service account can add a database to the
// config the console reads.
func separatedHint(e env) string {
	account := sysconf.DefaultServiceUser
	if sys, err := sysConfig(e); err == nil && sys != nil {
		account = sys.ServiceUser
	}
	return fmt.Sprintf("Separated mode: run `locksql` in the locksql session (account %s) to add a database and start the console.", account)
}

// runOnboard is bare `locksql` in a terminal: wire the agents, add a
// database when none is configured, start the console.
func runOnboard(e env) int {
	wireAgents(e)
	if separated, service := isServiceAccount(e); separated && !service {
		fmt.Fprintln(e.stdout, "\n"+separatedHint(e))
		return exitOK
	}
	term := console.NewTerminal(os.Stdin, e.stdout)
	name, err := chooseProfile(e, term)
	if err == nil && name == "" {
		fmt.Fprintln(e.stdout)
		name, err = addProfile(e, term)
	}
	if err != nil {
		return onboardFail(e, err)
	}
	fmt.Fprintln(e.stdout, "\nStarting the console. Keep this terminal open; use your agents in any other.")
	return openConsole(e, name, false, "", term)
}

// runAdd is `locksql add`: the database prompts only.
func runAdd(e env, args []string) int {
	const usage = "locksql add"
	if len(args) > 0 {
		return usageFail(e, "add", usage, "takes no arguments")
	}
	if !e.tty {
		return usageFail(e, "add", usage, "must run in a terminal: it asks questions")
	}
	if separated, service := isServiceAccount(e); separated && !service {
		return usageFail(e, "add", usage, separatedHint(e))
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
