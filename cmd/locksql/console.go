package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
)

// runConsole is `locksql console [--profile P] [--skip-permissions]`. It
// runs in the human's terminal only. Without --profile it opens the only
// profile, or asks which one among several.
func runConsole(e env, args []string) int {
	const usage = "usage: locksql console [--profile P] [--project DIR] [--skip-permissions]"
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	profile := fs.String("profile", "", "profile to open")
	skip := fs.Bool("skip-permissions", false, "auto-approve statements allowed by the tier and the weight check (never on production, never unmask)")
	project := fs.String("project", "", "project directory (default: the current directory); the console account opens the agent's project from its own session")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, usage)
		return exitUsage
	}
	if !e.tty {
		fmt.Fprintln(e.stderr, "locksql console: must run in a terminal: it asks the human for credentials and approvals")
		return exitUsage
	}
	fmt.Fprint(e.stdout, e.paint.Banner(version))
	fmt.Fprintln(e.stdout)
	term := console.NewTerminal(os.Stdin, e.stdout)
	name := *profile
	if name == "" {
		if code, failed := sysFail(e, " console"); failed {
			return code
		}
		wireAgents(e)
		pe := e
		if *project != "" {
			abs, err := filepath.Abs(*project)
			if err != nil {
				fmt.Fprintln(e.stderr, "locksql console:", err)
				return exitUsage
			}
			pe.cwd = abs
		}
		var err error
		if name, err = chooseProfile(pe, term); err != nil {
			return onboardFail(e, err)
		}
		if name == "" {
			if separated, _ := isServiceAccount(e); separated {
				fmt.Fprintf(e.stderr, "locksql console: no profile visible here; in separated mode, put the profile in the project's .locksql/config.toml and run: locksql console --project %s\n", projectDirHint(pe))
			} else {
				fmt.Fprintln(e.stderr, "locksql console: no profile: put the profile in the project's .locksql/config.toml (locksql init <agent> writes an example)")
			}
			return exitUsage
		}
	}
	return openConsole(e, name, *skip, *project, term)
}

// openConsole runs the console on profile until it ends.
func openConsole(e env, profile string, skip bool, project string, term *console.Terminal) int {
	cwd := project
	if cwd != "" {
		abs, err := filepath.Abs(cwd)
		if err != nil {
			fmt.Fprintln(e.stderr, "locksql console:", err)
			return exitUsage
		}
		cwd = abs
	}
	err := console.Run(context.Background(), console.Options{
		Profile:         profile,
		SkipPermissions: skip,
		Cwd:             cwd,
		IO:              term,
		TTY:             os.Stdin,
		Version:         version,
	})
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql console:", err)
		if errors.Is(err, console.ErrConfig) {
			return exitUsage
		}
		return exitFail
	}
	return exitOK
}

// errAborted is a profile choice cut short (Ctrl-D, timeout).
var errAborted = errors.New("aborted")

// chooseProfile returns the only profile, asks among several, or returns
// "" when none is configured.
func chooseProfile(e env, io console.IO) (string, error) {
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
			return "", errAborted
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

// onboardFail reports a profile choice error: exit 3 for a configuration
// error, 1 otherwise.
func onboardFail(e env, err error) int {
	fmt.Fprintln(e.stderr, "locksql:", err)
	var ue usageError
	if errors.As(err, &ue) {
		return exitUsage
	}
	return exitFail
}
