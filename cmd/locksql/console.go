package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
				fmt.Fprintln(e.stderr, "locksql console: no profile: run locksql (or locksql add) to add one")
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
