package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/DavidGodefroid/locksql/internal/console"
)

// runConsole is `locksql console --profile P [--skip-permissions]`. It runs
// in the human's terminal only.
func runConsole(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "profile to open")
	skip := fs.Bool("skip-permissions", false, "auto-approve statements allowed by the tier and the weight check (never on production, never unmask)")
	project := fs.String("project", "", "project directory (default: the current directory); the console account opens the agent's project from its own session")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *profile == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: locksql console --profile P [--project DIR] [--skip-permissions]")
		return exitUsage
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(stderr, "locksql console: must run in a terminal: it asks the human for credentials and approvals")
		return exitUsage
	}
	cwd := *project
	if cwd != "" {
		abs, err := filepath.Abs(cwd)
		if err != nil {
			fmt.Fprintln(stderr, "locksql console:", err)
			return exitUsage
		}
		cwd = abs
	}
	err := console.Run(context.Background(), console.Options{
		Profile:         *profile,
		SkipPermissions: *skip,
		Cwd:             cwd,
		IO:              console.NewTerminal(os.Stdin, stdout),
		TTY:             os.Stdin,
		Version:         version,
	})
	if err != nil {
		fmt.Fprintln(stderr, "locksql console:", err)
		if errors.Is(err, console.ErrConfig) {
			return exitUsage
		}
		return exitFail
	}
	return exitOK
}
