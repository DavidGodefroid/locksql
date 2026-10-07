package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

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
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *profile == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: locksql console --profile P [--skip-permissions]")
		return exitUsage
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(stderr, "locksql console: must run in a terminal: it asks the human for credentials and approvals")
		return exitUsage
	}
	err := console.Run(context.Background(), console.Options{
		Profile:         *profile,
		SkipPermissions: *skip,
		IO:              console.NewTerminal(os.Stdin, stdout),
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
