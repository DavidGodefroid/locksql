package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/secrets"
)

// stdinIsTerminal reports whether r is an interactive terminal. Tests
// replace it.
var stdinIsTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// runForget is `locksql forget --profile P`: it deletes the profile's OS
// keychain item. Like the console, it runs in the human's terminal only.
func runForget(e env, args []string) int {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	profile := fs.String("profile", "", "profile whose keychain secret is removed")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *profile == "" || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage: locksql forget --profile P")
		return exitUsage
	}
	cfg, err := config.Load(e.cwd)
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql forget:", err)
		return exitUsage
	}
	p, ok := cfg.Profiles[*profile]
	if !ok {
		fmt.Fprintf(e.stderr, "locksql forget: unknown profile %q; configured profiles: %s\n",
			*profile, listOrNone(profileNames(cfg)))
		return exitUsage
	}
	if !stdinIsTerminal(e.stdin) {
		fmt.Fprintln(e.stderr, "locksql forget: must run in a terminal: only the human removes saved secrets")
		return exitUsage
	}
	if p.Engine == config.EngineSQLite || p.Host == "" {
		fmt.Fprintf(e.stderr, "locksql forget: profile %s has no keychain secret (no server credentials)\n", p.Name)
		return exitFail
	}
	switch err := secrets.KeychainDelete(p.Name, p.Host); {
	case err == nil:
		fmt.Fprintf(e.stdout, "removed the keychain secret of %s@%s\n", p.Name, p.Host)
	case errors.Is(err, secrets.ErrNotFound):
		fmt.Fprintf(e.stdout, "no keychain secret for %s@%s, nothing to remove\n", p.Name, p.Host)
	default:
		fmt.Fprintln(e.stderr, "locksql forget:", secrets.Sanitize(err))
		return exitFail
	}
	return exitOK
}
