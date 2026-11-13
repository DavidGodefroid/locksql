package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
)

const (
	managedShowUsage  = "locksql managed show"
	managedCheckUsage = "locksql managed check [--profile NAME]"
	// noManaged is what managed show, managed check and doctor print when
	// the machine has no managed file.
	noManaged = "no managed configuration"
)

// runManaged is `locksql managed show|check`: the company's managed file
// (lockkit managed) as locksql reads it. lox runs `managed check` in a
// one-off container before it starts the lock: its output and exit codes
// are a contract, kept by the goldens of testdata/managed.
func runManaged(e env, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return runManagedShow(e, args[1:])
		case "check":
			return runManagedCheck(e, args[1:])
		}
	}
	// The subcommand is not quoted: it may be a token pasted in the wrong
	// place.
	fmt.Fprintf(e.stderr, "usage: %s\n       %s\n", managedShowUsage, managedCheckUsage)
	return exitUsage
}

// runManagedShow prints the managed file: its path, organisation,
// fingerprint and signature, then locksql's bounds, defaults and profile
// names. No file: noManaged, exit 0. A file refused: the lockkit error,
// exit 3.
func runManagedShow(e env, args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(e.stderr, "usage: "+managedShowUsage)
		return exitUsage
	}
	m, err := config.LoadManaged()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql managed show:", err)
		return exitUsage
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	f, w := m.File, e.stdout
	fmt.Fprintln(w, f.Describe())
	fmt.Fprintln(w, "path: "+f.Path)
	org := f.Organisation
	if org == "" {
		org = "none"
	}
	fmt.Fprintln(w, "organisation: "+org)
	fmt.Fprintln(w, "fingerprint: sha256:"+f.Fingerprint)
	signed := "no"
	if f.Signed {
		signed = "yes"
	}
	fmt.Fprintln(w, "signed: "+signed)
	managedSection(w, "bounds", m.Bounds.Describe())
	managedSection(w, "defaults", m.DescribeDefaults())
	fmt.Fprintln(w, "profiles: "+listOrNone(f.Profiles(config.ManagedTool)))
	return exitOK
}

// managedSection prints a titled list of lines, "none" when empty.
func managedSection(w io.Writer, title string, lines []string) {
	if len(lines) == 0 {
		fmt.Fprintln(w, title+": none")
		return
	}
	fmt.Fprintln(w, title+":")
	for _, l := range lines {
		fmt.Fprintln(w, "  "+l)
	}
}

// runManagedCheck checks the profiles of the config files against the
// managed bounds, as the console does at start, without a connection or a
// credential: one "blocked by company policy: …" line per violation and
// exit 3 on any, else one ok line and exit 0. A file refused, or a config
// that does not load under it, is the error and exit 3.
func runManagedCheck(e env, args []string) int {
	fs := flag.NewFlagSet("managed check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("profile", "", "check one profile")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(e.stderr, "usage: "+managedCheckUsage)
		return exitUsage
	}
	m, err := config.LoadManaged()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql managed check:", err)
		return exitUsage
	}
	if m == nil {
		fmt.Fprintln(e.stdout, noManaged)
		return exitOK
	}
	userPath, _ := config.UserConfigPath()
	cfg, err := config.LoadWith(e.cwd, userPath, m)
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql managed check:", err)
		return exitUsage
	}
	names := profileNames(cfg)
	if *name != "" {
		if _, ok := cfg.Profiles[*name]; !ok {
			// The name is not quoted back: it may be a token or a URL
			// pasted in the wrong place.
			fmt.Fprintf(e.stderr, "locksql managed check: unknown profile: --profile names none of the configured profiles: %s\n", listOrNone(names))
			return exitUsage
		}
		names = []string{*name}
	}
	lines, err := console.ManagedCheck(cfg, names)
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql managed check:", err)
		return exitUsage
	}
	for _, l := range lines {
		fmt.Fprintln(e.stdout, sanitize.Terminal(l, false))
	}
	if len(lines) > 0 {
		return exitUsage
	}
	n := fmt.Sprintf("%d profiles", len(names))
	if len(names) == 1 {
		n = "1 profile"
	}
	fmt.Fprintf(e.stdout, "ok: %s within the company policy (%s)\n", n, listOrNone(names))
	return exitOK
}

// managedCheck is doctor's managed line: the managed file as the console
// reads it (Describe), noManaged, or the error that refuses it.
func managedCheck() check {
	m, err := config.LoadManaged()
	switch {
	case err != nil:
		return check{state: checkFail, title: "managed", detail: err.Error(), fix: "ask your administrator to fix " + managed.DefaultPath()}
	case m == nil:
		return check{state: checkOK, title: "managed", detail: noManaged}
	}
	return check{state: checkOK, title: "managed", detail: m.File.Describe()}
}
