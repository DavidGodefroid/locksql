package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/console"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// runConsole is `locksql console [--profile P] [--auto] [--allow-unmask]
// [--show-results]`. It runs in the human's terminal only. Without
// --profile it opens the only profile, or asks which one among several.
func runConsole(e env, args []string) int {
	const usage = "usage: locksql console [--profile P] [--project DIR] [--auto] [--allow-unmask] [--show-results] [--hub URL --hub-key-file PATH --instance NAME]"
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	profile := fs.String("profile", "", "profile to open")
	auto := fs.Bool("auto", false, "start in auto mode: statements allowed by the tier and the weight check run without a prompt (never on production, never unmask); Shift+Tab switches the mode while the console runs")
	skip := fs.Bool("skip-permissions", false, "same as --auto (older name)")
	allowUnmask := fs.Bool("allow-unmask", false, "let clients ask for unmasked PII output; each such query is still approved here, never auto-approved (off by default: unmask requests are refused); :unmask switches it while the console runs")
	showResults := fs.Bool("show-results", false, "print in this console, in clear, the result of each masked query it runs; the client still gets it masked")
	noUpdateCheck := fs.Bool(strings.TrimPrefix(noUpdateCheckFlag, "--"), false, "internal: no new-version check (the handoff passes LOCKSQL_NO_UPDATE_CHECK on with it)")
	project := fs.String("project", "", "project directory (default: the current directory); the console account opens the agent's project from its own session")
	var hub kconsole.HubOptions
	hub.Register(fs)
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
	// In the launcher's container, a .locksql other than the one it
	// checked was swapped in before Docker mounted it.
	if want := os.Getenv(expectDirEnv); want != "" {
		proj, err := consoleProject(e.cwd, *project)
		if err == nil {
			err = checkConsoleDir(proj, want)
		}
		if err != nil {
			fmt.Fprintln(e.stderr, "locksql console:", err)
			return exitFail
		}
	}
	// Started from another account of a separated setup: open the console
	// in the console account, or say how.
	if proj, err := consoleProject(e.cwd, *project); err == nil {
		a := consoleArgs{profile: *profile, project: proj, auto: *auto || *skip, allowUnmask: *allowUnmask, showResults: *showResults, hub: hub,
			noUpdateCheck: *noUpdateCheck || e.updateCheckOff()}
		if code, handled := handoffConsole(e, a); handled {
			return code
		}
	}
	// This process runs the console: the new-version check runs here, in
	// the console account, never in the agent's before the handoff.
	if !*noUpdateCheck {
		updateNotice(e)
	}
	fmt.Fprint(e.stdout, e.paint.Banner(product.P.Name, product.P.Tagline, version))
	fmt.Fprintln(e.stdout)
	term := console.NewTerminal(os.Stdin, e.stdout)
	if err := term.Interactive(); err != nil {
		// Cooked mode then: no Shift+Tab, no status line, but a console.
		fmt.Fprintln(e.stderr, "locksql console: warning:", err, "(the mode keys and the status line are off)")
	}
	defer term.Restore()
	// Ctrl-C before the console runs ends the prompts, so that the
	// deferred Restore runs: the terminal is never left in cbreak mode.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	name := *profile
	if name == "" {
		if code, failed := sysFail(e, " console"); failed {
			return code
		}
		sys, _ := sysConfig(e)
		if err := console.SameUserRefused(sys); err != nil {
			fmt.Fprintln(e.stderr, "locksql console:", err)
			return exitFail
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
		if name, err = chooseProfile(ctx, pe, term); err != nil {
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
	if ctx.Err() != nil {
		return exitFail
	}
	return openConsole(ctx, e, name, consoleFlags{auto: *auto || *skip, allowUnmask: *allowUnmask, showResults: *showResults, hub: hub}, *project, term)
}

// consoleFlags are the console-only switches: no client or config file can
// set them.
type consoleFlags struct {
	auto, allowUnmask, showResults bool
	// hub is the hub mode, written by lock up.
	hub kconsole.HubOptions
}

// openConsole runs the console on profile until it ends.
func openConsole(ctx context.Context, e env, profile string, f consoleFlags, project string, term *console.Terminal) int {
	cwd := project
	if cwd != "" {
		abs, err := filepath.Abs(cwd)
		if err != nil {
			fmt.Fprintln(e.stderr, "locksql console:", err)
			return exitUsage
		}
		cwd = abs
	}
	err := console.Run(ctx, console.Options{
		Profile:     profile,
		Auto:        f.auto,
		AllowUnmask: f.allowUnmask,
		ShowResults: f.showResults,
		Hub:         f.hub,
		Cwd:         cwd,
		IO:          term,
		TTY:         os.Stdin,
		Version:     version,
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
func chooseProfile(ctx context.Context, e env, io console.IO) (string, error) {
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
		l, ok := io.Ask(ctx, "Profile: ", 30*time.Minute)
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
