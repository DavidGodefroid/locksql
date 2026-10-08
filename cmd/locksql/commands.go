package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// env is what a command reads and writes; tests replace it.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	cwd            string
	// tty reports whether stdin is a terminal.
	tty bool
	// agentEnv is the account the agents are wired for; nil means none.
	agentEnv func() (agentinit.Env, error)
	// sys loads the separated-mode setup; nil means same-user mode.
	sys func() (*sysconf.Config, error)
}

// usageError is a usage or configuration error (exit 3).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// opts are the parsed flags and arguments of a client command.
type opts struct {
	profile string
	db      string
	unmask  bool
	json    bool
	args    []string
}

// clientCmd is one client command: its flags, its arguments and what it
// asks the console. do returns the --json value and the text renderer.
type clientCmd struct {
	usage    string
	db       bool // accepts --db
	unmask   bool // accepts --unmask
	min, max int  // positional arguments
	do       func(ctx context.Context, e env, c *client.Client, o *opts) (any, func(io.Writer), error)
}

var clientCmds = map[string]clientCmd{
	"tables": {
		usage: "locksql tables --profile P --db D [--json]", db: true,
		do: func(ctx context.Context, _ env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			r, err := c.Tables(ctx, o.db)
			return r, func(w io.Writer) { client.FormatTables(w, r) }, err
		},
	},
	"describe": {
		usage: "locksql describe --profile P --db D [--json] TABLE", db: true, min: 1, max: 1,
		do: func(ctx context.Context, _ env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			info, err := c.Describe(ctx, o.db, o.args[0])
			if err != nil {
				return nil, nil, err
			}
			rules, err := c.PIIList(ctx)
			if err != nil {
				return nil, nil, err
			}
			d := client.Description{TableInfo: info, Masked: client.MaskedColumns(info, rules)}
			return d, func(w io.Writer) { client.FormatDescribe(w, d) }, nil
		},
	},
	"plan": {
		usage: `locksql plan --profile P --db D [--unmask] [--json] "SQL" | -`, db: true, unmask: true, min: 1, max: 1,
		do: func(ctx context.Context, e env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			sql, err := readSQL(e, o.args[0])
			if err != nil {
				return nil, nil, err
			}
			r, err := c.Plan(ctx, ipc.PlanParams{DB: o.db, SQL: sql, Unmask: o.unmask})
			return r, func(w io.Writer) { client.FormatPlan(w, r) }, err
		},
	},
	"run": {
		usage: "locksql run --profile P [--json] PLAN_ID", min: 1, max: 1,
		do: func(ctx context.Context, _ env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			// No timeout: the human may take up to the console's approval
			// timeout to answer.
			r, err := c.Run(ctx, o.args[0])
			asJSON := r
			asJSON.Text = "" // the rows are already there
			return asJSON, func(w io.Writer) { client.FormatRun(w, r) }, err
		},
	},
	"pii list": {
		usage: "locksql pii list --profile P [--json]",
		do: func(ctx context.Context, _ env, c *client.Client, _ *opts) (any, func(io.Writer), error) {
			r, err := c.PIIList(ctx)
			return r, func(w io.Writer) { client.FormatPII(w, r) }, err
		},
	},
	"pii add": {
		usage: "locksql pii add --profile P [--json] DB.TABLE.COLUMN", min: 1, max: 1,
		do: func(ctx context.Context, _ env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			r, err := c.PIIAdd(ctx, o.args[0])
			return r, func(w io.Writer) { fmt.Fprintf(w, "mask rule added: %s\n", o.args[0]) }, err
		},
	},
	"request": {
		usage: `locksql request --profile P [--json] "tier=write" | "limits.max_rows=500" | "allow=app.t.c"`, min: 1, max: 1,
		do: func(ctx context.Context, _ env, c *client.Client, o *opts) (any, func(io.Writer), error) {
			change := strings.TrimSpace(o.args[0])
			if change == "" {
				return nil, nil, usagef("empty change request")
			}
			r, err := c.Request(ctx, change)
			return r, func(w io.Writer) {
				fmt.Fprintf(w, "queued for the human's review in the console (:review): %s\nIt changes nothing until the human edits the config.\n", change)
			}, err
		},
	},
	"logout": {
		usage: "locksql logout --profile P [--json]",
		do: func(ctx context.Context, _ env, c *client.Client, _ *opts) (any, func(io.Writer), error) {
			err := c.Logout(ctx)
			return map[string]bool{"ok": true}, func(w io.Writer) {
				fmt.Fprintf(w, "console session for profile %s ended\n", c.Profile())
			}, err
		},
	},
}

// maxSQL bounds SQL read from stdin: a request must fit in one message.
const maxSQL = ipc.MaxMessage / 2

func readSQL(e env, arg string) (string, error) {
	sql := arg
	if arg == "-" {
		b, err := io.ReadAll(io.LimitReader(e.stdin, maxSQL+1))
		if err != nil {
			return "", fmt.Errorf("reading SQL from stdin: %w", err)
		}
		if len(b) > maxSQL {
			return "", usagef("SQL on stdin is larger than %d bytes", maxSQL)
		}
		sql = string(b)
	}
	if strings.TrimSpace(sql) == "" {
		return "", usagef("no SQL given")
	}
	return sql, nil
}

// parseInterleaved parses flags placed before, between or after the
// positional arguments. Everything after "--" is positional.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if used := len(args) - len(rest); used > 0 && args[used-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// resolveProfile checks name against the configured profiles, or picks the
// only one when name is empty.
func resolveProfile(e env, name string) (string, error) {
	cfg, err := config.Load(e.cwd)
	if err != nil {
		return "", usageError{err.Error()}
	}
	names := profileNames(cfg)
	if name != "" {
		if _, ok := cfg.Profiles[name]; !ok {
			return "", usagef("unknown profile %q; configured profiles: %s", name, listOrNone(names))
		}
		return name, nil
	}
	switch len(names) {
	case 0:
		return "", usagef("no profile is configured; add one to .locksql/config.toml")
	case 1:
		return names[0], nil
	}
	return "", usagef("several profiles are configured (%s): pass --profile", strings.Join(names, ", "))
}

func profileNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func listOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// signalContext ends on Ctrl-C. It never carries a deadline.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// runClient runs a client command: name is the command ("pii list" for a
// pii subcommand) and args its arguments.
func runClient(e env, name string, args []string) int {
	spec := clientCmds[name]
	o := &opts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.profile, "profile", "", "profile")
	fs.BoolVar(&o.json, "json", false, "JSON output")
	if spec.db {
		fs.StringVar(&o.db, "db", "", "database")
	}
	if spec.unmask {
		fs.BoolVar(&o.unmask, "unmask", false, "ask the human for unmasked output")
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return usageFail(e, name, spec.usage, err.Error())
	}
	if len(pos) < spec.min || len(pos) > spec.max {
		return usageFail(e, name, spec.usage, "wrong number of arguments")
	}
	o.args = pos
	profile, err := resolveProfile(e, o.profile)
	if err != nil {
		return usageFail(e, name, spec.usage, err.Error())
	}
	o.profile = profile

	ctx, stop := signalContext()
	defer stop()
	c, err := client.Dial(e.cwd, profile)
	if err != nil {
		return fail(e, name, o.json, err)
	}
	defer c.Close()
	v, text, err := spec.do(ctx, e, c, o)
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			return usageFail(e, name, spec.usage, ue.msg)
		}
		return fail(e, name, o.json, err)
	}
	if o.json {
		if err := client.WriteJSON(e.stdout, v); err != nil {
			return fail(e, name, false, err)
		}
		return exitOK
	}
	text(e.stdout)
	return exitOK
}

func usageFail(e env, name, usage, msg string) int {
	fmt.Fprintf(e.stderr, "locksql %s: %s\nusage: %s\n", name, msg, usage)
	return exitUsage
}

// fail reports err and returns its exit code: 2 without a console, 1
// otherwise. With --json the error also goes to stdout as {"error": ...}.
func fail(e env, name string, asJSON bool, err error) int {
	fmt.Fprintf(e.stderr, "locksql %s: %s\n", name, client.ErrorText(err))
	if asJSON {
		_ = client.WriteJSON(e.stdout, map[string]client.ErrorInfo{"error": client.DescribeError(err)})
	}
	if errors.Is(err, client.ErrNoConsole) {
		return exitNoConsole
	}
	return exitFail
}

// runPII dispatches `locksql pii list|add`.
func runPII(e env, args []string) int {
	if len(args) == 0 || (args[0] != "list" && args[0] != "add") {
		fmt.Fprintln(e.stderr, "usage: locksql pii list|add --profile P [--json] [DB.TABLE.COLUMN]")
		return exitUsage
	}
	return runClient(e, "pii "+args[0], args[1:])
}

// runStatus is `locksql status [--profile P] [--json]`. Without a profile
// and with several configured, it reports every profile.
func runStatus(e env, args []string) int {
	const usage = "locksql status [--profile P] [--json]"
	o := &opts{}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.profile, "profile", "", "profile")
	fs.BoolVar(&o.json, "json", false, "JSON output")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return usageFail(e, "status", usage, err.Error())
	}
	if len(pos) > 0 {
		return usageFail(e, "status", usage, "wrong number of arguments")
	}
	cfg, err := config.Load(e.cwd)
	if err != nil {
		return usageFail(e, "status", usage, err.Error())
	}
	names := profileNames(cfg)
	if o.profile == "" && len(names) > 1 {
		return statusAll(e, names, o.json)
	}
	profile, err := resolveProfile(e, o.profile)
	if err != nil {
		return usageFail(e, "status", usage, err.Error())
	}
	ctx, stop := signalContext()
	defer stop()
	c, err := client.Dial(e.cwd, profile)
	if err != nil {
		return fail(e, "status", o.json, err)
	}
	defer c.Close()
	st, err := c.Status(ctx)
	if err != nil {
		return fail(e, "status", o.json, err)
	}
	if o.json {
		_ = client.WriteJSON(e.stdout, st)
	} else {
		client.FormatStatus(e.stdout, st)
	}
	return exitOK
}

func statusAll(e env, names []string, asJSON bool) int {
	ctx, stop := signalContext()
	defer stop()
	list := make([]client.ProfileStatus, 0, len(names))
	for _, n := range names {
		ps := client.ProfileStatus{Profile: n}
		c, err := client.Dial(e.cwd, n)
		switch {
		case errors.Is(err, client.ErrNoConsole):
			ps.Start = client.StartCommand(n)
		case err != nil:
			ps.Error = err.Error()
		default:
			st, err := c.Status(ctx)
			c.Close()
			ps.Running = true
			if err != nil {
				ps.Error = client.ErrorText(err)
			} else {
				ps.Status = &st
			}
		}
		list = append(list, ps)
	}
	if asJSON {
		_ = client.WriteJSON(e.stdout, list)
	} else {
		client.FormatProfiles(e.stdout, list)
	}
	return exitOK
}
