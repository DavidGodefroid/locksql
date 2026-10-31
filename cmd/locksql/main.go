// Command locksql lets AI agents query databases only through a
// human-approved console. See README.md.
package main

import (
	"fmt"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockkit/ui"
	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// Exit codes shared by every subcommand.
const (
	exitOK        = 0 // success
	exitFail      = 1 // refused, denied or failed
	exitNoConsole = 2 // no console is listening for the profile
	exitUsage     = 3 // usage or configuration error
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// helpSection is one titled group of commands in the help.
type helpSection struct {
	title string
	rows  []helpRow
	notes []string
}

// helpRow is one command: its name, its arguments and what it does, with
// continuation lines for the description.
type helpRow struct{ name, args, desc string }

var helpSections = []helpSection{
	{title: "Human commands", rows: []helpRow{
		{"profile", "add [--project DIR] [--engine E ...]", "add a database profile to the project"},
		{"console", "--hub URL --hub-key-file PATH --instance NAME ...", "run the console (launched by `lox up` only)"},
		{"forget", "--profile P", "remove the keychain secret"},
		{"update", "[vX.Y.Z]", "update the launcher and its image (on the host;\ncosign signature and checksum checked)"},
		{"doctor", "[--profile P] [--fix [--yes]]", "check the setup\n(--fix: repair permissions, socket dir, wiring)"},
		{"init", "[claude|codex|cursor|gemini ...]", "write agent integration files into the project\n(default: the agents found on this machine)"},
		{"stats", "[--log PATH] [--top N] [--export]", "count the refusals of the local audit log\n(--export: anonymised report, SQL shapes only)"},
		{"config", "export|import [--project] [--profile P] ...", "share profiles and PII rules with your team\n(import: --dry-run, --allow-loosen, --local P.KEY=V)"},
	}},
	{title: "Client commands", rows: []helpRow{
		{"status", "[--profile P]", ""},
		{"tables", "--profile P --db D", ""},
		{"describe", "--profile P --db D TABLE", ""},
		{"plan", `--profile P --db D [--unmask] "SQL" | -`, ""},
		{"run", "--profile P PLAN_ID|TICKET", ""},
		{"pii", "list|add --profile P [COLUMN]", ""},
		{"request", `--profile P "tier=write" | "limits.max_rows=500" | "allow=app.t.c"`, ""},
		{"logout", "--profile P", ""},
		{"mcp", "[--profile P]", ""},
	}, notes: []string{
		"Client commands accept --json. --profile may be left out when exactly",
		"one profile is configured.",
	}},
	{title: "Other", rows: []helpRow{
		{"version", "", "print the version"},
		{"help", "", "print this help"},
	}},
}

// usage is the help text, coloured by p.
func usage(p ui.Painter) string {
	const nameW, argsW = 9, 35
	var b strings.Builder
	fmt.Fprintf(&b, "%s locksql %s\n", p.Bold("usage:"), p.Dim("<command> [arguments]"))
	for _, sec := range helpSections {
		b.WriteString("\n" + p.Heading(sec.title, 72) + "\n")
		for _, r := range sec.rows {
			head := "  " + p.Accent(fmt.Sprintf("%-*s", nameW, r.name)) + p.Dim(r.args)
			if r.desc == "" {
				b.WriteString(head + "\n")
				continue
			}
			// Descriptions start in one column; arguments too long for it
			// push the description to the next line.
			w, col := 2+nameW+len(r.args), 2+nameW+argsW
			if w+2 > col {
				b.WriteString(head + "\n")
				head, w = "", 0
			}
			for _, d := range strings.Split(r.desc, "\n") {
				b.WriteString(head + strings.Repeat(" ", col-w) + d + "\n")
				head, w = "", 0
			}
		}
		if len(sec.notes) > 0 {
			b.WriteString("\n")
		}
		for _, n := range sec.notes {
			b.WriteString("  " + p.Dim(n) + "\n")
		}
	}
	b.WriteString("\n" + p.Bold("Exit codes") + "  0 ok · 1 refused/denied/failed · 2 no console · 3 usage/config error\n")
	return b.String()
}

// usageText is the plain help, for errors and pipes.
var usageText = usage(ui.Painter{})

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args to a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locksql:", err)
		return exitFail
	}
	return runEnv(env{
		stdin: os.Stdin, stdout: stdout, stderr: stderr, cwd: cwd,
		tty:      term.IsTerminal(int(os.Stdin.Fd())),
		agentEnv: agentinit.SystemEnv,
		sys:      product.LoadSys,
		paint:    ui.For(os.Stdout),
	}, args)
}

// runEnv is run with an explicit environment.
func runEnv(e env, args []string) int {
	stdout, stderr := e.stdout, e.stderr
	first := ""
	if len(args) > 0 {
		first = args[0]
	}
	if !platformAllows(first) {
		fmt.Fprintln(stderr, windowsRefusal)
		return exitFail
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "version", "--version":
		fmt.Fprintf(stdout, "locksql %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		if e.paint.On {
			fmt.Fprint(stdout, e.paint.Banner(product.P.Name, product.P.Tagline, version))
			fmt.Fprintln(stdout)
		}
		fmt.Fprint(stdout, usage(e.paint))
		return exitOK
	case "console":
		return runConsole(e, args[1:])
	case "hub-key":
		// The instance's public key, for lock up to pin at the hub; the
		// key itself stays in the console account's home.
		if err := hubclient.HubKeyCommand(stdout, "", args[1:]); err != nil {
			fmt.Fprintln(stderr, "locksql hub-key:", err)
			return exitUsage
		}
		return exitOK
	case "status":
		return runStatus(e, args[1:])
	case "forget":
		return runForget(e, args[1:])
	case "mcp":
		return runMCP(e, args[1:])
	case "init":
		return runInit(e, args[1:])
	case "install", "update", "setup":
		fmt.Fprintln(stderr, hostModeRefusal(cmd))
		return exitFail
	case "profile":
		return runProfile(e, args[1:])
	case "doctor":
		return runDoctor(e, args[1:])
	case "stats":
		return runStats(e, args[1:])
	case "pii":
		return runPII(e, args[1:])
	case "config":
		return runConfig(e, args[1:])
	case "tables", "describe", "plan", "run", "request", "logout":
		return runClient(e, cmd, args[1:])
	default:
		// Not quoted back: it may be a token or a URL pasted in the
		// wrong place.
		fmt.Fprintf(stderr, "locksql: unknown command\n\n%s", usageText)
		return exitUsage
	}
}
