// Command locksql lets AI agents query databases only through a
// human-approved console. See README.md.
package main

import (
	"fmt"
	"io"
	"os"
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

const usageText = `usage: locksql <command> [arguments]

Human commands:
  console  --profile P [--project DIR] [--skip-permissions]
                                              run the approval console
  forget   --profile P                        remove the keychain secret
  install  [--client USER] [--print]          separate the console from the agent (sudo)
  doctor   [--profile P]                      check that this machine is safe-ready
  init     claude|codex|cursor|gemini [...]   write agent integration files

Client commands:
  status   [--profile P]
  tables   --profile P --db D
  describe --profile P --db D TABLE
  plan     --profile P --db D [--unmask] "SQL" | -
  run      --profile P PLAN_ID
  pii      list|add --profile P [COLUMN]
  request  --profile P "tier=write" | "limits.max_rows=500" | "allow=app.t.c"
  logout   --profile P
  mcp      [--profile P]
  Client commands accept --json. --profile may be left out when exactly
  one profile is configured.

Exit codes: 0 ok, 1 refused/denied/failed, 2 no console, 3 usage/config error.

Other:
  version                                     print the version
  help                                        print this help
`

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
	return runEnv(env{stdin: os.Stdin, stdout: stdout, stderr: stderr, cwd: cwd}, args)
}

// runEnv is run with an explicit environment.
func runEnv(e env, args []string) int {
	stdout, stderr := e.stdout, e.stderr
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "version", "--version":
		fmt.Fprintf(stdout, "locksql %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return exitOK
	case "console":
		return runConsole(args[1:], stdout, stderr)
	case "status":
		return runStatus(e, args[1:])
	case "forget":
		return runForget(e, args[1:])
	case "mcp":
		return runMCP(e, args[1:])
	case "init":
		return runInit(e, args[1:])
	case "install":
		return runInstall(e, args[1:])
	case "doctor":
		return runDoctor(e, args[1:])
	case "pii":
		return runPII(e, args[1:])
	case "tables", "describe", "plan", "run", "request", "logout":
		return runClient(e, cmd, args[1:])
	default:
		fmt.Fprintf(stderr, "locksql: unknown command %q\n\n%s", cmd, usageText)
		return exitUsage
	}
}
