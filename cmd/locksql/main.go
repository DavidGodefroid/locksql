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
  console  --profile P [--skip-permissions]   run the approval console
  forget   --profile P                        remove the keychain secret
  init     claude|codex|cursor|gemini         write agent integration files

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

Other:
  version                                     print the version
  help                                        print this help
`

// commands lists every subcommand that is dispatched but not handled inline.
var commands = map[string]bool{
	"console":  true,
	"forget":   true,
	"init":     true,
	"status":   true,
	"tables":   true,
	"describe": true,
	"plan":     true,
	"run":      true,
	"pii":      true,
	"request":  true,
	"logout":   true,
	"mcp":      true,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args to a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
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
	default:
		if commands[cmd] {
			fmt.Fprintf(stderr, "locksql %s: not implemented yet\n", cmd)
			return exitFail
		}
		fmt.Fprintf(stderr, "locksql: unknown command %q\n\n%s", cmd, usageText)
		return exitUsage
	}
}
