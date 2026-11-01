package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/DavidGodefroid/lockkit/mcpkit"

	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/mcpserver"
)

// runMCP is `locksql mcp [--profile P] [--instance NAME]`: an MCP server
// on stdin/stdout for the agent session that spawned it. Stdout carries
// only the protocol.
func runMCP(e env, args []string) int {
	const usage = "locksql mcp [--profile P] [--instance NAME]"
	var profile, instanceFlag string
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&profile, "profile", "", "pin the server to one profile")
	fs.StringVar(&instanceFlag, client.FlagInstance, "", "reach one lock among several of this type")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return usageFail(e, "mcp", usage, err.Error())
	}
	if len(pos) > 0 {
		return usageFail(e, "mcp", usage, "wrong number of arguments")
	}
	instance, err := client.ResolveInstance(instanceFlag)
	if err != nil {
		return usageFail(e, "mcp", usage, err.Error())
	}
	// The config is checked at start-up so that a broken config is a usage
	// error the human sees, and read again on every call.
	if _, err := config.Load(e.cwd); err != nil {
		return usageFail(e, "mcp", usage, err.Error())
	}
	if profile != "" {
		if _, err := resolveProfile(e, profile); err != nil {
			return usageFail(e, "mcp", usage, err.Error())
		}
	}
	o := mcpserver.Options{
		Profile: profile,
		Profiles: func() ([]string, error) {
			cfg, err := config.Load(e.cwd)
			if err != nil {
				return nil, err
			}
			return profileNames(cfg), nil
		},
		Dial:    mcpserver.DialClient(e.cwd, version, instance),
		Version: version,
	}
	ctx, stop := signalContext()
	defer stop()
	if err := mcpkit.Serve(ctx, mcpserver.New(o), e.stdin, e.stdout); err != nil {
		fmt.Fprintf(e.stderr, "locksql mcp: %v\n", err)
		return exitFail
	}
	return exitOK
}
