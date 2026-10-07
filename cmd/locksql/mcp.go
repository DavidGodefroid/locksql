package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/mcpserver"
)

// runMCP is `locksql mcp [--profile P]`: an MCP server on stdin/stdout for
// the agent session that spawned it. Stdout carries only the protocol.
func runMCP(e env, args []string) int {
	const usage = "locksql mcp [--profile P]"
	var profile string
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&profile, "profile", "", "pin the server to one profile")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return usageFail(e, "mcp", usage, err.Error())
	}
	if len(pos) > 0 {
		return usageFail(e, "mcp", usage, "wrong number of arguments")
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
		Dial:    mcpserver.DialClient(e.cwd, version),
		Version: version,
	}
	ctx, stop := signalContext()
	defer stop()
	t := &mcp.IOTransport{Reader: io.NopCloser(e.stdin), Writer: nopWriteCloser{e.stdout}}
	if err := mcpserver.Serve(ctx, o, t); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		fmt.Fprintf(e.stderr, "locksql mcp: %v\n", err)
		return exitFail
	}
	return exitOK
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
