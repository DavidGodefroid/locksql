package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/stats"
)

// runStats is `locksql stats [--log PATH] [--top N] [--export]`: it counts
// the refusals of the local audit log by code and by the token that
// triggered them. --export prints the anonymised report (SQL shapes only)
// to attach to an issue. It reads a local file and nothing else.
func runStats(e env, args []string) int {
	const usage = "locksql stats [--log PATH] [--top N] [--export]"
	fl := flag.NewFlagSet("stats", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	logPath := fl.String("log", "", "audit log to read (default: this account's)")
	top := fl.Int("top", 20, "tokens to list")
	export := fl.Bool("export", false, "print the anonymised report as JSON")
	if err := fl.Parse(args); err != nil || fl.NArg() > 0 {
		return usageFail(e, "stats", usage, "unexpected arguments")
	}
	path := *logPath
	if path == "" {
		dir, err := config.StateDir()
		if err != nil {
			fmt.Fprintln(e.stderr, "locksql stats:", err)
			return exitFail
		}
		path = filepath.Join(dir, "locksql", "audit.log")
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(e.stderr, "locksql stats: no audit log at %s: run stats as the account that runs the console, or pass --log\n", path)
		} else {
			fmt.Fprintln(e.stderr, "locksql stats:", err)
		}
		return exitFail
	}
	defer f.Close()
	rep, err := stats.Read(f)
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql stats:", err)
		return exitFail
	}
	if *export {
		if err := rep.WriteExport(e.stdout, version); err != nil {
			fmt.Fprintln(e.stderr, "locksql stats:", err)
			return exitFail
		}
		return exitOK
	}
	fmt.Fprintf(e.stdout, "audit log %s\n", path)
	rep.WriteText(e.stdout, *top)
	return exitOK
}
