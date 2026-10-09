package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
)

// runInit is `locksql init [AGENT...]`: it writes the agent integration
// files into the project of the current directory and prints the steps for
// any file outside it. Without an agent named, it uses the agents found on
// this machine.
func runInit(e env, args []string) int {
	usage := "locksql init [" + strings.Join(agentinit.Agents(), "|") + " ...]"
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	agents, err := parseInterleaved(fs, args)
	if err != nil {
		return usageFail(e, "init", usage, err.Error())
	}
	if len(agents) == 0 && e.agentEnv != nil {
		if ae, err := e.agentEnv(); err == nil {
			agents = agentinit.Detect(ae)
			if len(agents) > 0 {
				fmt.Fprintf(e.stdout, "Agents found: %s\n", strings.Join(agents, ", "))
			}
		}
	}
	if len(agents) == 0 {
		return usageFail(e, "init", usage, "name at least one agent")
	}
	for _, a := range agents {
		if !slices.Contains(agentinit.Agents(), a) {
			return usageFail(e, "init", usage, fmt.Sprintf("unknown agent %q", a))
		}
	}

	root := agentinit.ProjectRoot(e.cwd)
	fmt.Fprintf(e.stdout, "Project: %s\n", root)
	seenAgent := map[string]bool{}
	seenPath := map[string]bool{}
	var notes []string
	for _, a := range agents {
		if seenAgent[a] {
			continue
		}
		seenAgent[a] = true
		res, err := agentinit.Init(root, a)
		for _, act := range res.Actions {
			if seenPath[act.Path] {
				continue
			}
			seenPath[act.Path] = true
			line := fmt.Sprintf("  %-9s  %s", act.Status, act.Path)
			if act.Detail != "" {
				line += " (" + act.Detail + ")"
			}
			fmt.Fprintln(e.stdout, line)
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "locksql init %s: %v\n", a, err)
			return exitFail
		}
		if res.Notes != "" {
			notes = append(notes, res.Notes)
		}
	}
	fmt.Fprintln(e.stdout)
	for _, n := range notes {
		fmt.Fprint(e.stdout, n)
	}
	fmt.Fprint(e.stdout, initNextSteps(root))
	return exitOK
}

// initNextSteps tells the human how to finish a project set-up. The
// project has a .locksql/config.toml now, so its agents dial the project's
// socket key: only a console started on the project serves them.
func initNextSteps(root string) string {
	return fmt.Sprintf("Next: add the database profile to %s (or run `locksql add`),\nthen run this in a separate terminal and keep it open while the agent works:\n  %s\n",
		filepath.Join(root, ".locksql", "config.toml"), client.StartCommand("", root))
}
