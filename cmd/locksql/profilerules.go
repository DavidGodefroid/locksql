package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// profileRulesUsage is the usage of `locksql profile rules`.
const profileRulesUsage = "locksql profile rules [--json] [--project DIR] [--profile NAME]"

// profileRules is one profile's auto mode as `locksql profile rules
// --json` prints it: what `lox run` shows at start and applies in auto
// mode (locksql#185). Rules has every action set.
type profileRules struct {
	Profile    string           `json:"profile"`
	Production bool             `json:"production"`
	Preset     string           `json:"preset,omitempty"`
	Rules      config.AutoRules `json:"rules"`
}

// profileRulesOut is the JSON of `locksql profile rules`.
type profileRulesOut struct {
	Lock     string         `json:"lock"`
	Profiles []profileRules `json:"profiles"`
}

// runProfileRules prints the effective auto rules of the profiles visible
// from the project (or of one): the defaults filled in, from the config
// files. The console enforces those of the policy it approved, which the
// human reviews at start and at :review.
func runProfileRules(e env, args []string) int {
	asJSON := verbs.WantsJSON(args)
	fs := flag.NewFlagSet("profile rules", flag.ContinueOnError)
	fs.Bool(verbs.FlagJSON, false, "print one line of JSON on stdout")
	project := fs.String(verbs.FlagProject, "", "project directory (default: the project of the current directory)")
	name := fs.String(verbs.FlagProfile, "", "only this profile")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return usageFailure(err).report(e, "profile rules", profileRulesUsage, asJSON)
	}
	dir := e.cwd
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return usageFailure(errors.New("--project: not a usable path")).report(e, "profile rules", profileRulesUsage, asJSON)
		}
		dir = abs
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return verbFailure{exit: exitUsage, code: verbs.CodeFailed, msg: err.Error()}.report(e, "profile rules", "", asJSON)
	}
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		if *name == "" || n == *name {
			names = append(names, n)
		}
	}
	if *name != "" && len(names) == 0 {
		return verbFailure{exit: exitUsage, code: verbs.CodeUsage, msg: "no such profile"}.report(e, "profile rules", "", asJSON)
	}
	sort.Strings(names)
	out := profileRulesOut{Lock: product.P.Name, Profiles: []profileRules{}}
	for _, n := range names {
		p := cfg.Profiles[n]
		r := p.AutoRules()
		out.Profiles = append(out.Profiles, profileRules{Profile: n, Production: p.Production, Preset: r.Preset(), Rules: r})
	}
	if asJSON {
		if err := verbs.WriteJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "locksql profile rules: %v\n", err)
			return exitFail
		}
		return exitOK
	}
	if len(out.Profiles) == 0 {
		fmt.Fprintln(e.stdout, "no profile: add one with `locksql profile add`")
		return exitOK
	}
	for _, p := range out.Profiles {
		label := p.Profile
		if p.Production {
			label += " " + e.paint.Red("(production)")
		}
		fmt.Fprintf(e.stdout, "%s: %s\n", e.paint.Bold(label), p.Rules.String())
	}
	return exitOK
}
