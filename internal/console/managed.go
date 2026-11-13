package console

import (
	"errors"
	"fmt"
	"io/fs"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// ManagedCheck checks the profiles names of cfg against the bounds of the
// company's managed file, as the console does at start: the policy of
// each, its PII rule set and the managed rules included, through
// ManagedBounds and lockkit's managed.Check. It opens no connection and
// reads no credential. It returns one "blocked by company policy: …" line
// per violation; an error is a profile whose policy cannot be read.
func ManagedCheck(cfg *config.Config, names []string) ([]string, error) {
	if cfg.Managed == nil {
		return nil, nil
	}
	var ucp string
	if cfg.ProjectRoot == "" {
		var err error
		if ucp, err = config.UserConfigPath(); err != nil {
			return nil, err
		}
	}
	dir := rulesDirFor(cfg.ProjectRoot, ucp)
	stateDir, _ := config.StateDir()
	var out []string
	for _, name := range names {
		p, ok := cfg.Profiles[name]
		if !ok {
			return nil, fmt.Errorf("no such profile %q", name)
		}
		var prev *config.Policy
		if stateDir != "" {
			if ap, err := config.LoadApproved(stateDir, config.ApprovedKey(cfg.ProjectRoot, name)); err == nil {
				prev = ap
			}
		}
		set, path, err := resolveRuleSet(dir, p, prev)
		if err != nil {
			return nil, err
		}
		r, err := pii.LoadRulesFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		mask, allow, modes, err := cfg.Managed.BoundsOf().ApplyPII(r.Mask, r.Allow, r.Modes)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", name, err)
		}
		p.PIIRules = set
		err = kconsole.CheckManaged(product.P, managedChecker{}, kpolicy{config.NewPolicy(p, mask, allow).WithModes(modes)}, cfg.Managed.File)
		out = append(out, kconsole.ManagedLines(err)...)
	}
	return out, nil
}

// managedChecker is the backend kconsole.CheckManaged takes before the
// Server exists (the start-up, ManagedCheck): it only bounds policies.
type managedChecker struct{ kconsole.Backend }

func (managedChecker) ManagedBounds(kp kconsole.Policy, m *managed.File) (managed.Bounds, error) {
	return managedBounds(kp, m)
}

// refuseManagedStart refuses a start whose managed file cannot be read or
// applied: printed, audited refused-managed, an error wrapping
// kconsole.ErrManaged.
func refuseManagedStart(o Options, err error) error {
	line := "blocked by company policy: " + err.Error()
	o.IO.Println(red + safeText(line, false) + reset)
	if log, lerr := audit.Open(o.StateDir); lerr == nil {
		_ = log.Append(audit.Record{Event: audit.EventPolicy, Profile: o.Profile, Decision: kconsole.DecisionRefusedManaged, Error: err.Error()})
	}
	return &managedStartError{line: line, err: err}
}

// managedStartError is a start refused by the managed file itself.
type managedStartError struct {
	line string
	err  error
}

func (e *managedStartError) Error() string { return kconsole.ErrManaged.Error() + ": " + e.err.Error() }
func (e *managedStartError) Unwrap() error { return kconsole.ErrManaged }

// ManagedLines are the lines that cite why the company's managed
// configuration refused a start, nil for any other error.
func ManagedLines(err error) []string {
	var me *managedStartError
	if errors.As(err, &me) {
		return []string{me.line}
	}
	return kconsole.ManagedLines(err)
}
