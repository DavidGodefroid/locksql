package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

const (
	configExportUsage = "locksql config export [--profile NAME]... [--project] [--no-pii] [--include-user] [--output FILE]"
	configImportUsage = "locksql config import FILE|- [--project] [--profile NAME]... [--replace] [--dry-run] [--yes] [--allow-loosen] [--local NAME.KEY=VALUE]..."
)

// configHeader opens a config file the import writes.
const configHeader = `# locksql configuration, written by locksql config import (the previous
# file is config.toml.bak). It never holds a secret: the console asks for
# the password, or reads it from its own keychain or Vault.
`

// runConfig dispatches `locksql config export|import`.
func runConfig(e env, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "export":
			return runConfigExport(e, args[1:])
		case "import":
			return runConfigImport(e, args[1:])
		}
	}
	fmt.Fprintf(e.stderr, "usage: %s\n       %s\n", configExportUsage, configImportUsage)
	return exitUsage
}

// configScope is the config file and the directory of the PII rule sets
// that an export reads and an import writes.
type configScope struct {
	name    string // "user" or "project"
	path    string // config.toml
	dir     string // the directory of config.toml and of pii/
	baseDir string // relative sqlite paths resolve against it
}

func scopeOf(e env, project bool) (configScope, error) {
	if project {
		root, ok := config.FindProjectRoot(e.cwd)
		if !ok {
			return configScope{}, errors.New("--project: no .locksql/config.toml in this directory or above it")
		}
		dir := filepath.Join(root, ".locksql")
		return configScope{name: "project", path: filepath.Join(dir, "config.toml"), dir: dir, baseDir: root}, nil
	}
	p, err := config.UserConfigPath()
	if err != nil {
		return configScope{}, err
	}
	return configScope{name: "user", path: p, dir: filepath.Dir(p), baseDir: filepath.Dir(p)}, nil
}

// readConfig reads the scope's config file: nil when it does not exist. A
// config file that is a symbolic link is refused.
func (s configScope) readConfig() ([]byte, fs.FileMode, error) {
	st, err := os.Lstat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0o644, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file (a symbolic link?): refused", s.path)
	}
	data, err := os.ReadFile(s.path)
	return data, st.Mode().Perm(), err
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runConfigExport is `locksql config export`: the shared keys of the
// scope's profiles and the PII rule sets they use, as JSON.
func runConfigExport(e env, args []string) int {
	fset := flag.NewFlagSet("config export", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	var only listFlag
	fset.Var(&only, "profile", "")
	project := fset.Bool("project", false, "")
	noPII := fset.Bool("no-pii", false, "")
	includeUser := fset.Bool("include-user", false, "")
	output := fset.String("output", "", "")
	pos, err := parseInterleaved(fset, args)
	if err != nil || len(pos) > 0 {
		msg := "unexpected argument"
		if err != nil {
			msg = err.Error()
		}
		return usageFail(e, "config export", configExportUsage, msg)
	}
	sc, err := scopeOf(e, *project)
	if err != nil {
		return usageFail(e, "config export", configExportUsage, err.Error())
	}
	share, warns, err := exportScope(sc, only, *noPII, *includeUser)
	for _, w := range warns {
		fmt.Fprintln(e.stderr, "locksql config export: "+w)
	}
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql config export: "+err.Error()+"; nothing exported")
		return exitFail
	}
	var b bytes.Buffer
	if err := config.EncodeShare(&b, share); err != nil {
		fmt.Fprintln(e.stderr, "locksql config export: "+err.Error())
		return exitFail
	}
	if *output == "" {
		_, _ = e.stdout.Write(b.Bytes())
		return exitOK
	}
	if err := writeAtomic(*output, b.Bytes(), 0o600); err != nil {
		fmt.Fprintln(e.stderr, "locksql config export: "+err.Error())
		return exitFail
	}
	fmt.Fprintf(e.stderr, "exported %d profiles and %d PII rule sets to %s; it describes your databases: share it only with your team (a private repository)\n",
		len(share.Profiles), len(share.PII), *output)
	return exitOK
}

// exportScope builds the share of the scope sc. A profile that cannot be
// shared is left out with a warning; any other failure fails the whole
// export.
func exportScope(sc configScope, only []string, noPII, includeUser bool) (config.Share, []string, error) {
	share := config.Share{Format: config.ShareFormat, Version: version, Profiles: map[string]config.SharedProfile{}}
	data, _, err := sc.readConfig()
	if err != nil {
		return share, nil, err
	}
	if data == nil {
		return share, nil, fmt.Errorf("no config file at %s", sc.path)
	}
	profiles, err := config.ParseProfiles(data, sc.path, sc.baseDir)
	if err != nil {
		return share, nil, err
	}
	sets, err := pii.LoadSets(sc.dir)
	if err != nil {
		return share, nil, err
	}
	names := slices.Sorted(maps.Keys(profiles))
	if len(only) > 0 {
		for _, n := range only {
			if _, ok := profiles[n]; !ok {
				return share, nil, fmt.Errorf("no profile %q in %s", n, sc.path)
			}
		}
		names = only
	}
	var warns []string
	used := map[string]bool{}
	for _, n := range names {
		set := pii.FileSet(profiles[n], hasSet(sets))
		sp, err := config.ExportProfile(profiles[n], set, includeUser)
		if errors.Is(err, config.ErrNotShareable) {
			warns = append(warns, "skipped: "+err.Error())
			continue
		}
		if err != nil {
			return share, warns, err
		}
		share.Profiles[n] = sp
		used[set] = true
	}
	if !noPII {
		for set := range used {
			if r, ok := sets[set]; ok {
				if share.PII == nil {
					share.PII = map[string]config.SharedRules{}
				}
				share.PII[set] = pii.ToShared(r)
			}
		}
	}
	if len(share.Profiles) == 0 {
		return share, warns, errors.New("no profile to export")
	}
	return share, warns, nil
}

func hasSet(sets map[string]pii.Rules) func(string) bool {
	return func(s string) bool { _, ok := sets[s]; return ok }
}

// importPlan is what an import would change.
type importPlan struct {
	oldConfig, newConfig []byte
	mode                 fs.FileMode
	newSets              map[string]pii.Rules // the sets the import writes
	changes              map[string][]config.Change
	// setChanges compares each written set with the set on disk, whatever
	// profile the console resolves to it.
	setChanges map[string][]config.Change
	loosens    bool
	skipped    []config.Skipped
	conflicts  []string
}

// runConfigImport is `locksql config import`.
func runConfigImport(e env, args []string) int {
	fset := flag.NewFlagSet("config import", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	var only, locals listFlag
	fset.Var(&only, "profile", "")
	fset.Var(&locals, "local", "")
	project := fset.Bool("project", false, "")
	replace := fset.Bool("replace", false, "")
	dryRun := fset.Bool("dry-run", false, "")
	yes := fset.Bool("yes", false, "")
	allowLoosen := fset.Bool("allow-loosen", false, "")
	pos, err := parseInterleaved(fset, args)
	if err != nil {
		return usageFail(e, "config import", configImportUsage, err.Error())
	}
	if len(pos) != 1 {
		return usageFail(e, "config import", configImportUsage, "give one file, or - for stdin")
	}
	local, err := parseLocals(locals)
	if err != nil {
		return usageFail(e, "config import", configImportUsage, err.Error())
	}
	sc, err := scopeOf(e, *project)
	if err != nil {
		return usageFail(e, "config import", configImportUsage, err.Error())
	}
	failf := func(format string, a ...any) int {
		fmt.Fprintf(e.stderr, "locksql config import: "+format+"; nothing written\n", a...)
		return exitFail
	}
	var data []byte
	if pos[0] == "-" {
		data, err = io.ReadAll(io.LimitReader(e.stdin, 16<<20))
	} else {
		data, err = os.ReadFile(pos[0])
	}
	if err != nil {
		return failf("%v", err)
	}
	share, err := config.DecodeShare(data)
	if err != nil {
		return failf("%v", err)
	}
	plan, err := planImport(sc, share, config.ImportOptions{Only: only, Replace: *replace, Local: local})
	if err != nil {
		return failf("%v", err)
	}
	printPlan(e, plan)
	rec := audit.Record{Event: audit.EventConfigImport, Scope: sc.name, Profiles: slices.Sorted(maps.Keys(plan.changes)), AllowLoosen: *allowLoosen}
	if bytes.Equal(plan.oldConfig, plan.newConfig) && len(plan.newSets) == 0 {
		fmt.Fprintln(e.stdout, "nothing to change")
		return exitOK
	}
	if plan.loosens && !*allowLoosen {
		rec.Decision = "refused"
		auditImport(e, rec)
		return failf("the import loosens the policy (in red above); check it, then run it again with --allow-loosen")
	}
	if *dryRun {
		fmt.Fprintln(e.stdout, "--dry-run: nothing written")
		return exitOK
	}
	if !*yes {
		if !e.tty {
			return failf("not a terminal: pass --yes to write")
		}
		fmt.Fprintf(e.stdout, "Write these changes to %s? [y/N] ", sc.path)
		ans, _ := bufio.NewReader(e.stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return failf("not confirmed")
		}
	}
	if err := writePlan(sc, plan); err != nil {
		fmt.Fprintln(e.stderr, "locksql config import: "+err.Error())
		return exitFail
	}
	rec.Decision = "applied"
	auditImport(e, rec)
	fmt.Fprintf(e.stdout, "written %s (previous file: %s.bak)\n", sc.path, filepath.Base(sc.path))
	if plan.loosens {
		fmt.Fprintln(e.stdout, "the console asks you to approve each loosened profile at its next start, as for a hand edit")
	}
	fmt.Fprintln(e.stdout, "run locksql doctor to check this machine (local files such as tls_ca, the console account's known_hosts for a new bastion)")
	return exitOK
}

// parseLocals reads --local NAME.KEY=VALUE values. The key may hold a dot
// (ssh.key): the profile name is up to the first dot, as profile names
// may hold dots too only the local keys are tried.
func parseLocals(vals []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, v := range vals {
		lhs, val, ok := strings.Cut(v, "=")
		if !ok || val == "" {
			// Without '=', lhs is the whole argument: perhaps a value.
			return nil, errors.New("--local: want NAME.KEY=VALUE")
		}
		found := false
		for _, k := range config.LocalKeys {
			if name, cut := strings.CutSuffix(lhs, "."+k); cut && name != "" {
				if out[name] == nil {
					out[name] = map[string]string{}
				}
				out[name][k] = val
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("--local: only %s can be given (NAME.KEY=VALUE)", strings.Join(config.LocalKeys, ", "))
		}
	}
	return out, nil
}

// planImport computes the merged config and rule sets and what they change.
// Nothing is written.
func planImport(sc configScope, share *config.Share, o config.ImportOptions) (*importPlan, error) {
	old, mode, err := sc.readConfig()
	if err != nil {
		return nil, err
	}
	f, err := config.ParseConfigFile(old, sc.path, sc.baseDir)
	if err != nil {
		return nil, err
	}
	oldProfiles, _ := config.ParseProfiles(old, sc.path, sc.baseDir)
	skipped, err := f.Import(share, o)
	if err != nil {
		return nil, err
	}
	p := &importPlan{oldConfig: old, mode: mode, skipped: skipped, newSets: map[string]pii.Rules{}, changes: map[string][]config.Change{},
		setChanges: map[string][]config.Change{}}
	p.newConfig = f.TOML(configHeader)
	if bytes.Equal(old, p.newConfig) || sameProfiles(old, p.newConfig, sc) {
		p.newConfig = old
	}
	newProfiles, err := config.ParseProfiles(p.newConfig, sc.path, sc.baseDir)
	if err != nil {
		return nil, err
	}

	oldSets, err := pii.LoadSets(sc.dir)
	if err != nil {
		return nil, err
	}
	// The sets to import: those of the imported profiles, and every set of
	// the file when no --profile narrows it.
	wanted := map[string]bool{}
	skip := map[string]bool{}
	for _, s := range skipped {
		skip[s.Profile] = true
	}
	for n, sp := range share.Profiles {
		if (len(o.Only) == 0 || slices.Contains(o.Only, n)) && !skip[n] && sp.PIIRules != "" {
			wanted[sp.PIIRules] = true
		}
	}
	if len(o.Only) == 0 {
		for set := range share.PII {
			wanted[set] = true
		}
	}
	sets := maps.Clone(oldSets)
	for _, set := range slices.Sorted(maps.Keys(wanted)) {
		shared, ok := share.PII[set]
		if !ok {
			continue
		}
		in, err := pii.FromShared(shared)
		if err != nil {
			return nil, fmt.Errorf("PII rule set %q: %v", set, err)
		}
		next := in
		if !o.Replace {
			var conflicts []string
			next, conflicts = pii.MergeRules(oldSets[set], in)
			for _, c := range conflicts {
				p.conflicts = append(p.conflicts, set+": "+c)
			}
		}
		if prev, had := oldSets[set]; !had || !sameRules(prev, next) {
			p.newSets[set] = next
			sets[set] = next
			if ch := setDiff(prev, next); len(ch) > 0 {
				p.setChanges[set] = ch
				for _, c := range ch {
					p.loosens = p.loosens || c.Loosens
				}
			}
		}
	}

	policy := func(pr config.Profile, sets map[string]pii.Rules) config.Policy {
		set := pii.FileSet(pr, hasSet(sets))
		r := sets[set]
		pr.PIIRules = set
		return config.NewPolicy(pr, r.Mask, r.Allow).WithModes(r.Modes)
	}
	for _, n := range slices.Sorted(maps.Keys(newProfiles)) {
		np := policy(newProfiles[n], sets)
		op, had := oldProfiles[n]
		if !had {
			p.changes[n] = []config.Change{{Field: "profile", New: "new profile", Loosens: true}}
			p.loosens = true
			continue
		}
		if ch := config.Diff(policy(op, oldSets), np); len(ch) > 0 {
			p.changes[n] = ch
			for _, c := range ch {
				p.loosens = p.loosens || c.Loosens
			}
		}
	}
	for n := range oldProfiles {
		if _, ok := newProfiles[n]; !ok {
			p.changes[n] = []config.Change{{Field: "profile", Old: n, New: "removed"}}
		}
	}
	return p, nil
}

// sameProfiles reports whether two config files hold the same profiles,
// key for key: an import that changes nothing keeps the file as it is.
func sameProfiles(a, b []byte, sc configScope) bool {
	if a == nil {
		return false
	}
	fa, err1 := config.ParseConfigFile(a, sc.path, sc.baseDir)
	fb, err2 := config.ParseConfigFile(b, sc.path, sc.baseDir)
	return err1 == nil && err2 == nil && bytes.Equal(fa.TOML(""), fb.TOML(""))
}

// setDiff lists the rule changes from old to next with config.Diff's
// classes: a removed mask rule, an added allow rule or a mode other than
// redact loosens.
func setDiff(old, next pii.Rules) []config.Change {
	pol := func(r pii.Rules) config.Policy {
		return config.NewPolicy(config.Profile{}, r.Mask, r.Allow).WithModes(r.Modes)
	}
	return config.Diff(pol(old), pol(next))
}

func sameRules(a, b pii.Rules) bool {
	sa, sb := pii.ToShared(a), pii.ToShared(b)
	return slices.Equal(sa.Mask, sb.Mask) && slices.Equal(sa.Allow, sb.Allow)
}

// printPlan shows what the import changes: per profile, loosening changes
// in red; then the PII rule sets written, mode conflicts and skipped
// profiles.
func printPlan(e env, p *importPlan) {
	printChanges := func(title string, changes []config.Change) {
		fmt.Fprintln(e.stdout, title+":")
		for _, c := range changes {
			line := "  " + c.Field + ": "
			switch {
			case c.Old == "":
				line += c.New
			case c.New == "":
				line += c.Old + " → (none)"
			default:
				line += c.Old + " → " + c.New
			}
			if c.Loosens {
				line = e.paint.Red(line + " (loosens)")
			}
			fmt.Fprintln(e.stdout, line)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(p.changes)) {
		printChanges("profile "+n, p.changes[n])
	}
	for _, s := range slices.Sorted(maps.Keys(p.newSets)) {
		r := p.newSets[s]
		title := fmt.Sprintf("PII rule set %s (%d mask, %d allow rules)", s, len(r.Mask), len(r.Allow))
		if ch := p.setChanges[s]; len(ch) > 0 {
			printChanges(title, ch)
		} else {
			fmt.Fprintln(e.stdout, title)
		}
	}
	for _, c := range p.conflicts {
		fmt.Fprintln(e.stdout, "PII mode conflict: "+c)
	}
	for _, s := range p.skipped {
		fmt.Fprintf(e.stderr, "not imported: profile %s: %s\n", s.Profile, s.Reason)
	}
}

// writePlan puts the new config file and rule sets in place, all or
// nothing: every file is first written next to its target, every target
// copied to *.bak, then the files are renamed into place; a failure undoes
// the renames already done. A legacy pii.toml is first moved to the
// default set, as the console does.
func writePlan(sc configScope, p *importPlan) (err error) {
	if len(p.newSets) > 0 {
		if _, _, err := pii.MigrateLegacy(sc.dir); err != nil {
			return err
		}
	}
	type target struct {
		path, tmp string
		old       []byte
		existed   bool
		perm      fs.FileMode
	}
	var targets []*target
	defer func() {
		for _, t := range targets {
			if t.tmp != "" {
				os.Remove(t.tmp)
			}
		}
	}()
	stage := func(path string, perm fs.FileMode, write func(tmp string) error) error {
		t := &target{path: path, perm: perm}
		if st, err := os.Lstat(path); err == nil {
			if !st.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file (a symbolic link?): refused", path)
			}
			if t.old, err = os.ReadFile(path); err != nil {
				return err
			}
			t.existed, t.perm = true, st.Mode().Perm()
		}
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		f, err := os.CreateTemp(dir, ".locksql-import-*.tmp")
		if err != nil {
			return err
		}
		t.tmp = f.Name()
		f.Close()
		targets = append(targets, t)
		if err := write(t.tmp); err != nil {
			return err
		}
		return os.Chmod(t.tmp, t.perm)
	}
	if !bytes.Equal(p.oldConfig, p.newConfig) {
		if err := stage(sc.path, 0o644, func(tmp string) error { return os.WriteFile(tmp, p.newConfig, 0o600) }); err != nil {
			return err
		}
	}
	for _, set := range slices.Sorted(maps.Keys(p.newSets)) {
		path, err := pii.SetPath(sc.dir, set)
		if err != nil {
			return err
		}
		r := p.newSets[set]
		if err := stage(path, 0o644, func(tmp string) error { return pii.SaveRulesFile(tmp, r) }); err != nil {
			return err
		}
	}
	for _, t := range targets {
		if t.existed {
			if err := writeAtomic(t.path+".bak", t.old, t.perm); err != nil {
				return err
			}
		}
	}
	for i, t := range targets {
		if err := renameFile(t.tmp, t.path); err != nil {
			for _, done := range targets[:i] {
				if done.existed {
					_ = writeAtomic(done.path, done.old, done.perm)
				} else {
					_ = os.Remove(done.path)
				}
			}
			return fmt.Errorf("writing %s: %v; the files already written were rolled back", t.path, err)
		}
		t.tmp = ""
	}
	return nil
}

// writeAtomic replaces path with data through a temporary file in its
// directory, with mode perm. A path that is a symbolic link is refused.
func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (a symbolic link?): refused", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".locksql-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// auditImport writes the import's record to this account's audit log; a
// log that cannot be written is reported, not fatal.
func auditImport(e env, rec audit.Record) {
	state, err := config.StateDir()
	if err == nil {
		var log *audit.Log
		if log, err = audit.Open(state); err == nil {
			err = log.Append(rec)
		}
	}
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql config import: audit log: "+err.Error())
	}
}

// renameFile is os.Rename; tests replace it.
var renameFile = os.Rename
