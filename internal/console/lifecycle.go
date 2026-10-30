package console

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/tunnel"
	"github.com/DavidGodefroid/lockkit/ui"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/product"
	"github.com/DavidGodefroid/locksql/internal/proxycmd"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// ErrConfig marks usage and configuration errors (exit code 3). It is
// lockkit's, which the isolation checks wrap too.
var ErrConfig = kconsole.ErrConfig

// errPrivilegeAudit marks a reconnection stopped by the privilege audit:
// the console ends, as it would have at start-up.
var errPrivilegeAudit = errors.New("privilege audit")

// connectTimeout bounds one connection attempt.
const connectTimeout = 30 * time.Second

// starter carries the start-up state of Run.
type starter struct {
	o       Options
	io      IO
	log     *audit.Log
	profile config.Profile
	user    string
	// privWarns are the start-up privilege audit's findings.
	privWarns []string
	// approver takes the human decisions of the start-up; nil means typed.
	approver Approver
	// lockedOut is set by decide on the third non-matching finger in a
	// row: the console ends even after a decision whose refusal it would
	// otherwise go past (offerSaveAs).
	lockedOut bool
	// vaultToken is the Vault token the human typed (credentials =
	// "vault"): kept in memory for the session, so reconnects and lease
	// renewals do not ask again; nil until asked, and after Vault refused
	// it. wipeVaultToken wipes it when the console ends.
	vaultToken []byte
}

// wipeVaultToken wipes the Vault token the human typed.
func (st *starter) wipeVaultToken() {
	secrets.Wipe(st.vaultToken)
	st.vaultToken = nil
}

// errLockedOut ends a start-up after too many non-matching fingers.
var errLockedOut = errors.New("console: fingerprint: three non-matching fingers")

// checkLockedOut is errLockedOut once a start-up decision met the third
// non-matching finger in a row; every start-up step that goes on after a
// refused decision calls it.
func (st *starter) checkLockedOut() error {
	if st.lockedOut {
		return errLockedOut
	}
	return nil
}

// decide asks the approver and explains a missing finger; the caller stops
// on any outcome other than Approved, or calls checkLockedOut when it goes
// on.
func (st *starter) decide(ctx context.Context, d Decision) Result {
	a := kconsole.Asker{IO: st.io, Approver: st.appr(), End: func(string) { st.lockedOut = true }}
	return a.Decide(ctx, d)
}

// appr is the approver in force: typed when none was set (a starter built
// without Run).
func (st *starter) appr() Approver {
	if st.approver == nil {
		return newTypedApprover(st.io)
	}
	return st.approver
}

// audit writes rec; a failure is told and returned: an approval at start
// is not saved without its record.
func (st *starter) audit(rec audit.Record) error {
	rec.Profile, rec.Engine, rec.DBUser = st.profile.Name, st.profile.Engine, st.user
	rec.Host = st.profile.Host
	if st.profile.Engine == config.EngineSQLite {
		rec.Host = st.profile.Path
	}
	if st.profile.SSH != nil && rec.SSHHost == "" {
		rec.SSHHost = st.profile.SSH.Host
	}
	if err := st.log.Append(rec); err != nil {
		st.io.Println("audit log write failed: " + err.Error())
		return err
	}
	return nil
}

// failed records, when recorded is set (a widening already on record),
// that the change it announced did not happen, and returns err.
func (st *starter) failed(recorded bool, err error) error {
	if recorded {
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "failed", Error: secrets.Sanitize(err)})
	}
	return err
}

// errApprovalUnrecorded: the human approved a policy at start, but the
// record could not be written; nothing is saved and the console stops.
var errApprovalUnrecorded = errors.New("console: the approval of the policy could not be recorded in the audit log")

// rulesDirFor is the directory of the PII rule sets: the project's
// .locksql when there is one, else the user config directory.
func rulesDirFor(projectRoot, userConfigPath string) string {
	if projectRoot != "" {
		return filepath.Join(projectRoot, filepath.Dir(pii.RulesFile))
	}
	return filepath.Dir(userConfigPath)
}

// resolveRuleSet is the PII rule set of profile p and its file in dir.
// pii_rules wins; without it, a profile approved before named sets, or
// approved on the default set since, keeps the default set (the migrated
// pii.toml) while that set exists; any other profile gets its own set,
// named after it. approved is nil when nothing was approved yet.
func resolveRuleSet(dir string, p config.Profile, approved *config.Policy) (string, string, error) {
	if err := pii.CheckSetsDir(dir); err != nil {
		return "", "", err
	}
	set := config.RuleSetOf(p)
	if p.PIIRules == "" && approved != nil && pii.SetExists(dir, pii.DefaultSet) {
		if a := approved.Profile.PIIRules; a == "" || a == pii.DefaultSet {
			set = pii.DefaultSet
		}
	}
	path, err := pii.SetPath(dir, set)
	return set, path, err
}

// implicitSharingNotice is one line when profile p, without pii_rules,
// shares its rule set set by accident: another profile uses it too (a
// name that differs only by case, or that another profile names in its
// pii_rules), or p is named "default", the set the former pii.toml
// became. A profile kept on the migrated default set gets no notice, even
// when another profile names that set: the migration said so once. All
// profiles of one console keep their sets in the same directory
// (rulesDirFor), so the comparison never crosses scopes. "" otherwise.
func implicitSharingNotice(p config.Profile, set string, all map[string]config.Profile) string {
	if p.PIIRules != "" || set == pii.DefaultSet && config.RuleSetOf(p) != pii.DefaultSet {
		// Named on purpose, or kept on the migrated default set, which the
		// migration notice covered, whoever else uses it.
		return ""
	}
	var with []string
	for name, q := range all {
		if name != p.Name && config.RuleSetOf(q) == set {
			with = append(with, name)
		}
	}
	sort.Strings(with)
	switch {
	case len(with) > 0:
		return fmt.Sprintf("note: profile %s sets no pii_rules and shares the PII rule set %q with %s; set pii_rules in its profile to give it a set of its own, or to %q to share it on purpose",
			p.Name, set, strings.Join(with, ", "), set)
	case set == pii.DefaultSet:
		return fmt.Sprintf("note: profile %s sets no pii_rules and uses the PII rule set %q, which the former pii.toml became and the profiles approved before keep; set pii_rules in its profile to give it a set of its own",
			p.Name, set)
	}
	return ""
}

// migrateRules moves the legacy pii.toml of dir to the default set, once,
// and returns the notice to print then; "" when nothing moved.
func migrateRules(dir string) (string, error) {
	from, to, err := pii.MigrateLegacy(dir)
	if err != nil || from == "" {
		return "", err
	}
	return fmt.Sprintf("note: PII rules are now kept in named sets; %s moved to the set %q (%s). The profiles approved before keep using it until you give them pii_rules = \"<set>\"; any other profile uses a set named after it.", from, pii.DefaultSet, to), nil
}

// legacyRulesNotice is one line when, outside a project, cwd holds a
// .locksql/pii.toml (where rules lived before the user-dir file) and the
// user-dir rules file does not exist yet; "" otherwise. Nothing is copied:
// the human decides.
func legacyRulesNotice(cwd, projectRoot, rulesPath string) string {
	if projectRoot != "" {
		return ""
	}
	old := filepath.Join(cwd, pii.RulesFile)
	if st, err := os.Stat(old); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	if _, err := os.Stat(rulesPath); err == nil {
		return ""
	}
	return fmt.Sprintf("note: %s is no longer read outside a project; PII rules now live in %s (copy it there to keep its rules)", old, rulesPath)
}

// newIsolationEnv builds what Run's isolation checks read; tests replace it.
var newIsolationEnv = realIsolationEnv

// policyFromFiles reads the current policy of profile from the config
// found from cwd and from the PII rule set at rulesPath, mask modes
// included. set names that rule set: it is resolved once, at start, so a
// pii_rules change applies at the next start.
func policyFromFiles(cwd, profile, rulesPath, set string) (config.Policy, error) {
	c, err := config.Load(cwd)
	if err != nil {
		return config.Policy{}, err
	}
	cp, ok := c.Profiles[profile]
	if !ok {
		return config.Policy{}, fmt.Errorf("profile %q is no longer in the config", profile)
	}
	r, err := pii.LoadRulesFile(rulesPath)
	if err != nil {
		return config.Policy{}, err
	}
	cp.PIIRules = set
	return config.NewPolicy(cp, r.Mask, r.Allow).WithModes(r.Modes), nil
}

// Run is `locksql console`: the start-up sequence of spec §6, then the
// request loop until Ctrl-C, logout, :quit or a timeout.
func Run(ctx context.Context, o Options) error {
	if o.IO == nil {
		return errors.New("console: no terminal")
	}
	// Same-user mode, then any other isolation failure, is refused before
	// any prompt or file write: nothing is audited, the state directory is
	// not touched.
	iso, err := checkIsolation(o.IO, newIsolationEnv(o.TTY))
	if err != nil {
		return err
	}
	if iso.verifier != nil {
		defer closeVerifier(iso.verifier)
	}
	// Level 2 widens nothing from a typed answer: the start-up widening
	// flags are refused before any prompt or file write.
	if iso.verifier != nil && (o.Auto || o.AllowUnmask || o.ShowResults) {
		return fmt.Errorf("%w: level 2 does not accept --auto, --allow-unmask or --show-results", ErrConfig)
	}
	// Level 1: the agent's account can read the console window, so the
	// clear results would reach it. --auto and --allow-unmask stay.
	if iso.desktop && iso.verifier == nil && o.ShowResults {
		return fmt.Errorf("%w: level 1 does not accept --show-results: the agent's account can read this window", ErrConfig)
	}
	// Hub mode: lockhub decides, with its own auto mode.
	if o.Hub.Enabled() && o.Auto {
		return fmt.Errorf("%w: --auto is refused with --hub: lockhub decides", ErrConfig)
	}
	hardenErr := hardenProcess()
	if hardenErr != nil {
		o.IO.Println(paint.Warn(red + "could not disable core dumps: " + safeText(hardenErr.Error(), false) + reset))
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		o.Cwd = wd
	}
	if o.StateDir == "" {
		d, err := config.StateDir()
		if err != nil {
			return err
		}
		o.StateDir = d
	}
	var hub *kconsole.Hub
	if o.Hub.Enabled() {
		// The flags, the pinned hub key and the instance key are checked
		// before any prompt.
		if o.Hub.KeyFile != "" && o.Hub.URL != "" && o.Hub.Instance != "" {
			// The instance names the copy of the key: checked first.
			if !hubclient.ValidInstance(o.Hub.Instance) {
				return fmt.Errorf("%w: --instance %q is not a valid instance name", ErrConfig, o.Hub.Instance)
			}
			if o.Hub.KeyFile, err = pinHubKey(o.StateDir, o.Hub.Instance, o.Hub.KeyFile); err != nil {
				return err
			}
		}
		if hub, err = kconsole.OpenHub(product.P, o.Hub, o.StateDir, o.Now); err != nil {
			return err
		}
		// The plans store holds a lock file: closed on every return, after
		// the watch has stopped (deferred later, so run first).
		defer hub.Close()
	}

	cfg, err := config.Load(o.Cwd)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	p, ok := cfg.Profiles[o.Profile]
	if !ok {
		names := make([]string, 0, len(cfg.Profiles))
		for n := range cfg.Profiles {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("%w: no profile %q (profiles: %s)", ErrConfig, o.Profile, strings.Join(names, ", "))
	}
	var ucp string
	if cfg.ProjectRoot == "" {
		if ucp, err = config.UserConfigPath(); err != nil {
			return err
		}
	}
	rulesDir := rulesDirFor(cfg.ProjectRoot, ucp)
	key := config.ApprovedKey(cfg.ProjectRoot, p.Name)
	n, err := migrateRules(rulesDir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if n != "" {
		o.IO.Println(safeText(n, false))
	}
	var prev *config.Policy
	if ap, err := config.LoadApproved(o.StateDir, key); err == nil {
		prev = ap // none yet, or unreadable: startPolicy reports it
	}
	ruleSet, rulesPath, err := resolveRuleSet(rulesDir, p, prev)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if n := legacyRulesNotice(o.Cwd, cfg.ProjectRoot, rulesPath); n != "" {
		o.IO.Println(safeText(n, false))
	}
	if n := implicitSharingNotice(p, ruleSet, cfg.Profiles); n != "" {
		o.IO.Println(paint.Warn(safeText(n, false)))
	}
	// A production profile, loaded or approved before, never runs in an
	// X11 session: refused before the policy review, so that no X client
	// can answer it and no approval is written.
	if err := refuseX11Production(iso, o.StateDir, key, p); err != nil {
		return err
	}
	log, err := audit.Open(o.StateDir)
	if err != nil {
		return err
	}
	// With a verifier (level 2) every approval takes a fingerprint after the
	// typed answer, and never falls back to a typed answer alone; without
	// one (level 1, session) approvals are typed.
	appr := newTypedApprover(o.IO)
	if iso.desktop {
		appr = newDesktopTypedApprover(o.IO)
	}
	if iso.verifier != nil {
		appr = newFingerprintApprover(o.IO, iso.verifier, iso.sys.Finger, FingerDeadline)
	}
	st := &starter{o: o, io: o.IO, log: log, profile: p, approver: appr}
	defer st.wipeVaultToken()

	loadPolicy := func() (config.Policy, error) {
		return policyFromFiles(o.Cwd, o.Profile, rulesPath, ruleSet)
	}
	cur, err := loadPolicy()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}

	// 1. Policy check.
	approved, refusedFP, err := st.startPolicy(ctx, o.StateDir, key, cur)
	if err != nil {
		return err
	}
	if err := st.checkLockedOut(); err != nil {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}
	if approved.Profile.PIIRules == "" {
		// Approved before named sets: record the set in force, so that a
		// later switch is shown as one.
		approved.Profile.PIIRules = ruleSet
		if err := config.SaveApproved(o.StateDir, key, approved); err != nil {
			return err
		}
	}
	p = approved.Profile
	st.profile = p
	if err := hardenRefusal(hardenErr, p.Production); err != nil {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}

	// X11 is refused on a production profile, before any secret is asked
	// for.
	if err := iso.refuseX11IfProduction(p); err != nil {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}

	// 2. Production banner and typed profile name.
	if p.Production {
		o.IO.Println(red + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset)
		o.IO.Println(red + "  " + ui.MarkWarn + " PRODUCTION profile " + p.Name + " (" + st.where() + ")" + reset)
		o.IO.Println(red + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset)
		bell(o.IO)
		ans, ok := o.IO.Ask(ctx, fmt.Sprintf("Type the profile name %q to continue: ", p.Name), ApprovalTimeout)
		if !ok || strings.TrimSpace(ans) != p.Name {
			return errors.New("console: production profile not confirmed")
		}
		if o.Auto {
			o.IO.Println("--auto is ignored on production profiles: every statement is prompted")
		}
	}

	for _, l := range flagNotices(o, p) {
		o.IO.Println(l)
	}

	// 3. Host (confirmed with the policy) and user.
	o.IO.Println(paint.OK(fmt.Sprintf("profile %s · %s %s · PII rules %q %s", paint.Bold(p.Name), p.Engine, st.where(), p.PIIRules, paint.Dim("(approved policy)"))))
	st.user = p.User
	// With credentials = "vault" the user comes with the login (connect).
	if st.user == "" && p.Engine != config.EngineSQLite && p.Credentials != config.CredentialsVault {
		ans, ok := o.IO.Ask(ctx, "Database user: ", ApprovalTimeout)
		st.user = strings.TrimSpace(ans)
		if !ok || st.user == "" {
			return errors.New("console: no database user")
		}
	}

	// 4. Credentials and connection.
	sess, err := st.connect(ctx, true)
	if err != nil {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "failed", Error: err.Error()})
		return err
	}
	closeSess := func() {
		if sess != nil {
			_ = sess.Close()
		}
	}

	// 5. Version and privilege audit.
	o.IO.Println(paint.OK(fmt.Sprintf("connected: %s %s", sess.Flavor(), safeText(sess.ServerVersion(), false))))
	if err := st.privileges(ctx, sess); err != nil {
		closeSess()
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}

	// 6. Databases.
	dbs, err := sess.Databases(ctx)
	if err != nil {
		closeSess()
		return fmt.Errorf("console: listing databases: %s", secrets.Sanitize(err))
	}
	dbs = servedDatabases(p.Database, dbs)
	o.IO.Println(paint.OK("databases: " + safeText(strings.Join(dbs, ", "), false)))
	health := &ipc.Health{Separated: iso.sys != nil, Display: iso.display.Kind, Privileges: nonNil(st.privWarns),
		ReadOnly: p.Tier == config.TierRead}
	probeDB := p.Database
	if probeDB == "" && len(dbs) > 0 {
		probeDB = dbs[0]
	}
	if _, err := sess.Explain(ctx, probeDB, "SELECT 1"); err == nil {
		health.ExplainOK = true
	} else {
		o.IO.Println(paint.Warn(red + "warning: EXPLAIN does not work on this server: " + safeText(secrets.Sanitize(err), false) + reset))
	}

	// 7. PII first-run proposal.
	approved, err = st.piiBootstrap(ctx, sess, dbs, rulesPath, o.StateDir, key, approved)
	if err != nil {
		closeSess()
		return err
	}

	// 8. Socket.
	path, err := iso.socketPath(config.ProjectKey(o.Cwd), p.Name)
	if err != nil {
		closeSess()
		return err
	}
	ln, err := iso.listen(path)
	if err != nil {
		closeSess()
		return err
	}

	s, err := NewServer(ServerConfig{
		Policy: approved, RulesPath: rulesPath, StateDir: o.StateDir, ApprovedKey: key,
		Session: sess, DBUser: st.user, Databases: dbs, Audit: log, IO: o.IO, Approver: st.approver, Fingerprint: iso.verifier != nil, Boundary: iso.boundary(), Now: o.Now,
		Auto: o.Auto, AllowUnmask: o.AllowUnmask, ShowResults: o.ShowResults, Version: o.Version, LoadPolicy: loadPolicy,
		Reconnect: st.reconnect, Quantum: ResponseQuantum, PeerAllowed: iso.peerCheck(), Health: health, Hub: hub,
	})
	if err != nil {
		ln.Close()
		closeSess()
		return err
	}
	s.refused = refusedFP
	s.audit(audit.Record{Event: audit.EventLogin, Decision: "ok"})
	o.IO.Println("")
	for _, l := range readyLines(path, cfg.ProjectRoot, o.ShowResults) {
		o.IO.Println(l)
	}
	o.IO.Println("")
	s.println(paint.Step("Listening…"))

	var lines <-chan string
	if ls, ok := o.IO.(LineSource); ok {
		lines = ls.Lines()
	}
	if hub != nil {
		// Decisions come from lockhub; this terminal keeps the console's own
		// decisions (policy changes, :unmask).
		s.approver = hub.Approver(s.approver)
		wctx, stopWatch := context.WithCancel(ctx)
		watched := make(chan struct{})
		go func() { defer close(watched); hub.Watch(wctx, o.IO) }()
		defer func() { stopWatch(); <-watched }()
		s.println(paint.Step("hub mode: requests are decided in lockhub (instance " + safeText(o.Hub.Instance, false) + ")"))
	}
	serveErr := s.Serve(ctx, ln, lines)
	if s.sess != nil {
		_ = s.sess.Close()
	}
	reason, _ := s.Ended()
	s.audit(audit.Record{Event: audit.EventLogout, Decision: reason})
	o.IO.Println(paint.Step("session ended: " + reason))
	return serveErr
}

// refuseX11Production is refuseX11IfProduction for the loaded profile p
// and for the policy approved before under key, when there is one.
func refuseX11Production(iso *isolation, stateDir, key string, p config.Profile) error {
	if err := iso.refuseX11IfProduction(p); err != nil {
		return err
	}
	if ap, err := config.LoadApproved(stateDir, key); err == nil {
		return iso.refuseX11IfProduction(ap.Profile)
	}
	return nil // none yet, or unreadable: startPolicy reports it
}

// hardenRefusal is the error of a console whose core-dump protection could
// not be set up (hardenErr) on a production profile, where that protection
// is part of the credential mitigations; nil otherwise, where the console
// only warned.
func hardenRefusal(hardenErr error, production bool) error {
	if hardenErr == nil || !production {
		return nil
	}
	return fmt.Errorf("console: refused: core dumps could not be disabled (%v) and the profile is production; the secret would be exposed in a dump", hardenErr)
}

// where is the profile's host (and port) or SQLite path, escaped for the
// terminal.
func (st *starter) where() string {
	p := st.profile
	if p.Engine == config.EngineSQLite {
		return safeText(p.Path, false)
	}
	if p.Port != 0 {
		return safeText(fmt.Sprintf("%s:%d", p.Host, p.Port), false)
	}
	return safeText(p.Host, false)
}

// startPolicy compares the current policy with the approved one (spec §4).
// It returns the policy to enforce and, when the human refused a loosening,
// the refused policy's fingerprint.
func (st *starter) startPolicy(ctx context.Context, stateDir, key string, cur config.Policy) (config.Policy, string, error) {
	io := st.io
	ap, err := config.LoadApproved(stateDir, key)
	if errors.Is(err, fs.ErrNotExist) {
		io.Println(bold + "First start of profile " + cur.Profile.Name + ": review its policy." + reset)
		for _, line := range describePolicy(cur) {
			io.Println(line)
		}
		// A project config can shadow a user-config profile of the same
		// name, which moves the approval to a new key: show what differs
		// from the policy the human approved under that name, loosenings in
		// red.
		if userKey := config.ApprovedKey("", cur.Profile.Name); userKey != key {
			if prev, err := config.LoadApproved(stateDir, userKey); err == nil {
				if changes := config.Diff(*prev, cur); len(changes) > 0 {
					io.Println(bold + "This project's profile " + cur.Profile.Name + " differs from the user-config profile approved under that name:" + reset)
					for _, line := range formatChanges(changes) {
						io.Println(line)
					}
				}
			}
		}
		if r := st.decide(ctx, Decision{Prompt: "Apply these changes? [y/N] ", Expected: "y"}); r.Outcome != Approved {
			reason, errText := noFingerFields(r)
			st.audit(audit.Record{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
			return config.Policy{}, "", errors.New("console: the policy was not approved")
		}
		if st.audit(audit.Record{Event: audit.EventPolicy, Decision: "applied", Approval: st.appr().Mode()}) != nil {
			return config.Policy{}, "", errApprovalUnrecorded
		}
		if err := config.SaveApproved(stateDir, key, cur); err != nil {
			return config.Policy{}, "", st.failed(true, err)
		}
		return cur, "", nil
	}
	if err != nil {
		return config.Policy{}, "", fmt.Errorf("%w: %v (delete the file to approve the policy again)", ErrConfig, err)
	}
	changes := config.Diff(*ap, cur)
	if len(changes) == 0 {
		return *ap, "", nil
	}
	if !kconsole.Loosens(changes) {
		if err := config.SaveApproved(stateDir, key, cur); err != nil {
			return config.Policy{}, "", err
		}
		io.Println("policy tightened since the last session:")
		for _, line := range formatChanges(changes) {
			io.Println(line)
		}
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "tightened"})
		return cur, "", nil
	}
	io.Println(bold + "The policy of profile " + cur.Profile.Name + " changed since it was approved:" + reset)
	for _, line := range formatChanges(changes) {
		io.Println(line)
	}
	r := st.decide(ctx, Decision{Prompt: "Apply these changes? [y/N] ", Expected: "y"})
	if ctx.Err() != nil {
		return config.Policy{}, "", ctx.Err()
	}
	if r.Outcome != Approved {
		reason, errText := noFingerFields(r)
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
		io.Println("changes refused: the last approved policy applies")
		return *ap, config.Fingerprint(cur), nil
	}
	if st.audit(audit.Record{Event: audit.EventPolicy, Decision: "applied", Approval: st.appr().Mode()}) != nil {
		return config.Policy{}, "", errApprovalUnrecorded
	}
	if err := config.SaveApproved(stateDir, key, cur); err != nil {
		return config.Policy{}, "", st.failed(true, err)
	}
	return cur, "", nil
}

// connect opens a session with the profile's credentials mode (spec §5).
// The secret is wiped once the connection is open.
func (st *starter) connect(ctx context.Context, first bool) (engine.Session, error) {
	p := st.profile
	eng, err := engine.Get(p.Engine)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	prof := p
	prof.User = st.user
	var dial engine.DialFunc
	var tun *tunnel.Tunnel
	if p.SSH != nil {
		t, err := st.openTunnel(ctx, p)
		if err != nil {
			return nil, err
		}
		tun, dial = t, t.Dial
		if err := st.checkLockedOut(); err != nil {
			tun.Close()
			return nil, err
		}
	}
	var proxy *proxycmd.Proxy
	if len(p.ProxyCommand) > 0 {
		proxy = proxycmd.New(p.ProxyCommand)
		dial = proxy.Dial
	}
	// Every return without a session closes the tunnel opened for it; a
	// session takes the tunnel over and closes it with itself.
	connected := false
	defer func() {
		if !connected && tun != nil {
			tun.Close()
		}
	}()
	open := func(secret []byte) (engine.Session, error) {
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		sess, err := eng.Connect(cctx, prof, secret, dial)
		if proxy != nil {
			if err != nil {
				return nil, withProxyStderr(err, safeText(proxy.Stderr(), false))
			}
			return &proxiedSession{Session: sess, program: safeText(p.ProxyCommand[0], false), dbHost: p.Host}, nil
		}
		if err != nil || tun == nil {
			return sess, err
		}
		connected = true
		return &tunneledSession{Session: sess, closeTunnel: tun.Close, bastion: p.SSH.Host, dbHost: p.Host}, nil
	}
	if p.Engine == config.EngineSQLite {
		sess, err := open(nil)
		if err != nil {
			return nil, fmt.Errorf("console: %s", secrets.Sanitize(err))
		}
		return sess, nil
	}

	var sess engine.Session
	if p.Credentials == config.CredentialsVault {
		sess, err = st.connectVault(ctx, p, &prof, open, first)
	} else {
		sess, err = st.connectSecret(ctx, p, open, first)
	}
	if err != nil {
		return nil, err
	}
	if err := st.checkLockedOut(); err != nil {
		_ = sess.Close()
		return nil, err
	}
	if n, ok := sess.(engine.Noticer); ok {
		for _, msg := range n.Notices() {
			st.io.Println(paint.Warn(red + "warning: " + msg + reset))
			st.audit(audit.Record{Event: audit.EventLogin, Decision: "notice", Error: msg})
		}
	}
	return sess, nil
}

// connectSecret connects with a secret asked of the human or read from the
// OS keychain (credentials = "ask" or "keychain").
func (st *starter) connectSecret(ctx context.Context, p config.Profile, open func([]byte) (engine.Session, error), first bool) (engine.Session, error) {
	ask := func() ([]byte, error) {
		return st.io.AskSecret(ctx, fmt.Sprintf("Password for %s@%s: ", st.user, p.Host))
	}
	keychain := p.Credentials == config.CredentialsKeychain
	var secret []byte
	var err error
	fromKeychain := false
	if keychain {
		s, legacy, err := product.Keychain.Get(p.Name, p.Host, p.Port, defaultPort(p.Engine))
		switch {
		case err == nil:
			secret, fromKeychain = s, true
			if legacy == secrets.LegacyMoved {
				st.io.Println(migratedLine(p.Name, p.Host, p.Port))
			}
		case errors.Is(err, secrets.ErrNotFound) && legacy == secrets.LegacyRemoved:
			st.io.Println(removedLine(p.Name, p.Host, p.Port))
		case errors.Is(err, secrets.ErrNotFound):
			if first {
				st.io.Println("no secret in the OS keychain yet")
			}
		default:
			st.io.Println("OS keychain unavailable, asking instead: " + secrets.Sanitize(err))
			keychain = false
		}
	}
	if secret == nil {
		if secret, err = ask(); err != nil {
			return nil, err
		}
	}
	defer func() { secrets.Wipe(secret) }()
	sess, err := open(secret)
	if err != nil && fromKeychain {
		st.io.Println("connecting with the keychain secret failed: " + secrets.Sanitize(err, secret))
		secrets.Wipe(secret)
		if secret, err = ask(); err != nil {
			return nil, err
		}
		if sess, err = open(secret); err == nil {
			st.offerSave(ctx, secret, "Replace the secret stored in the OS keychain? [y/N] ")
		}
	} else if err == nil && keychain && !fromKeychain {
		st.offerSave(ctx, secret, "Save in OS keychain? [y/N] ")
	}
	if err != nil {
		return nil, fmt.Errorf("console: connect: %s", secrets.Sanitize(err, secret))
	}
	return sess, nil
}

// vaultRead is secrets.VaultReadToken; tests replace it.
var vaultRead = secrets.VaultReadToken

// vaultTokenTries is how many Vault tokens in a row may be refused before
// a connection gives up.
const vaultTokenTries = 3

// vaultAddr is the Vault server the vault CLI talks to: VAULT_ADDR, or the
// CLI's default.
func vaultAddr() string {
	if a := os.Getenv("VAULT_ADDR"); a != "" {
		return a
	}
	return "https://127.0.0.1:8200"
}

// readVault reads the login at p.VaultPath with the Vault token of the
// session, asked of the human the first time (no echo), and again when
// Vault refuses the read up to vaultTokenTries times. Vault answers
// "permission denied" alike for an expired or revoked token and for a
// policy that may not read the path, so the warning names both. The
// token goes to the vault CLI in its environment only, never its
// arguments, a file, a log or the audit trail.
func (st *starter) readVault(ctx context.Context, p config.Profile) (*secrets.VaultCredentials, error) {
	for try := 1; ; try++ {
		if st.vaultToken == nil {
			tok, err := st.io.AskSecret(ctx, "Vault token for "+safeText(vaultAddr(), false)+": ")
			if err != nil {
				return nil, err
			}
			st.vaultToken = tok
		}
		c, err := vaultRead(ctx, p.VaultPath, st.vaultToken)
		if err == nil || !errors.Is(err, secrets.ErrVaultAuth) {
			return c, err
		}
		err = errors.New(secrets.Sanitize(err, st.vaultToken))
		st.wipeVaultToken()
		if try == vaultTokenTries {
			return nil, fmt.Errorf("%w: %v", secrets.ErrVaultAuth, err)
		}
		st.io.Println(paint.Warn("Vault refused the read: " + err.Error() + ". Enter the token again, or a token whose policy may read " + safeText(p.VaultPath, false)))
	}
}

// connectVault connects with the login read from Vault at p.VaultPath
// (credentials = "vault"): at every connection, so a rotated or
// short-lived login is fetched fresh, and never stored. The username comes
// from the secret, or from the profile's user when the secret has none; a
// secret naming another user than the profile is refused. prof is the
// profile open connects with.
func (st *starter) connectVault(ctx context.Context, p config.Profile, prof *config.Profile, open func([]byte) (engine.Session, error), first bool) (engine.Session, error) {
	fetched := st.now()
	c, err := st.readVault(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("console: credentials from Vault (%s): %w", safeText(p.VaultPath, false), err)
	}
	defer secrets.Wipe(c.Password)
	user := c.User
	switch {
	case user == "" && p.User == "":
		return nil, fmt.Errorf("console: the Vault secret at %s has no username field: set user in the profile", safeText(p.VaultPath, false))
	case user == "":
		user = p.User
	case p.User != "" && user != p.User:
		return nil, fmt.Errorf("console: the Vault secret at %s is for user %q, the profile sets user %q: remove user from the profile, or fix vault_path",
			safeText(p.VaultPath, false), safeText(user, false), safeText(p.User, false))
	case safeText(user, false) != user:
		return nil, fmt.Errorf("console: the Vault secret at %s has a username with a control or formatting character", safeText(p.VaultPath, false))
	}
	st.user, prof.User = user, user
	sess, err := open(c.Password)
	if err != nil {
		return nil, fmt.Errorf("console: connect with the Vault login of %s: %s", safeText(p.VaultPath, false), secrets.Sanitize(err, c.Password))
	}
	vs := &vaultSession{Session: sess, user: user}
	line := "credentials from Vault: " + safeText(p.VaultPath, false) + " · user " + safeText(user, false)
	if c.LeaseID != "" && c.LeaseDuration > 0 {
		// Reconnect with a fresh login before the lease ends, when Vault
		// may revoke the account and its connections.
		vs.refreshAt = fetched.Add(c.LeaseDuration - c.LeaseDuration/10)
		line += " · lease " + c.LeaseDuration.String()
	}
	if first {
		st.io.Println(paint.OK(line))
	} else {
		st.io.Println(line)
	}
	return vs, nil
}

// now is the starter's clock.
func (st *starter) now() time.Time {
	if st.o.Now != nil {
		return st.o.Now()
	}
	return time.Now()
}

// vaultSession is a session opened with a login read from Vault: it names
// the login's user, which may change at every connection, and when to
// reconnect with a fresh one.
type vaultSession struct {
	engine.Session
	user string
	// refreshAt is when the lease nears its end; zero for a secret without
	// a lease.
	refreshAt time.Time
}

// DBUser is the database user of the login.
func (s *vaultSession) DBUser() string { return s.user }

// CredentialsExpire is when the session must be replaced by one with a
// fresh login; zero for never.
func (s *vaultSession) CredentialsExpire() time.Time { return s.refreshAt }

// ShadowedFunctions passes the lookup on (engine.FunctionShadows).
func (s *vaultSession) ShadowedFunctions(ctx context.Context, db string, names []string) ([]string, error) {
	return engine.ShadowedFunctions(ctx, s.Session, db, names)
}

// ShadowedOperators passes the lookup on (engine.FunctionShadows).
func (s *vaultSession) ShadowedOperators(ctx context.Context, db string, names []string) ([]string, error) {
	return engine.ShadowedOperators(ctx, s.Session, db, names)
}

// Notices passes on the session's transport notices.
func (s *vaultSession) Notices() []string {
	if n, ok := s.Session.(engine.Noticer); ok {
		return n.Notices()
	}
	return nil
}

func (st *starter) offerSave(ctx context.Context, secret []byte, prompt string) {
	st.offerSaveAs(ctx, st.profile.Host, st.profile.Port, secret, prompt)
}

// defaultPort is config.DefaultPort; tests that connect through a fake
// engine replace it.
var defaultPort = config.DefaultPort

// migratedLine tells the human that a keychain item stored under its old
// name, without the port, now has the new one.
func migratedLine(profile, host string, port int) string {
	return "moved the keychain secret of " + safeText(profile+"@"+host, false) + " to " +
		safeText(secrets.KeychainAccount(profile, host, port), false) + " (the port is now part of its name)"
}

// removedLine tells the human that a keychain item stored under its old
// name, without the port, was deleted because the profile is on another
// port than the one it was migrated to.
func removedLine(profile, host string, port int) string {
	return "removed the pre-upgrade keychain item " + safeText(profile+"@"+host, false) +
		"; answer \"Save in OS keychain?\" to store the secret for " + safeText(host+":"+strconv.Itoa(port), false)
}

// offerSaveAs offers to store secret in the OS keychain under the
// profile's name, host and port.
func (st *starter) offerSaveAs(ctx context.Context, host string, port int, secret []byte, prompt string) {
	if r := st.decide(ctx, Decision{Prompt: prompt, Expected: "y"}); r.Outcome != Approved {
		return
	}
	if err := product.Keychain.Set(st.profile.Name, host, port, secret); err != nil {
		st.io.Println("not saved: " + secrets.Sanitize(err, secret))
		return
	}
	st.io.Println(paint.OK("saved in the OS keychain"))
}

// reconnect opens a new session after a lost connection and runs the
// privilege audit again, with the start-up rules: the account behind the
// secret may not be the one audited at start-up, and its grants may have
// changed. A failed audit closes the session and wraps errPrivilegeAudit.
//
// p is the profile in force now: a tightening applied since start-up (such
// as production turned on, or credentials from keychain to ask) governs the
// new connection and its audit.
func (st *starter) reconnect(ctx context.Context, p config.Profile) (engine.Session, error) {
	st.profile = p
	sess, err := st.connect(ctx, false)
	if err != nil {
		return nil, err
	}
	if err := st.privileges(ctx, sess); err != nil {
		_ = sess.Close()
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: "reconnect: " + err.Error()})
		return nil, fmt.Errorf("%w: %v", errPrivilegeAudit, err)
	}
	return sess, nil
}

// privileges runs the privilege audit for the tier: refused on production,
// a typed "continue" otherwise.
func (st *starter) privileges(ctx context.Context, sess engine.Session) error {
	p := st.profile
	warns, err := sess.ExtraPrivileges(ctx, p.Tier)
	if err != nil {
		warns = append(warns, "privilege audit failed: "+secrets.Sanitize(err))
	}
	st.privWarns = warns
	if len(warns) == 0 {
		st.io.Println(paint.OK("privileges: nothing beyond tier " + p.Tier.String()))
		return nil
	}
	st.io.Println(paint.Warn(red + "the account can do more than tier " + p.Tier.String() + " needs:" + reset))
	for _, w := range warns {
		st.io.Println(red + "  - " + safeText(w, false) + reset)
	}
	if p.Production {
		return fmt.Errorf("console: refused: the account has privileges beyond tier %s on a production profile; use a %s-only account", p.Tier, p.Tier)
	}
	if p.Tier == config.TierRead {
		st.io.Println("the session stays read-only either way")
	}
	if r := st.decide(ctx, Decision{Prompt: `Type "continue" to proceed: `, Expected: "continue", Production: true}); r.Outcome != Approved {
		return errors.New("console: stopped at the privilege audit")
	}
	return nil
}

// piiBootstrap scans the schema at every start and proposes mask rules for
// the columns that look like personal data and that no rule names yet
// (neither a mask nor an allow rule). It returns the policy including the
// accepted rules, which only tighten it.
func (st *starter) piiBootstrap(ctx context.Context, sess engine.Session, dbs []string, rulesPath, stateDir, key string, ap config.Policy) (config.Policy, error) {
	_, statErr := os.Stat(rulesPath)
	firstRun := errors.Is(statErr, fs.ErrNotExist)
	var cols []engine.ColumnInfo
	for _, db := range servedDatabases(st.profile.Database, dbs) {
		c, err := sess.Columns(ctx, db)
		if err != nil {
			st.io.Println("PII scan of " + safeText(db, false) + " skipped: " + safeText(secrets.Sanitize(err), false))
			continue
		}
		cols = append(cols, c...)
	}
	rules := pii.Rules{Mask: slices.Clone(ap.PIIMask), Allow: slices.Clone(ap.PIIAllow), Modes: maps.Clone(ap.PIIModes)}
	var proposals []string
	for _, pat := range pii.Propose(cols) {
		seg := strings.SplitN(pat, ".", 3)
		if len(seg) == 3 && rules.Covered(seg[0], seg[1], seg[2]) {
			continue
		}
		proposals = append(proposals, pat)
	}
	var quasi []string
	for _, pat := range pii.ProposeQuasi(cols) {
		seg := strings.SplitN(pat, ".", 3)
		if len(seg) == 3 && rules.Covered(seg[0], seg[1], seg[2]) {
			continue
		}
		quasi = append(quasi, pat)
	}
	if !firstRun && len(proposals) == 0 && len(quasi) == 0 {
		return ap, nil
	}
	if len(proposals) == 0 && len(quasi) == 0 {
		st.io.Println(paint.OK("PII: no personal-data columns found in the schema"))
	}
	if len(proposals) > 0 {
		if firstRun {
			st.io.Println(bold + "PII: these columns look like personal data and would be masked:" + reset)
		} else {
			st.io.Println(bold + "PII scan: these columns look like personal data and no rule names them yet:" + reset)
		}
		groups := map[string][]string{}
		var order []string
		for _, pat := range proposals {
			i := strings.LastIndex(pat, ".")
			t, c := pat[:i], pat[i+1:]
			if _, ok := groups[t]; !ok {
				order = append(order, t)
			}
			groups[t] = append(groups[t], c)
		}
		for _, t := range order {
			st.io.Println("  " + safeText(t, false) + ": " + safeText(strings.Join(groups[t], ", "), false))
		}
		ans, _ := st.io.Ask(ctx, "Accept all [a], review [r], skip [s]: ", ApprovalTimeout)
		if ctx.Err() != nil {
			return ap, ctx.Err()
		}
		switch strings.TrimSpace(strings.ToLower(ans)) {
		case "a":
			for _, pat := range proposals {
				_ = rules.Add(pat)
			}
		case "r":
			for _, pat := range proposals {
				a, ok := st.io.Ask(ctx, "Mask "+safeText(pat, false)+"? [Y/n] ", ApprovalTimeout)
				if ctx.Err() != nil {
					return ap, ctx.Err()
				}
				if a = strings.TrimSpace(strings.ToLower(a)); ok && (a == "" || a == "y") {
					_ = rules.Add(pat)
				}
			}
		default:
			st.io.Println("PII: no rules added; add them later with locksql pii add")
		}
	}
	allowed := false
	if len(quasi) > 0 {
		st.io.Println(bold + "PII scan: these columns can identify a person together (quasi-identifiers); they are not masked unless you say so:" + reset)
		for _, pat := range quasi {
			a, ok := st.io.Ask(ctx, "Mask "+safeText(pat, false)+"? ("+pii.QuasiLimit+") [y/N] ", ApprovalTimeout)
			if ctx.Err() != nil {
				return ap, ctx.Err()
			}
			if !ok {
				continue // asked again at the next start
			}
			switch strings.TrimSpace(strings.ToLower(a)) {
			case "y", "yes":
				if err := rules.Add(pat); err != nil {
					return ap, err
				}
			case "n", "no", "":
				if err := rules.AddAllow(pat); err != nil {
					return ap, err
				}
				allowed = true
			default:
				// Not an answer: nothing is written, asked again at the next start.
			}
		}
	}
	next := config.NewPolicy(ap.Profile, rules.Mask, rules.Allow).WithModes(rules.Modes)
	changed := config.Fingerprint(next) != config.Fingerprint(ap)
	if allowed && changed {
		// The human declined to mask a quasi-identifier: a widening, on
		// record before anything is saved.
		if st.audit(audit.Record{Event: audit.EventPolicy, Decision: "approved"}) != nil {
			return ap, errApprovalUnrecorded
		}
	}
	switch {
	case firstRun:
		// Write the file even when empty, so that the first-run proposal
		// runs once.
		if err := pii.SaveRulesFile(rulesPath, rules); err != nil {
			return ap, st.failed(allowed && changed, err)
		}
	case changed:
		// Add the accepted rules to the file as it is on disk, so that
		// unconfirmed edits are neither lost nor applied.
		onDisk, err := pii.LoadRulesFile(rulesPath)
		if err != nil {
			return ap, err
		}
		for _, pat := range rules.Mask {
			if !slices.Contains(ap.PIIMask, pat) {
				if err := onDisk.Add(pat); err != nil {
					return ap, err
				}
			}
		}
		for _, pat := range rules.Allow {
			if !slices.Contains(ap.PIIAllow, pat) {
				if err := onDisk.AddAllow(pat); err != nil {
					return ap, err
				}
			}
		}
		if err := pii.SaveRulesFile(rulesPath, onDisk); err != nil {
			return ap, st.failed(allowed, err)
		}
	}
	next = config.NewPolicy(ap.Profile, rules.Mask, rules.Allow).WithModes(rules.Modes)
	if changed {
		if err := config.SaveApproved(stateDir, key, next); err != nil {
			return ap, st.failed(allowed, err)
		}
		if !allowed {
			st.audit(audit.Record{Event: audit.EventPolicy, Decision: "tightened"})
		}
		st.io.Println(paint.OK(fmt.Sprintf("PII: %d mask rules in %s", len(next.PIIMask), rulesPath)))
	}
	return next, nil
}

// flagNotices are the start-up warnings of the console-only flags that
// widen what the console does.
func flagNotices(o Options, p config.Profile) []string {
	var out []string
	if o.AllowUnmask {
		out = append(out, paint.Warn("--allow-unmask: clients may ask for unmasked PII output; each such query is approved here, never auto-approved (:unmask: off)"))
	}
	if o.ShowResults {
		msg := "--show-results: the result of each query is printed here in clear, PII included; the agent still gets it masked (Ctrl-O: hide)"
		if p.Production {
			out = append(out, red+ui.MarkWarn+" "+msg+" (PRODUCTION data: mind screen sharing and the terminal's scrollback)"+reset)
		} else {
			out = append(out, paint.Warn(msg))
		}
	}
	return out
}

// readyLines is the "Ready" block printed once the console serves.
func readyLines(socket, root string, showResults bool) []string {
	out := []string{paint.Heading("Ready", 60), "  " + paint.Dim("socket   ") + socket}
	if root != "" {
		// Only agents working under this root dial this socket.
		out = append(out, "  "+paint.Dim("serving  ")+"agents in "+safeText(root, false))
	}
	if showResults {
		out = append(out, "  "+paint.Dim("results  ")+paint.Yellow("shown in clear in this console (--show-results)"))
	}
	out = append(out, "  "+paint.Dim("keys     ")+paint.Accent("Shift+Tab")+" manual/auto mode  "+paint.Accent("Ctrl-O")+" results masked/clear"+paint.Dim(" · the status line below shows both"))
	return append(out, "  "+paint.Dim("commands ")+paint.Accent(":review")+"  "+paint.Accent(":status")+"  "+paint.Accent(":mode")+"  "+paint.Accent(":results")+"  "+paint.Accent(":unmask")+"  "+paint.Accent(":quit")+paint.Dim(" · Ctrl-C ends the session"))
}

// servedDatabases is what the console serves: the profile's database alone
// when it names one (the PII scan covers that database only), else every
// database the account lists.
func servedDatabases(profileDB string, listed []string) []string {
	if profileDB != "" {
		return []string{profileDB}
	}
	return listed
}

// ObjectState passes the read on (engine.ObjectGuard).
func (s *vaultSession) ObjectState(ctx context.Context, db string, refs engine.ObjectRefs) (engine.ObjectState, error) {
	return engine.ObjectStateOf(ctx, s.Session, db, refs)
}

// RunGuarded passes the guarded run on (engine.ObjectGuard).
func (s *vaultSession) RunGuarded(ctx context.Context, db string, st sqlclass.Statement, maxRows int, refs engine.ObjectRefs, check engine.GuardCheck) (engine.Result, error) {
	return engine.RunGuarded(ctx, s.Session, db, st, maxRows, refs, check)
}

// RunCounted passes the counted run on (engine.RowChecker).
func (s *vaultSession) RunCounted(ctx context.Context, db string, st sqlclass.Statement, maxRows int, check func(int64) error) (engine.Result, error) {
	return engine.RunCounted(ctx, s.Session, db, st, maxRows, check)
}
