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
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/secrets"
)

// ErrConfig marks usage and configuration errors (exit code 3).
var ErrConfig = errors.New("configuration error")

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
}

func (st *starter) audit(rec audit.Record) {
	rec.Profile, rec.Engine, rec.DBUser = st.profile.Name, st.profile.Engine, st.user
	rec.Host = st.profile.Host
	if st.profile.Engine == config.EngineSQLite {
		rec.Host = st.profile.Path
	}
	if err := st.log.Write(rec); err != nil {
		st.io.Println("audit log write failed: " + err.Error())
	}
}

// Run is `locksql console`: the start-up sequence of spec §6, then the
// request loop until Ctrl-C, logout, :quit or a timeout.
func Run(ctx context.Context, o Options) error {
	if o.IO == nil {
		return errors.New("console: no terminal")
	}
	if err := harden(); err != nil {
		o.IO.Println("warning: could not disable core dumps: " + err.Error())
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
	piiRoot := cfg.ProjectRoot
	if piiRoot == "" {
		if piiRoot, err = filepath.Abs(o.Cwd); err != nil {
			return err
		}
	}
	key := config.ApprovedKey(cfg.ProjectRoot, p.Name)
	log, err := audit.Open(o.StateDir)
	if err != nil {
		return err
	}
	st := &starter{o: o, io: o.IO, log: log, profile: p}

	loadPolicy := func() (config.Policy, error) {
		c, err := config.Load(o.Cwd)
		if err != nil {
			return config.Policy{}, err
		}
		cp, ok := c.Profiles[o.Profile]
		if !ok {
			return config.Policy{}, fmt.Errorf("profile %q is no longer in the config", o.Profile)
		}
		r, err := pii.LoadRules(piiRoot)
		if err != nil {
			return config.Policy{}, err
		}
		return config.NewPolicy(cp, r.Mask, r.Allow), nil
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
	p = approved.Profile
	st.profile = p

	// Separation from the agent, before any secret is asked for.
	iso, err := checkIsolation(o.IO, realIsolationEnv(o.TTY), p)
	if err != nil {
		st.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}

	// 2. Production banner and typed profile name.
	if p.Production {
		o.IO.Println(red + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset)
		o.IO.Println(red + "  PRODUCTION profile " + p.Name + " (" + st.where() + ")" + reset)
		o.IO.Println(red + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + reset)
		ans, ok := o.IO.Ask(ctx, fmt.Sprintf("Type the profile name %q to continue: ", p.Name), ApprovalTimeout)
		if !ok || strings.TrimSpace(ans) != p.Name {
			return errors.New("console: production profile not confirmed")
		}
		if o.SkipPermissions {
			o.IO.Println("--skip-permissions is ignored on production profiles: every statement is prompted")
		}
	}

	// 3. Host (confirmed with the policy) and user.
	o.IO.Println(fmt.Sprintf("profile %s · %s %s (approved policy)", p.Name, p.Engine, st.where()))
	st.user = p.User
	if st.user == "" && p.Engine != config.EngineSQLite {
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
	o.IO.Println(fmt.Sprintf("connected: %s %s", sess.Flavor(), safeText(sess.ServerVersion(), false)))
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
	o.IO.Println("databases: " + safeText(strings.Join(dbs, ", "), false))
	health := &ipc.Health{Separated: iso.sys != nil, Display: iso.display.Kind, Privileges: nonNil(st.privWarns),
		ReadOnly: p.Tier == config.TierRead}
	probeDB := p.Database
	if probeDB == "" && len(dbs) > 0 {
		probeDB = dbs[0]
	}
	if _, err := sess.Explain(ctx, probeDB, "SELECT 1"); err == nil {
		health.ExplainOK = true
	} else {
		o.IO.Println(red + "warning: EXPLAIN does not work on this server: " + safeText(secrets.Sanitize(err), false) + reset)
	}

	// 7. PII first-run proposal.
	approved, err = st.piiBootstrap(ctx, sess, dbs, piiRoot, o.StateDir, key, approved)
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
		Policy: approved, Root: piiRoot, StateDir: o.StateDir, ApprovedKey: key,
		Session: sess, DBUser: st.user, Databases: dbs, Audit: log, IO: o.IO, Now: o.Now,
		SkipPermissions: o.SkipPermissions, Version: o.Version, LoadPolicy: loadPolicy,
		Reconnect: st.reconnect, Quantum: ResponseQuantum, PeerAllowed: iso.peerCheck(), Health: health,
	})
	if err != nil {
		ln.Close()
		closeSess()
		return err
	}
	s.refused = refusedFP
	s.audit(audit.Record{Event: audit.EventLogin, Decision: "ok"})
	o.IO.Println("socket " + path)
	o.IO.Println("console commands: :review  :status  :quit · Ctrl-C ends the session")
	s.println("Listening…")

	var lines <-chan string
	if ls, ok := o.IO.(LineSource); ok {
		lines = ls.Lines()
	}
	serveErr := s.Serve(ctx, ln, lines)
	if s.sess != nil {
		_ = s.sess.Close()
	}
	reason, _ := s.Ended()
	s.audit(audit.Record{Event: audit.EventLogout, Decision: reason})
	o.IO.Println("session ended: " + reason)
	return serveErr
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
		ans, ok := io.Ask(ctx, "Apply these changes? [y/N] ", ApprovalTimeout)
		if !ok || strings.TrimSpace(ans) != "y" {
			st.audit(audit.Record{Event: audit.EventPolicy, Decision: "refused"})
			return config.Policy{}, "", errors.New("console: the policy was not approved")
		}
		if err := config.SaveApproved(stateDir, key, cur); err != nil {
			return config.Policy{}, "", err
		}
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "applied"})
		return cur, "", nil
	}
	if err != nil {
		return config.Policy{}, "", fmt.Errorf("%w: %v (delete the file to approve the policy again)", ErrConfig, err)
	}
	changes := config.Diff(*ap, cur)
	if len(changes) == 0 {
		return *ap, "", nil
	}
	if !loosens(changes) {
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
	ans, ok := io.Ask(ctx, "Apply these changes? [y/N] ", ApprovalTimeout)
	if ctx.Err() != nil {
		return config.Policy{}, "", ctx.Err()
	}
	if !ok || strings.TrimSpace(ans) != "y" {
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "refused"})
		io.Println("changes refused: the last approved policy applies")
		return *ap, config.Fingerprint(cur), nil
	}
	if err := config.SaveApproved(stateDir, key, cur); err != nil {
		return config.Policy{}, "", err
	}
	st.audit(audit.Record{Event: audit.EventPolicy, Decision: "applied"})
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
	open := func(secret []byte) (engine.Session, error) {
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		return eng.Connect(cctx, prof, secret)
	}
	if p.Engine == config.EngineSQLite {
		sess, err := open(nil)
		if err != nil {
			return nil, fmt.Errorf("console: %s", secrets.Sanitize(err))
		}
		return sess, nil
	}

	ask := func() ([]byte, error) {
		return st.io.AskSecret(ctx, fmt.Sprintf("Password for %s@%s: ", st.user, p.Host))
	}
	keychain := p.Credentials == config.CredentialsKeychain
	var secret []byte
	fromKeychain := false
	if keychain {
		s, err := secrets.KeychainGet(p.Name, p.Host)
		switch {
		case err == nil:
			secret, fromKeychain = s, true
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
	if n, ok := sess.(engine.Noticer); ok {
		for _, msg := range n.Notices() {
			st.io.Println(red + "warning: " + msg + reset)
			st.audit(audit.Record{Event: audit.EventLogin, Decision: "notice", Error: msg})
		}
	}
	return sess, nil
}

func (st *starter) offerSave(ctx context.Context, secret []byte, prompt string) {
	ans, ok := st.io.Ask(ctx, prompt, ApprovalTimeout)
	if !ok || strings.TrimSpace(ans) != "y" {
		return
	}
	if err := secrets.KeychainSet(st.profile.Name, st.profile.Host, secret); err != nil {
		st.io.Println("not saved: " + secrets.Sanitize(err, secret))
		return
	}
	st.io.Println("saved in the OS keychain")
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
		st.io.Println("privileges: nothing beyond tier " + p.Tier.String())
		return nil
	}
	st.io.Println(red + "the account can do more than tier " + p.Tier.String() + " needs:" + reset)
	for _, w := range warns {
		st.io.Println(red + "  - " + safeText(w, false) + reset)
	}
	if p.Production {
		return fmt.Errorf("console: refused: the account has privileges beyond tier %s on a production profile; use a %s-only account", p.Tier, p.Tier)
	}
	if p.Tier == config.TierRead {
		st.io.Println("the session stays read-only either way")
	}
	ans, ok := st.io.Ask(ctx, `Type "continue" to proceed: `, ApprovalTimeout)
	if !ok || strings.TrimSpace(ans) != "continue" {
		return errors.New("console: stopped at the privilege audit")
	}
	return nil
}

// piiBootstrap scans the schema at every start and proposes mask rules for
// the columns that look like personal data and that no rule names yet
// (neither a mask nor an allow rule). It returns the policy including the
// accepted rules, which only tighten it.
func (st *starter) piiBootstrap(ctx context.Context, sess engine.Session, dbs []string, root, stateDir, key string, ap config.Policy) (config.Policy, error) {
	_, statErr := os.Stat(filepath.Join(root, pii.RulesFile))
	firstRun := errors.Is(statErr, fs.ErrNotExist)
	scan := dbs
	if st.profile.Database != "" {
		scan = []string{st.profile.Database}
	}
	var cols []engine.ColumnInfo
	for _, db := range scan {
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
	if !firstRun && len(proposals) == 0 {
		return ap, nil
	}
	if len(proposals) == 0 {
		st.io.Println("PII: no personal-data columns found in the schema")
	} else {
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
	next := config.NewPolicy(ap.Profile, rules.Mask, rules.Allow).WithModes(rules.Modes)
	switch {
	case firstRun:
		// Write the file even when empty, so that the first-run proposal
		// runs once.
		if err := pii.SaveRules(root, rules); err != nil {
			return ap, err
		}
	case config.Fingerprint(next) != config.Fingerprint(ap):
		// Add the accepted rules to the file as it is on disk, so that
		// unconfirmed edits are neither lost nor applied.
		onDisk, err := pii.LoadRules(root)
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
		if err := pii.SaveRules(root, onDisk); err != nil {
			return ap, err
		}
	}
	next = config.NewPolicy(ap.Profile, rules.Mask, rules.Allow).WithModes(rules.Modes)
	if config.Fingerprint(next) != config.Fingerprint(ap) {
		if err := config.SaveApproved(stateDir, key, next); err != nil {
			return ap, err
		}
		st.audit(audit.Record{Event: audit.EventPolicy, Decision: "tightened"})
		st.io.Println(fmt.Sprintf("PII: %d mask rules in %s", len(next.PIIMask), pii.RulesFile))
	}
	return next, nil
}
