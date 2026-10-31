package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/lockkit/ui"
	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// Check outcomes.
const (
	checkOK   = ui.MarkOK
	checkWarn = ui.MarkWarn
	checkFail = ui.MarkFail
)

type check struct {
	state, title, detail, fix string
	// repair is what `locksql doctor --fix` does about a check that is not
	// ok, or nil.
	repair *repair
}

// doctorEnv holds what the doctor reads from the system; tests replace it.
type doctorEnv struct {
	goos       string
	loadSys    func() (*sysconf.Config, error)
	display    func() sysconf.Display
	current    func() (*user.User, error)
	lookupUser func(string) (*user.User, error)
	inGroup    func(uid int, group string) bool
	sudoNoPass func() bool
	executable func() (string, error)
	stat       func(string) (os.FileInfo, error)
	ownerOf    func(os.FileInfo) (uid, gid int, ok bool)
	tiocsti    func() (bool, bool)
	ptrace     func() (int, bool)
	keychain   func(profile, host string, port int) error
	status     func(cwd, profile string) (*ipc.StatusResult, error)
	// groupIDs lists the groups of an account.
	groupIDs func(u *user.User) []int
	// acl reads the POSIX ACL of a path (nil: none, or not read).
	acl func(path string) []byte
	// lstat does not follow a final symbolic link; nil skips the checks
	// that need it.
	lstat func(string) (os.FileInfo, error)
	// agents is the account the agents are wired for; nil skips the
	// wiring check.
	agents   func() (agentinit.Env, error)
	lookPath func(string) (string, error)
	// getenv reads this process's environment (VAULT_TOKEN).
	getenv   func(string) string
	run      func(name string, args ...string) ([]byte, error)
	readFile func(string) ([]byte, error)
	// tlsProbe returns the certificates the profile's server presents,
	// without authenticating (engine.TLSProber); nil skips the check.
	tlsProbe func(config.Profile) ([]*x509.Certificate, error)
}

// imageHint is the fix of a check that a former host install met: the
// console now runs in the image, whose launcher sets it up.
const imageHint = "run locksql through the launcher, which runs it in its image (scripts/install.sh, docs/docker.md)"

func realDoctorEnv() doctorEnv {
	return doctorEnv{
		goos:       runtime.GOOS,
		loadSys:    product.LoadSys,
		display:    sysconf.DetectDisplay,
		current:    user.Current,
		lookupUser: user.Lookup,
		inGroup:    sysconf.InGroup,
		sudoNoPass: func() bool {
			if _, err := exec.LookPath("sudo"); err != nil {
				return false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
			cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
			return cmd.Run() == nil
		},
		groupIDs: func(u *user.User) []int {
			ids, _ := u.GroupIds()
			var out []int
			for _, id := range ids {
				if n, err := strconv.Atoi(id); err == nil {
					out = append(out, n)
				}
			}
			return out
		},
		acl:      readACL,
		agents:   agentinit.SystemEnv,
		lookPath: exec.LookPath,
		getenv:   os.Getenv,
		run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		executable: os.Executable,
		stat:       os.Stat,
		lstat:      os.Lstat,
		ownerOf:    fileOwner,
		tiocsti:    sysconf.LegacyTIOCSTI,
		ptrace:     sysconf.PtraceScope,
		keychain:   product.Keychain.Has,
		readFile:   os.ReadFile,
		tlsProbe: func(p config.Profile) ([]*x509.Certificate, error) {
			e, err := engine.Get(p.Engine)
			if err != nil {
				return nil, err
			}
			prober, ok := e.(engine.TLSProber)
			if !ok {
				return nil, errors.New("engine " + p.Engine + " cannot be probed")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return prober.ProbeTLS(ctx, p)
		},
		status: func(cwd, profile string) (*ipc.StatusResult, error) {
			c, err := client.Dial(cwd, profile)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, err := c.Status(ctx)
			if err != nil {
				return nil, err
			}
			return &st, nil
		},
	}
}

// runDoctor is `locksql doctor`: it checks that this machine is ready to
// keep the agent away from the credentials and the data. With --fix it
// then makes the repairs the checks offer and checks again.
func runDoctor(e env, args []string) int {
	const usage = "locksql doctor [--profile P] [--fix [--yes]]"
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile whose console to check (default: every profile)")
	fix := fs.Bool("fix", false, "repair permissions, the socket directory, the project's access and the agents' wiring")
	yes := fs.Bool("yes", false, "with --fix: run the root commands without asking")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *yes && !*fix {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	defer updateNotice(e)
	d := realDoctorEnv()
	if e.doc != nil {
		d = *e.doc
	}
	checks := doctor(d, e.cwd, *profile)
	code := printChecks(e, checks)
	if !*fix {
		return code
	}
	if own, root := repairsOf(checks); len(own)+len(root) == 0 {
		fmt.Fprintln(e.stdout, "\nNothing doctor --fix can repair; the remaining items need the steps shown.")
		return code
	}
	changed, code := applyRepairs(e, "doctor", checks, *yes)
	if code != exitOK || !changed {
		return code
	}
	fmt.Fprintln(e.stdout, "\n"+e.paint.Bold("After the repairs:"))
	return printChecks(e, doctor(d, e.cwd, *profile))
}

// printChecks prints the checks and their count; exitFail when one failed.
func printChecks(e env, checks []check) int {
	p := e.paint
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.state]++
		var line string
		switch c.state {
		case checkOK:
			line = p.OK(c.title)
		case checkWarn:
			line = p.Warn(p.Bold(c.title))
		default:
			line = p.Fail(p.Bold(c.title))
		}
		if c.detail != "" {
			line += p.Dim(" — " + c.detail)
		}
		fmt.Fprintln(e.stdout, line)
		if c.fix != "" && c.state != checkOK {
			fmt.Fprintf(e.stdout, "  %s %s\n", p.Accent("→"), c.fix)
		}
	}
	fmt.Fprintf(e.stdout, "\n%s passed · %s warnings · %s failed\n",
		p.Green(strconv.Itoa(counts[checkOK])), p.Yellow(strconv.Itoa(counts[checkWarn])), p.Red(strconv.Itoa(counts[checkFail])))
	if counts[checkFail] > 0 {
		return exitFail
	}
	return exitOK
}

// repairsOf splits the repairs of the checks that are not ok into the
// changes this account makes and those that run as root.
func repairsOf(checks []check) (own, root []*repair) {
	for _, c := range checks {
		if c.state == checkOK || c.repair == nil {
			continue
		}
		if c.repair.apply != nil {
			own = append(own, c.repair)
		}
		if c.repair.root != "" {
			root = append(root, c.repair)
		}
	}
	return own, root
}

// applyRepairs makes the repairs of the checks that are not ok: the
// changes this account can make first, then one root script, shown and
// confirmed (or yes) before sudo runs it. It reports each change and
// whether anything changed.
func applyRepairs(e env, cmd string, checks []check, yes bool) (changed bool, code int) {
	own, root := repairsOf(checks)
	if len(own) == 0 && len(root) == 0 {
		return false, exitOK
	}
	fmt.Fprintln(e.stdout)
	if len(root) > 0 && !yes && !e.tty {
		fmt.Fprintf(e.stderr, "locksql %s: some repairs run as root: confirm in a terminal, or run with --yes\n", cmd)
		return false, exitUsage
	}
	code = exitOK
	for _, r := range own {
		if err := r.apply(); err != nil {
			fmt.Fprintf(e.stdout, "%s %s: %v\n", e.paint.Fail("not repaired:"), r.what, err)
			code = exitFail
			continue
		}
		fmt.Fprintf(e.stdout, "%s %s\n", e.paint.OK("repaired:"), r.what)
		changed = true
	}
	if len(root) == 0 {
		return changed, code
	}
	var cmds []string
	for _, r := range root {
		cmds = append(cmds, r.root)
	}
	script := "set -eu\n" + strings.Join(cmds, "\n") + "\n"
	fmt.Fprintf(e.stdout, "These repairs run as root:\n%s\n", indent(script))
	if !yes {
		q := "Run them now with sudo? [y/N] "
		if e.geteuid() == 0 {
			q = "Run them now? [y/N] "
		}
		if !confirm(e, q) {
			fmt.Fprintln(e.stdout, "root repairs not made")
			return changed, code
		}
	}
	if err := e.asRoot(script); err != nil {
		fmt.Fprintf(e.stderr, "locksql %s: %v\n", cmd, err)
		return changed, exitFail
	}
	for _, r := range root {
		fmt.Fprintf(e.stdout, "%s %s\n", e.paint.OK("repaired:"), r.what)
	}
	return true, code
}

func doctor(d doctorEnv, cwd, onlyProfile string) []check {
	var out []check
	add := func(state, title, detail, fix string) {
		out = append(out, check{state: state, title: title, detail: detail, fix: fix})
	}

	// 1. Operating system (Linux or macOS; a Windows build refuses to run).
	add(checkOK, "operating system", d.goos, "")

	// 2. Graphical session.
	disp := d.display()
	switch disp.Kind {
	case sysconf.DisplayWayland, sysconf.DisplayQuartz:
		add(checkOK, "graphical session", disp.Kind, "")
	case sysconf.DisplayX11:
		add(checkWarn, "graphical session", "X11 ("+disp.Detail+"): any X client can read the keyboard and the screen of the others and inject input",
			"log in with a Wayland session (the console refuses X11 on production profiles)")
	case sysconf.DisplayTTY:
		add(checkOK, "graphical session", "none (text console or SSH)", "")
	default:
		add(checkWarn, "graphical session", disp.Kind+" ("+disp.Detail+")", "prefer a Wayland session")
	}

	me, err := d.current()
	if err != nil {
		add(checkFail, "current account", err.Error(), "")
		return out
	}
	myUID, _ := strconv.Atoi(me.Uid)

	// 3. Separation from the agent.
	sys, err := d.loadSys()
	switch {
	case err != nil:
		add(checkFail, "system setup", err.Error(), "fix "+product.SysconfPath()+" (root-owned, mode 0644), or "+imageHint)
		return out
	case sys == nil:
		add(checkFail, "separation", "same-user mode: the console refuses to run in the agent's account", imageHint)
		if on, known := d.tiocsti(); known && on {
			add(checkWarn, "terminal injection", "dev.tty.legacy_tiocsti = 1: a process can type into a terminal of its own account",
				"sysctl -w dev.tty.legacy_tiocsti=0 (default since Linux 6.2)")
		}
		if s, known := d.ptrace(); known && s == 0 {
			add(checkWarn, "ptrace", "kernel.yama.ptrace_scope = 0: any process of an account may attach to the others",
				"sysctl -w kernel.yama.ptrace_scope=1")
		}
	default:
		out = append(out, separationChecks(d, sys, me, myUID)...)
	}
	svc, isService := consoleAccount(d, sys, myUID)

	// The agents of this account, and the project the console serves.
	if !isService && myUID != 0 {
		out = append(out, wiringChecks(d)...)
	}
	if sys != nil && !isService && svc.uid >= 0 {
		if root, ok := config.FindProjectRoot(cwd); ok {
			out = append(out, projectChecks(d, root, svc, myUID)...)
		}
	}

	// 4. Binary.
	if bin, err := d.executable(); err == nil {
		if real, err := filepath.EvalSymlinks(bin); err == nil {
			bin = real
		}
		if fi, err := d.stat(bin); err == nil {
			uid, _, ok := d.ownerOf(fi)
			switch {
			case !ok:
			case uid == 0 && fi.Mode().Perm()&0o022 == 0:
				add(checkOK, "binary", bin+" belongs to root", "")
			case sys != nil:
				add(checkFail, "binary", bin+" can be changed by a non-root account: the console would run what the agent puts there",
					imageHint)
			default:
				add(checkWarn, "binary", bin+" is not owned by root", imageHint)
			}
		}
	}

	// 5. Profiles: the secret store and the running consoles.
	cfg, err := config.Load(cwd)
	if err != nil {
		add(checkFail, "configuration", err.Error(), "fix .locksql/config.toml")
		return out
	}
	names := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		if onlyProfile == "" || n == onlyProfile {
			names = append(names, n)
		}
	}
	if onlyProfile != "" && len(names) == 0 {
		// Not quoted back: --profile may be a token or a URL pasted in
		// the wrong place.
		add(checkFail, "profile", "--profile names none of the configured profiles: "+listOrNone(profileNames(cfg)), "")
		return out
	}
	slices.Sort(names)
	for _, n := range names {
		out = append(out, profileChecks(d, cfg.Profiles[n], sys, cwd)...)
	}
	return out
}

// consoleAccount is the console account of a separated setup (uid -1 when
// there is none), and whether this account (uid me) is it.
func consoleAccount(d doctorEnv, sys *sysconf.Config, me int) (svcAccount, bool) {
	if sys == nil {
		return svcAccount{uid: -1}, false
	}
	u, err := d.lookupUser(sys.ServiceUser)
	if err != nil {
		return svcAccount{name: sys.ServiceUser, uid: -1}, false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return svcAccount{name: sys.ServiceUser, uid: -1}, false
	}
	a := svcAccount{name: sys.ServiceUser, uid: uid}
	if d.groupIDs != nil {
		a.gids = d.groupIDs(u)
	}
	return a, uid == me
}

// wiringChecks reports the installed agents that are not wired for this
// account; --fix wires them as bare locksql does.
func wiringChecks(d doctorEnv) []check {
	if d.agents == nil {
		return nil
	}
	ae, err := d.agents()
	if err != nil {
		return nil
	}
	found := agentinit.Detect(ae)
	if len(found) == 0 {
		return []check{{state: checkOK, title: "agent wiring", detail: "no agent found (" + strings.Join(agentinit.Agents(), ", ") + ")"}}
	}
	var pending []string
	for _, a := range found {
		if p, err := agentinit.PendingUser(ae, a); err != nil || p {
			pending = append(pending, a)
		}
	}
	if len(pending) == 0 {
		return []check{{state: checkOK, title: "agent wiring", detail: "wired: " + strings.Join(found, ", ")}}
	}
	return []check{{state: checkWarn, title: "agent wiring", detail: "installed but not wired: " + strings.Join(pending, ", "),
		fix: "locksql doctor --fix (or bare locksql)",
		repair: &repair{what: "wire " + strings.Join(pending, ", ") + " for this account", apply: func() error {
			var errs []error
			for _, a := range pending {
				if _, err := agentinit.InitUser(ae, a); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", a, err))
				}
			}
			return errors.Join(errs...)
		}}}}
}

func separationChecks(d doctorEnv, sys *sysconf.Config, me *user.User, myUID int) []check {
	var out []check
	add := func(state, title, detail, fix string) {
		out = append(out, check{state: state, title: title, detail: detail, fix: fix})
	}
	// fixable adds a check that --fix repairs with root commands.
	fixable := func(state, title, detail, fix, what, root string) {
		out = append(out, check{state: state, title: title, detail: detail, fix: fix, repair: &repair{what: what, root: root}})
	}
	add(checkOK, "system setup", product.SysconfPath()+" (root-owned)", "")
	svc, err := d.lookupUser(sys.ServiceUser)
	if err != nil {
		add(checkFail, "console account", fmt.Sprintf("%q does not exist", sys.ServiceUser), imageHint)
		return out
	}
	svcUID, _ := strconv.Atoi(svc.Uid)
	add(checkOK, "console account", fmt.Sprintf("%s (uid %d)", sys.ServiceUser, svcUID), "")
	if d.inGroup(svcUID, sys.ClientGroup) {
		cmd := fmt.Sprintf("gpasswd -d %s %s", shellQuote(sys.ServiceUser), shellQuote(sys.ClientGroup))
		if d.goos == "darwin" {
			cmd = fmt.Sprintf("dseditgroup -o edit -d %s -t user %s", shellQuote(sys.ServiceUser), shellQuote(sys.ClientGroup))
		}
		fixable(checkFail, "console account isolated", fmt.Sprintf("%s is in the client group %s: it could talk to itself as a client", sys.ServiceUser, sys.ClientGroup),
			"sudo "+cmd, "remove "+sys.ServiceUser+" from "+sys.ClientGroup, cmd)
	} else {
		add(checkOK, "console account isolated", "not a member of "+sys.ClientGroup, "")
	}

	if myUID != svcUID {
		// The agent's side.
		if d.inGroup(myUID, sys.ClientGroup) || containsInt(sys.AllowedUIDs, myUID) {
			add(checkOK, "client access", me.Username+" may reach the console", "")
		} else {
			cmd := fmt.Sprintf("usermod -aG %s %s", shellQuote(sys.ClientGroup), shellQuote(me.Username))
			if d.goos == "darwin" {
				cmd = fmt.Sprintf("dseditgroup -o edit -a %s -t user %s", shellQuote(me.Username), shellQuote(sys.ClientGroup))
			}
			if myUID == 0 { // root is no agent's account: nothing to add
				add(checkFail, "client access", me.Username+" is not in "+sys.ClientGroup, "run locksql doctor from the agent's account")
			} else {
				fixable(checkFail, "client access", me.Username+" is not in "+sys.ClientGroup,
					"sudo "+cmd+", then log out and in again", "add "+me.Username+" to "+sys.ClientGroup+" (log out and in again)", cmd)
			}
		}
		if d.sudoNoPass() {
			add(checkFail, "privilege escalation", me.Username+" can run sudo without a password: the agent could become "+sys.ServiceUser+" or root",
				"require a password for sudo (remove NOPASSWD, keep timestamp_timeout short) or run the agent under an account without sudo")
		} else {
			add(checkOK, "privilege escalation", "no password-less sudo for "+me.Username, "")
		}
	} else {
		add(checkOK, "running as", "the console account "+sys.ServiceUser, "")
	}

	// A login session of the console account.
	if d.goos == "linux" {
		if _, err := d.stat(filepath.Join("/run/user", svc.Uid)); err == nil {
			add(checkOK, "separate session", sys.ServiceUser+" has a login session", "")
		} else {
			add(checkWarn, "separate session", sys.ServiceUser+" has no login session now",
				"log in as "+sys.ServiceUser+" in a session of its own (switch user, Wayland) and run the console there")
		}
	}

	// The socket directory.
	wantMode := "0710"
	if d.goos == "linux" {
		wantMode = "2710"
	}
	dirFix := socketDirScript(d.goos, sys, wantMode)
	dirWhat := fmt.Sprintf("create %s %s %s:%s", sys.SocketDir, wantMode, sys.ServiceUser, sys.ClientGroup)
	if fi, err := d.stat(sys.SocketDir); err != nil {
		fixable(checkFail, "socket directory", sys.SocketDir+" is missing", "locksql doctor --fix (or systemd-tmpfiles --create)", dirWhat, dirFix)
	} else {
		uid, gid, ok := d.ownerOf(fi)
		perm := fi.Mode().Perm()
		shown := perm // with setgid, as chmod takes it
		if fi.Mode()&os.ModeSetgid != 0 {
			shown |= 0o2000
		}
		want := ""
		if g, err := user.LookupGroup(sys.ClientGroup); err == nil {
			want = g.Gid
		}
		dirWhat = fmt.Sprintf("set %s to %s %s:%s", sys.SocketDir, wantMode, sys.ServiceUser, sys.ClientGroup)
		switch {
		case !ok:
		case uid != svcUID:
			fixable(checkFail, "socket directory", fmt.Sprintf("%s belongs to uid %d, not %s", sys.SocketDir, uid, sys.ServiceUser),
				fmt.Sprintf("sudo chown %s:%s %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir), dirWhat, dirFix)
		case want != "" && strconv.Itoa(gid) != want:
			fixable(checkFail, "socket directory", sys.SocketDir+" does not belong to group "+sys.ClientGroup,
				fmt.Sprintf("sudo chown %s:%s %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir), dirWhat, dirFix)
		case perm&0o027 != 0 || perm&0o010 == 0:
			fixable(checkFail, "socket directory", fmt.Sprintf("%s has mode %04o", sys.SocketDir, shown), "sudo chmod "+wantMode+" "+sys.SocketDir, dirWhat, dirFix)
		case d.goos == "linux" && fi.Mode()&os.ModeSetgid == 0:
			// The console cannot give its socket to the client group.
			fixable(checkFail, "socket directory", fmt.Sprintf("%s has mode %04o, without setgid", sys.SocketDir, shown),
				"locksql doctor --fix (it also fixes /etc/tmpfiles.d/locksql.conf)", dirWhat, dirFix)
		default:
			add(checkOK, "socket directory", fmt.Sprintf("%s %04o %s:%s", sys.SocketDir, shown, sys.ServiceUser, sys.ClientGroup), "")
		}
	}
	return out
}

// socketDirScript (re)creates the socket directory with its owner, group
// and mode, and on Linux the tmpfiles.d entry that recreates it at boot.
func socketDirScript(goos string, sys *sysconf.Config, mode string) string {
	dir, owner := shellQuote(sys.SocketDir), shellQuote(sys.ServiceUser)+":"+shellQuote(sys.ClientGroup)
	s := fmt.Sprintf("mkdir -p %s\nchown %s %s\nchmod %s %s", dir, owner, dir, mode, dir)
	if goos == "linux" {
		s += fmt.Sprintf("\ninstall -d -m 0755 -o root -g root /etc/tmpfiles.d\nprintf 'd %%s %s %%s %%s -\\n' %s %s %s > /etc/tmpfiles.d/locksql.conf",
			mode, dir, shellQuote(sys.ServiceUser), shellQuote(sys.ClientGroup))
	}
	return s
}

func profileChecks(d doctorEnv, p config.Profile, sys *sysconf.Config, cwd string) []check {
	var out []check
	name := "profile " + p.Name
	add := func(state, title, detail, fix string) {
		out = append(out, check{state: state, title: name + ": " + title, detail: detail, fix: fix})
	}

	if p.Credentials == config.CredentialsKeychain {
		err := d.keychain(p.Name, p.Host, p.Port)
		switch {
		case sys != nil && err == nil:
			add(checkFail, "secret store", "a secret for this profile is in this account's keychain, which the agent can read",
				"locksql forget --profile "+p.Name+" here; store it as "+sys.ServiceUser+" instead")
		case sys != nil:
			add(checkOK, "secret store", "no secret in this account's keychain (the console account keeps its own)", "")
		case errors.Is(err, secrets.ErrUnavailable):
			add(checkWarn, "secret store", "the OS keychain is unavailable: the console will ask for the secret", "unlock or install a Secret Service (GNOME Keyring, KeePassXC)")
		default:
			add(checkOK, "secret store", "OS keychain available", "")
		}
	} else if p.Credentials == config.CredentialsVault {
		out = append(out, vaultChecks(d, p, sys, name)...)
	} else if p.CredentialsTTL > 0 {
		add(checkOK, "credentials", "asked at start, again every "+p.CredentialsTTL.String(), "")
	} else {
		add(checkOK, "credentials", "asked at every console start", "")
	}

	if p.Engine != config.EngineSQLite && !strings.HasPrefix(p.Host, "/") {
		switch {
		case config.TLSVerifiesChain(p.TLS, p.TLSCA):
			add(checkOK, "tls", "tls = \""+p.TLS+"\": the server certificate is verified", "")
		case p.SSH != nil && config.IsLoopback(p.Host):
			add(checkOK, "tls", "the database is on the bastion: the ssh tunnel encrypts the whole path (tls = \""+p.TLS+"\")", "")
		case len(p.ProxyCommand) > 0 && config.IsLoopback(p.Host):
			add(checkOK, "tls", "the database listens on loopback where proxy_command runs: the command carries the whole path (tls = \""+p.TLS+"\")", "")
		case config.IsLoopback(p.Host):
			add(checkOK, "tls", "loopback host: tls = \""+p.TLS+"\"", "")
		case len(p.ProxyCommand) > 0:
			add(checkWarn, "tls", "tls = \""+p.TLS+"\": proxy_command carries the stream to where it runs, but an attacker on the network between there and "+p.Host+" can read the traffic or obtain the password",
				"set tls = \"verify-full\" (and tls_ca if the server's CA is private), or proxy to the database's own loopback")
		case p.SSH != nil:
			add(checkWarn, "tls", "tls = \""+p.TLS+"\": encrypted by ssh to "+p.SSH.Host+", but an attacker on the bastion's network can read the traffic or obtain the password",
				"set tls = \"verify-full\" (and tls_ca if the server's CA is private)")
		default:
			add(checkWarn, "tls", "tls = \""+p.TLS+"\": an attacker on the path can read the traffic or obtain the password",
				"set tls = \"verify-full\" (and tls_ca if the server's CA is private), or reach the server through an ssh tunnel")
		}
	}

	out = append(out, tlsChecks(d, p, sys, name)...)

	if s := p.SSH; s != nil {
		add(checkOK, "ssh", "reached through "+s.User+"@"+s.Host+":"+strconv.Itoa(s.Port)+" ("+s.Auth+")", "")
		if s.Auth == config.SSHAuthKey {
			path := s.Key
			if rest, ok := strings.CutPrefix(path, "~/"); ok {
				home := "~"
				if sys != nil {
					home = "the console account's home"
				} else if h, err := os.UserHomeDir(); err == nil {
					home = h
				}
				path = filepath.Join(home, rest)
			}
			if st, err := d.stat(path); err != nil {
				if sys == nil {
					var pe *fs.PathError
					if errors.As(err, &pe) {
						err = pe.Err // the path is already in the detail
					}
					add(checkFail, "ssh key", path+": "+err.Error(), "check ssh.key")
				}
				// In a separated setup the key lives in the console account's
				// home, which this account cannot read: nothing to check here.
			} else if st.Mode().Perm()&0o077 != 0 {
				add(checkFail, "ssh key", path+" is readable by others", "chmod 600 "+path)
			} else {
				add(checkOK, "ssh key", path+" is private", "")
			}
		}
	}

	if len(p.ProxyCommand) > 0 {
		out = append(out, proxyChecks(d, p, sys, cwd, name)...)
	}

	st, err := d.status(cwd, p.Name)
	if err != nil {
		if errors.Is(err, client.ErrNoConsole) {
			add(checkWarn, "console", "not running: connectivity, privileges and EXPLAIN are checked by a running console",
				"start it: "+startCommandOf(err, p.Name)+" (then `lox attach INSTANCE` answers its questions)")
		} else {
			add(checkFail, "console", err.Error(), "")
		}
		return out
	}
	detail := "running, socket reachable"
	if st.ShowResults {
		detail += "; shows results in clear (--show-results)"
	}
	add(checkOK, "console", detail, "")
	h := st.Health
	if h == nil {
		add(checkWarn, "console health", "the console is too old to report its health", "upgrade it")
		return out
	}
	switch {
	case sys != nil && !h.Separated:
		add(checkFail, "console separation", "the console does not run in separated mode", "restart it as "+sys.ServiceUser)
	case h.Separated:
		add(checkOK, "console separation", "the console runs as the console account", "")
	}
	if h.Display == sysconf.DisplayX11 {
		add(checkWarn, "console display", "the console runs in an X11 session", "run it in a Wayland session")
	}
	if len(h.Privileges) == 0 {
		add(checkOK, "database privileges", "nothing beyond tier "+st.Tier, "")
	} else {
		add(checkWarn, "database privileges", strings.Join(h.Privileges, "; "), "use a least-privilege ("+st.Tier+"-only) database account")
	}
	if h.ExplainOK {
		add(checkOK, "EXPLAIN", "works on the server", "")
	} else {
		add(checkFail, "EXPLAIN", "fails on the server: every statement will be refused", "check the account's rights to EXPLAIN")
	}
	return out
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// vaultChecks reports on a profile whose login is read from Vault. In a
// separated setup the console account reads it, so a Vault token this
// account holds lets the agent read the login itself.
func vaultChecks(d doctorEnv, p config.Profile, sys *sysconf.Config, name string) []check {
	var out []check
	add := func(state, title, detail, fix string) {
		out = append(out, check{state: state, title: name + ": " + title, detail: detail, fix: fix})
	}
	if sys != nil {
		var held []string
		if d.getenv != nil && d.getenv("VAULT_TOKEN") != "" {
			held = append(held, "VAULT_TOKEN is set")
		}
		if me, err := d.current(); err == nil && me.HomeDir != "" && d.stat != nil {
			if _, err := d.stat(filepath.Join(me.HomeDir, ".vault-token")); err == nil {
				held = append(held, "~/.vault-token exists")
			}
		}
		if len(held) > 0 {
			add(checkFail, "vault token", "this account holds a Vault token ("+strings.Join(held, ", ")+"), which the agent can use to read the login at "+p.VaultPath,
				"unset VAULT_TOKEN and run `vault token revoke -self` here; the console asks "+sys.ServiceUser+"'s human for the token at start")
		} else {
			add(checkOK, "credentials", "read from Vault at "+p.VaultPath+" by "+sys.ServiceUser+" at every connection, with the token asked at start", "")
		}
		return out
	}
	if d.lookPath != nil {
		if _, err := d.lookPath(secrets.VaultCommand); err != nil {
			add(checkFail, "vault CLI", "credentials = \"vault\" needs the vault CLI, not found in PATH", "install it: https://developer.hashicorp.com/vault/install")
			return out
		}
	}
	add(checkOK, "credentials", "read from Vault at "+p.VaultPath+" at every connection, with the token asked at start", "")
	return out
}

// proxyChecks reports on a profile reached through proxy_command: the
// program must exist, and must not live in the project, which the agent
// can write to after the human approved the command.
func proxyChecks(d doctorEnv, p config.Profile, sys *sysconf.Config, cwd, name string) []check {
	add := func(state, detail, fix string) []check {
		return []check{{state: state, title: name + ": proxy_command", detail: detail, fix: fix}}
	}
	argv := config.ProxyString(p.ProxyCommand)
	prog := p.ProxyCommand[0]
	if filepath.IsAbs(prog) {
		if root, ok := config.FindProjectRoot(cwd); ok {
			if rel, err := filepath.Rel(root, prog); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return add(checkFail, prog+" is inside the project "+root+", where the agent can rewrite it after the approval",
					"install the program outside the project, owned by root or the console account")
			}
		}
	}
	// In a separated setup the console account runs the command with its
	// own PATH: nothing to look up here.
	if sys == nil {
		var err error
		if filepath.IsAbs(prog) {
			_, err = d.stat(prog)
		} else if d.lookPath != nil {
			_, err = d.lookPath(prog)
		}
		if err != nil {
			return add(checkFail, prog+" not found: "+argv, "install it, or fix proxy_command")
		}
	}
	return add(checkOK, "reached through "+argv, "")
}
