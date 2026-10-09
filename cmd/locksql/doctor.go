package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/secrets"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
	"github.com/DavidGodefroid/locksql/internal/ui"
)

// Check outcomes.
const (
	checkOK   = ui.MarkOK
	checkWarn = ui.MarkWarn
	checkFail = ui.MarkFail
)

type check struct {
	state, title, detail, fix string
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
	keychain   func(profile, host string) error
	status     func(cwd, profile string) (*ipc.StatusResult, error)
}

func realDoctorEnv() doctorEnv {
	return doctorEnv{
		goos:       runtime.GOOS,
		loadSys:    sysconf.Load,
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
		executable: os.Executable,
		stat:       os.Stat,
		ownerOf:    fileOwner,
		tiocsti:    sysconf.LegacyTIOCSTI,
		ptrace:     sysconf.PtraceScope,
		keychain: func(profile, host string) error {
			s, err := secrets.KeychainGet(profile, host)
			secrets.Wipe(s)
			return err
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
// keep the agent away from the credentials and the data.
func runDoctor(e env, args []string) int {
	const usage = "locksql doctor [--profile P]"
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile whose console to check (default: every profile)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	checks := doctor(realDoctorEnv(), e.cwd, *profile)
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

func doctor(d doctorEnv, cwd, onlyProfile string) []check {
	var out []check
	add := func(state, title, detail, fix string) {
		out = append(out, check{state, title, detail, fix})
	}

	// 1. Operating system.
	switch d.goos {
	case "linux", "darwin":
		add(checkOK, "operating system", d.goos, "")
	default:
		add(checkFail, "operating system", d.goos+" is not supported", "use Linux or macOS")
	}

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
		add(checkFail, "system setup", err.Error(), "fix "+sysconf.Path+" (root-owned, mode 0644) or run sudo locksql install again")
		return out
	case sys == nil:
		add(checkWarn, "separation", "same-user mode: the agent runs as the console's account and could read its terminal or type into it",
			"run sudo locksql install, then use the console from a separate locksql session")
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
					"run the console from /usr/local/bin/locksql (sudo locksql install copies it there)")
			default:
				add(checkWarn, "binary", bin+" is not owned by root", "install locksql system-wide (sudo locksql install)")
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
		add(checkFail, "profile "+onlyProfile, "not in the configuration", "")
		return out
	}
	slices.Sort(names)
	for _, n := range names {
		out = append(out, profileChecks(d, cfg.Profiles[n], sys, cwd)...)
	}
	return out
}

func separationChecks(d doctorEnv, sys *sysconf.Config, me *user.User, myUID int) []check {
	var out []check
	add := func(state, title, detail, fix string) { out = append(out, check{state, title, detail, fix}) }
	add(checkOK, "system setup", sysconf.Path+" (root-owned)", "")
	svc, err := d.lookupUser(sys.ServiceUser)
	if err != nil {
		add(checkFail, "console account", fmt.Sprintf("%q does not exist", sys.ServiceUser), "run sudo locksql install")
		return out
	}
	svcUID, _ := strconv.Atoi(svc.Uid)
	add(checkOK, "console account", fmt.Sprintf("%s (uid %d)", sys.ServiceUser, svcUID), "")
	if d.inGroup(svcUID, sys.ClientGroup) {
		add(checkFail, "console account isolated", fmt.Sprintf("%s is in the client group %s: it could talk to itself as a client", sys.ServiceUser, sys.ClientGroup),
			fmt.Sprintf("sudo gpasswd -d %s %s", sys.ServiceUser, sys.ClientGroup))
	} else {
		add(checkOK, "console account isolated", "not a member of "+sys.ClientGroup, "")
	}

	if myUID != svcUID {
		// The agent's side.
		if d.inGroup(myUID, sys.ClientGroup) || containsInt(sys.AllowedUIDs, myUID) {
			add(checkOK, "client access", me.Username+" may reach the console", "")
		} else {
			add(checkFail, "client access", me.Username+" is not in "+sys.ClientGroup,
				fmt.Sprintf("sudo usermod -aG %s %s, then log out and in again", sys.ClientGroup, me.Username))
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
	if fi, err := d.stat(sys.SocketDir); err != nil {
		add(checkFail, "socket directory", sys.SocketDir+" is missing", "run sudo locksql install (or systemd-tmpfiles --create)")
	} else {
		uid, gid, ok := d.ownerOf(fi)
		perm := fi.Mode().Perm()
		want := ""
		if g, err := user.LookupGroup(sys.ClientGroup); err == nil {
			want = g.Gid
		}
		switch {
		case !ok:
		case uid != svcUID:
			add(checkFail, "socket directory", fmt.Sprintf("%s belongs to uid %d, not %s", sys.SocketDir, uid, sys.ServiceUser),
				fmt.Sprintf("sudo chown %s:%s %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir))
		case want != "" && strconv.Itoa(gid) != want:
			add(checkFail, "socket directory", sys.SocketDir+" does not belong to group "+sys.ClientGroup,
				fmt.Sprintf("sudo chown %s:%s %s", sys.ServiceUser, sys.ClientGroup, sys.SocketDir))
		case perm&0o027 != 0 || perm&0o010 == 0:
			add(checkFail, "socket directory", fmt.Sprintf("%s has mode %04o", sys.SocketDir, perm), "sudo chmod 0710 "+sys.SocketDir)
		default:
			add(checkOK, "socket directory", fmt.Sprintf("%s %04o %s:%s", sys.SocketDir, perm, sys.ServiceUser, sys.ClientGroup), "")
		}
	}
	return out
}

func profileChecks(d doctorEnv, p config.Profile, sys *sysconf.Config, cwd string) []check {
	var out []check
	name := "profile " + p.Name
	add := func(state, title, detail, fix string) {
		out = append(out, check{state, name + ": " + title, detail, fix})
	}

	if p.Credentials == config.CredentialsKeychain {
		err := d.keychain(p.Name, p.Host)
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
	} else if p.CredentialsTTL > 0 {
		add(checkOK, "credentials", "asked at start, again every "+p.CredentialsTTL.String(), "")
	} else {
		add(checkOK, "credentials", "asked at every console start", "")
	}

	st, err := d.status(cwd, p.Name)
	if err != nil {
		if errors.Is(err, client.ErrNoConsole) {
			start := client.StartCommand(p.Name, "")
			var nc *client.NoConsoleError
			if errors.As(err, &nc) {
				start = nc.Command()
			}
			add(checkWarn, "console", "not running: connectivity, privileges and EXPLAIN are checked by a running console",
				"start it: "+start)
		} else {
			add(checkFail, "console", err.Error(), "")
		}
		return out
	}
	add(checkOK, "console", "running, socket reachable", "")
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
