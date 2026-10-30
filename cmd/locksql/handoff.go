package main

import (
	"errors"
	"fmt"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockkit/sysconf"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// handoffEnv holds what the console handoff reads from the system; tests
// replace it.
type handoffEnv struct {
	goos          string
	uid           func() int
	userName      func(uid int) string
	serviceUID    func(sys *sysconf.Config) (int, error)
	clientAllowed func(sys *sysconf.Config, uid int) bool
	lookPath      func(string) (string, error)
	// systemd reports whether systemd runs the machine (machinectl shell
	// needs it).
	systemd func() bool
	// binary is the root-owned locksql binary the console account runs.
	binary func() (string, error)
	// exec replaces this process with argv; it returns only on failure.
	exec func(argv []string) error
}

func realHandoffEnv() *handoffEnv {
	return &handoffEnv{
		goos: runtime.GOOS,
		uid:  os.Getuid,
		userName: func(uid int) string {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				return u.Username
			}
			return "uid " + strconv.Itoa(uid)
		},
		serviceUID:    func(sys *sysconf.Config) (int, error) { return sys.ServiceUID() },
		clientAllowed: func(sys *sysconf.Config, uid int) bool { return sys.ClientAllowed(uid) },
		lookPath:      exec.LookPath,
		systemd: func() bool {
			fi, err := os.Stat("/run/systemd/system")
			return err == nil && fi.IsDir()
		},
		binary: trustedBinary,
		exec: func(argv []string) error {
			// The helper (sudo, su, machinectl) resets the environment of
			// the console account; locksql adds nothing to it, and the
			// arguments hold no secret.
			return syscall.Exec(argv[0], argv, os.Environ())
		},
	}
}

func (e env) handoffEnv() *handoffEnv {
	if e.handoff != nil {
		return e.handoff
	}
	return realHandoffEnv()
}

// trustedBinary is the locksql binary the console account may run: this
// one when root alone may change it, else /usr/local/bin/locksql when root
// alone may change that. The console must never run a binary the agent's
// account could have replaced.
func trustedBinary() (string, error) {
	bin, err := os.Executable()
	if err == nil {
		bin, err = filepath.EvalSymlinks(bin)
	}
	if err == nil {
		if msg, err := installSourceRefusal(bin); err == nil && msg == "" {
			return bin, nil
		}
	}
	if msg, err := installSourceRefusal(installedBinary); err == nil && msg == "" {
		return installedBinary, nil
	}
	return "", errors.New("no root-owned locksql binary to run as the console account: " + imageHint)
}

// consoleArgs are the console flags passed on to the console account.
type consoleArgs struct {
	profile, project               string
	auto, allowUnmask, showResults bool
	hub                            kconsole.HubOptions
	// noUpdateCheck forwards LOCKSQL_NO_UPDATE_CHECK, which the helper
	// does not pass on, as an internal flag.
	noUpdateCheck bool
}

// argv is the console command line, after the binary.
func (a consoleArgs) argv() []string {
	out := []string{"console", "--project", a.project}
	if a.profile != "" {
		out = append(out, "--profile", a.profile)
	}
	if a.auto {
		out = append(out, "--auto")
	}
	if a.allowUnmask {
		out = append(out, "--allow-unmask")
	}
	if a.showResults {
		out = append(out, "--show-results")
	}
	if a.hub.Enabled() {
		out = append(out, "--hub", a.hub.URL, "--hub-key-file", a.hub.KeyFile, "--instance", a.hub.Instance)
	}
	return out
}

// command is the console command line to type in the console account.
func (a consoleArgs) command() string {
	parts := []string{"locksql"}
	for _, s := range a.argv() {
		parts = append(parts, shellWord(s))
	}
	return strings.Join(parts, " ")
}

// shellWord quotes s for sh only when it needs quoting.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:@") == "" {
		return s
	}
	return shellQuote(s)
}

// consoleProject is the project directory a console started in cwd
// serves: the project root, else cwd itself.
func consoleProject(cwd, project string) (string, error) {
	if project != "" {
		return filepath.Abs(project)
	}
	if root, ok := config.FindProjectRoot(cwd); ok {
		return root, nil
	}
	return filepath.Abs(cwd)
}

// helperArgv is the command that runs bin with args as the console
// account svc, through the first helper available: sudo -u, machinectl
// shell (systemd), su -l. Each asks for its own authentication; none gets
// a secret from locksql.
func helperArgv(h *handoffEnv, svc, bin string, args []string) (argv []string, name string) {
	if p, err := h.lookPath("sudo"); err == nil {
		return append([]string{p, "-u", svc, "-H", "--", bin}, args...), "sudo -u " + svc
	}
	if h.goos == "linux" && h.systemd() {
		if p, err := h.lookPath("machinectl"); err == nil {
			return append([]string{p, "shell", "--quiet", svc + "@", bin}, args...), "machinectl shell " + svc + "@"
		}
	}
	if p, err := h.lookPath("su"); err == nil {
		words := []string{shellQuote(bin)}
		for _, a := range args {
			words = append(words, shellQuote(a))
		}
		return []string{p, "-l", svc, "-c", strings.Join(words, " ")}, "su -l " + svc
	}
	return nil, ""
}

// handoffConsole opens the console in the console account when `locksql
// console` was started from another account of a separated setup. handled
// is false when this process runs the console itself: no separated setup
// (or one that does not load: the console reports it), or this is the
// console account.
//
// The console must not read a terminal that the agent's account can read
// or type into, so an account that may reach the console (the agent's) is
// not handed off: it is told to open a session of the console account.
// Another account (an administrator's, when the agents run under an
// account of their own) is handed off through a helper; the console then
// applies its own isolation checks.
func handoffConsole(e env, a consoleArgs) (code int, handled bool) {
	sys, err := sysConfig(e)
	if err != nil || sys == nil {
		return 0, false
	}
	h := e.handoffEnv()
	svcUID, err := h.serviceUID(sys)
	if err != nil {
		return 0, false // the console names the missing account
	}
	uid := h.uid()
	if uid == svcUID {
		return 0, false
	}
	if h.clientAllowed(sys, uid) {
		fmt.Fprintf(e.stderr, `locksql console: the console does not run in this terminal: it belongs to %s, an account that
may reach the console (group %s), where your agents run; they could read what you type
here (the database password) and type approvals.
Open a session of %s's own (switch user on the desktop, or a text console with Ctrl-Alt-F3)
and run there:
    %s
`, h.userName(uid), sys.ClientGroup, sys.ServiceUser, a.command())
		return exitFail, true
	}
	bin, err := h.binary()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql console:", err)
		return exitFail, true
	}
	args := a.argv()
	if a.noUpdateCheck {
		args = append(args, noUpdateCheckFlag)
	}
	argv, name := helperArgv(h, sys.ServiceUser, bin, args)
	if argv == nil {
		fmt.Fprintf(e.stderr, "locksql console: no sudo, machinectl or su to reach the console account %s; log in as %s and run:\n    %s\n",
			sys.ServiceUser, sys.ServiceUser, a.command())
		return exitFail, true
	}
	fmt.Fprintf(e.stdout, "Opening the console as %s through %s.\n", sys.ServiceUser, name)
	if err := h.exec(argv); err != nil {
		fmt.Fprintf(e.stderr, "locksql console: %s: %v\n", name, err)
		return exitFail, true
	}
	return exitOK, true
}
