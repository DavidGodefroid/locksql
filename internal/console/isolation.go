package console

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/fingerprint"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// isolation is how the console is kept apart from the agent: in a
// separated setup (sysconf) the console runs as the service account and
// serves the client group over a shared socket, either in its own login
// session (the session shape: the kernel keeps the agent out of its
// terminal) or in a terminal of the console account opened on the agent's
// desktop (the desktop shape: every approval also takes a fingerprint).
// Without one it refuses to start (except in a test build:
// allowSameUserForTests).
type isolation struct {
	sys     *sysconf.Config
	display sysconf.Display
	self    int
	gid     int
	allowed func(uid int) bool
	// desktop is the desktop shape; verifier is then its fingerprint
	// reader (nil at level 1 and in the session shape).
	desktop  bool
	verifier fingerprint.Verifier
}

// isolationEnv holds what checkIsolation reads from the system; tests
// replace it.
type isolationEnv struct {
	loadSys       func() (*sysconf.Config, error)
	display       func() sysconf.Display
	uid           func() int
	userName      func() (string, error)
	loginUID      func() (int, bool)
	terminalOwner func() (int, bool)
	clientAllowed func(sys *sysconf.Config, uid int) bool
	clientGID     func(sys *sysconf.Config) (int, error)
	// accountExists reports whether uid names an account.
	accountExists func(uid int) bool
	// relay reports a session opened through a relay (sysconf.SessionRelay).
	relay func() string
	// machinectlUIDs lists the callers of running `machinectl shell`
	// processes (sysconf.MachinectlShellUIDs).
	machinectlUIDs func() ([]int, bool)
	// desktopEnv reports LOCKSQL_DESKTOP=1: the desktop shape is asked for.
	desktopEnv func() bool
	// displaySet reports a non-empty DISPLAY.
	displaySet func() bool
	// parentChain lists the ancestors of the process, from the parent up
	// (sysconf.ParentChain).
	parentChain func() ([]sysconf.Proc, error)
	// newVerifier opens the fingerprint reader of user.
	newVerifier func(user string) (fingerprint.Verifier, error)
}

func realIsolationEnv(tty *os.File) isolationEnv {
	return isolationEnv{
		loadSys: sysconf.Load,
		display: sysconf.DetectDisplay,
		uid:     os.Getuid,
		userName: func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		},
		loginUID: sysconf.LoginUID,
		terminalOwner: func() (int, bool) {
			if tty == nil {
				return 0, false
			}
			return sysconf.TerminalOwner(tty)
		},
		clientAllowed: func(sys *sysconf.Config, uid int) bool { return sys.ClientAllowed(uid) },
		clientGID:     func(sys *sysconf.Config) (int, error) { return sys.ClientGID() },
		accountExists: func(uid int) bool {
			_, err := user.LookupId(strconv.Itoa(uid))
			return err == nil
		},
		relay:          sysconf.SessionRelay,
		machinectlUIDs: sysconf.MachinectlShellUIDs,
		desktopEnv:     func() bool { return os.Getenv("LOCKSQL_DESKTOP") == "1" },
		displaySet:     func() bool { return os.Getenv("DISPLAY") != "" },
		parentChain:    sysconf.ParentChain,
		newVerifier: func(user string) (fingerprint.Verifier, error) {
			return fingerprint.NewFprintd(fingerprint.Options{User: user, OwnerUID: 0})
		},
	}
}

// allowSameUserForTests lets the console run without a separated setup, in
// the agent's account. Only isolation_testhook.go sets it, in a build with
// the locksql_testhook tag: no config file, flag, environment variable or
// client can.
var allowSameUserForTests bool

// sameUserRefusal is the one text of the same-user refusal.
const sameUserRefusal = "console: refused: the console must run in a separate account, apart from the agent's, or the agent could read its terminal and type into it; run `locksql doctor`, then `sudo locksql install`"

// SameUserRefused is the refusal of a console without a separated setup
// (sys nil, as sysconf.Load returns it), or nil.
func SameUserRefused(sys *sysconf.Config) error {
	if sys == nil && !allowSameUserForTests {
		return errors.New(sameUserRefusal)
	}
	return nil
}

// checkIsolation applies the separation rules before any prompt and before
// the console writes any state. Warnings go to the terminal; a violation is
// an error. The production rule on X11 needs the profile and is applied
// later, by refuseX11IfProduction.
func checkIsolation(io IO, env isolationEnv) (*isolation, error) {
	sys, err := env.loadSys()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if err := SameUserRefused(sys); err != nil {
		return nil, err
	}
	iso := &isolation{sys: sys, display: env.display(), self: env.uid(), gid: -1}

	if iso.display.Kind == sysconf.DisplayX11 {
		msg := "the console runs in an X11 session (" + iso.display.Detail + "): any X client, the agent's included, can read its keyboard and screen and send it keystrokes"
		if sys != nil && sys.X11 == sysconf.X11Refuse {
			return nil, errors.New("console: refused: " + msg + "; run it in a Wayland session or on a text console")
		}
		io.Println(red + "warning: " + msg + "; prefer a Wayland session" + reset)
	}

	if sys == nil { // only a test build gets here (allowSameUserForTests)
		io.Println(red + "same-user mode: test build only" + reset)
		return iso, nil
	}

	name, err := env.userName()
	if err != nil {
		return nil, fmt.Errorf("console: cannot read the current account: %w", err)
	}
	if name != sys.ServiceUser {
		return nil, fmt.Errorf("console: this machine separates the console from the agent (%s): run the console as %q, in its own login session, not as %q",
			sysconf.Path, sys.ServiceUser, name)
	}
	if env.clientAllowed(sys, iso.self) {
		return nil, fmt.Errorf("console: the account %q may also connect as a client (group %q or allowed_uids): the separation would be void", name, sys.ClientGroup)
	}
	if env.desktopEnv() {
		return iso.desktopShape(io, env, name)
	}
	// Another account's session or terminal is refused when that account
	// may reach the console (the agent's: it could read the terminal and
	// type into it) or names no account. An account outside the client
	// group (an administrator handing the console off with sudo, su or
	// machinectl, while the agents run under an account of their own) is
	// out of the agent's reach.
	agentSide := func(uid int) bool { return !env.accountExists(uid) || env.clientAllowed(sys, uid) }
	if lu, ok := env.loginUID(); ok && lu >= 0 && lu != iso.self {
		if agentSide(lu) {
			return nil, fmt.Errorf("console: started from the login session of uid %d (sudo or su), which may reach the console: that account shares this terminal and display; log in as %q in a session of its own",
				lu, sys.ServiceUser)
		}
		io.Println(fmt.Sprintf("started from the login session of uid %d, an account outside the client group", lu))
	}
	if owner, ok := env.terminalOwner(); ok && owner != iso.self && agentSide(owner) {
		return nil, fmt.Errorf("console: the terminal belongs to uid %d, which may reach the console: its owner can read it and type into it; open a terminal in %q's own session",
			owner, sys.ServiceUser)
	}
	if err := checkRelay(io, env, sys, agentSide); err != nil {
		return nil, err
	}
	gid, err := env.clientGID(sys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (run locksql install)", ErrConfig, err)
	}
	iso.gid = gid
	iso.allowed = func(uid int) bool { return env.clientAllowed(sys, uid) }
	io.Println("session mode: boundary: kernel")
	return iso, nil
}

// refuseX11IfProduction applies the production rule once the profile is
// known: a production profile never runs in an X11 session.
func (iso *isolation) refuseX11IfProduction(p config.Profile) error {
	if p.Production && iso.display.Kind == sysconf.DisplayX11 {
		return errors.New("console: refused: production profile in an X11 session; run it in a Wayland session or on a text console")
	}
	return nil
}

// desktopShape accepts a console of the service account opened in a
// terminal on the agent's desktop session (LOCKSQL_DESKTOP=1): Wayland with
// no DISPLAY (no X client reads its keyboard), a terminal and a terminal
// emulator of the console account (the agent's account can neither read
// nor write them), started from an allowed client's login session, no
// relay. The checks run in this order; the first failure is the refusal. It
// never falls back to the session shape. With a fingerprint reader and a
// finger enrolled for the console account it is level 2 (every approval
// also takes a finger); without one it is level 1 (typed approvals, the
// boundary line in red); a reader that errs otherwise refuses.
func (iso *isolation) desktopShape(io IO, env isolationEnv, name string) (*isolation, error) {
	sys := iso.sys
	if iso.display.Kind != sysconf.DisplayWayland || env.displaySet() {
		detail := iso.display.Detail
		if detail == "" {
			detail = iso.display.Kind
		}
		return nil, errors.New("console: desktop mode needs a Wayland socket and no DISPLAY (" + detail + ")")
	}
	if owner, ok := env.terminalOwner(); !ok || owner != iso.self {
		return nil, fmt.Errorf("console: desktop mode: the terminal must belong to %q", name)
	}
	if lu, ok := env.loginUID(); !ok || !env.clientAllowed(sys, lu) {
		return nil, errors.New("console: desktop mode: started outside an allowed desktop session")
	}
	chain, err := env.parentChain()
	if err != nil {
		return nil, fmt.Errorf("console: desktop mode: cannot read the parent processes: %v", err)
	}
	if !hasEmulator(chain, iso.self) {
		return nil, fmt.Errorf("console: desktop mode: no terminal emulator of %q above this process", name)
	}
	agentSide := func(uid int) bool { return !env.accountExists(uid) || env.clientAllowed(sys, uid) }
	if err := checkRelay(io, env, sys, agentSide); err != nil {
		return nil, err
	}
	gid, err := env.clientGID(sys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (run locksql install)", ErrConfig, err)
	}
	iso.gid, iso.desktop = gid, true
	iso.allowed = func(uid int) bool { return env.clientAllowed(sys, uid) }
	v, why, err := openReader(env, sys.ServiceUser)
	if err != nil {
		return nil, err
	}
	if v == nil {
		iso.verifier = nil
		io.Println(red + "desktop mode, level 1: boundary: your desktop — the agent can read this window and type into it" + reset)
		io.Println(red + "no fingerprint: " + why + reset)
		return iso, nil
	}
	iso.verifier = v
	io.Println("desktop mode, level 2: approvals by fingerprint (fprintd), boundary: your desktop session")
	return iso, nil
}

// openReader opens the fingerprint reader of the console account. A reader
// that is absent, not answering or without an enrolled finger gives a nil
// verifier and the reason (level 1); any other error, a fprintd of the
// wrong account included, is a refusal. A verifier it does not return is
// closed.
func openReader(env isolationEnv, account string) (fingerprint.Verifier, string, error) {
	refusal := func(err error) error {
		return fmt.Errorf("console: desktop mode: fingerprint reader refused: %v", err)
	}
	v, err := env.newVerifier(account)
	if err != nil {
		if errors.Is(err, fingerprint.ErrUnavailable) && !errors.Is(err, fingerprint.ErrWrongOwner) {
			return nil, "no reader", nil
		}
		return nil, "", refusal(err)
	}
	ectx, cancel := context.WithTimeout(context.Background(), enrolledTimeout)
	n, err := v.Enrolled(ectx)
	cancel()
	if err == nil && n <= 0 {
		err = fingerprint.ErrNotEnrolled
	}
	if err == nil {
		return v, "", nil
	}
	closeVerifier(v)
	switch {
	case errors.Is(err, fingerprint.ErrNotEnrolled):
		return nil, "no fingerprint enrolled for " + account + ": run sudo locksql enroll", nil
	case errors.Is(err, fingerprint.ErrUnavailable), errors.Is(err, fingerprint.ErrTimeout),
		errors.Is(err, context.DeadlineExceeded):
		if errors.Is(err, fingerprint.ErrWrongOwner) {
			return nil, "", refusal(err)
		}
		return nil, "no reader", nil
	}
	return nil, "", refusal(err)
}

// Level is the security level of the isolation: 2 for the desktop shape
// with a fingerprint reader, 1 for the desktop shape without, 0 for the
// session shape (the kernel is the boundary).
func (iso *isolation) Level() int {
	switch {
	case !iso.desktop:
		return 0
	case iso.verifier != nil:
		return 2
	}
	return 1
}

// boundary names where the approval screen stands, for the status screen.
func (iso *isolation) boundary() string {
	switch iso.Level() {
	case 2:
		return "your desktop session; approvals take a fingerprint"
	case 1:
		return "your desktop: the agent can read this window and type into it"
	}
	return ""
}

// enrolledTimeout bounds the start-up question to fprintd; past it, the
// reader counts as unavailable.
var enrolledTimeout = 10 * time.Second

// closeVerifier releases a verifier that holds a connection (fprintd's).
func closeVerifier(v fingerprint.Verifier) {
	if c, ok := v.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// hasEmulator reports whether chain holds one of the desktop terminal
// emulators running as uid.
func hasEmulator(chain []sysconf.Proc, uid int) bool {
	for _, p := range chain {
		if p.UID != uid {
			continue
		}
		for _, e := range sysconf.DesktopEmulators {
			// The kernel truncates comm to 15 bytes (TASK_COMM_LEN - 1).
			if p.Comm == e || len(e) > sysconf.CommLen && p.Comm == e[:sysconf.CommLen] {
				return true
			}
		}
	}
	return false
}

// checkRelay refuses a session of the console account that relays the
// terminal of an account on the agent's side. loginuid and the terminal
// owner name the console account there, so checkIsolation alone accepts
// it. A machinectl shell is accepted only when every running `machinectl
// shell` belongs to an account out of the agent's reach; an SSH login from
// this machine is refused, since its client cannot be identified.
func checkRelay(io IO, env isolationEnv, sys *sysconf.Config, agentSide func(uid int) bool) error {
	switch env.relay() {
	case sysconf.RelayMachinectl:
		uids, ok := env.machinectlUIDs()
		if !ok || len(uids) == 0 {
			return fmt.Errorf("console: refused: this session is a machinectl shell and the console cannot tell which account opened it; log in as %q in a session of its own", sys.ServiceUser)
		}
		for _, uid := range uids {
			if agentSide(uid) {
				return fmt.Errorf("console: refused: this machinectl shell may relay the terminal of uid %d, which may reach the console: that account could read it and type into it; log in as %q in a session of its own",
					uid, sys.ServiceUser)
			}
		}
		io.Println("started from a machinectl shell of an account outside the client group")
	case sysconf.RelaySSHLoopback:
		return fmt.Errorf("console: refused: this session is an ssh from this machine, which relays the terminal of an account the console cannot identify; log in as %q in a session of its own (or ssh from another machine)", sys.ServiceUser)
	}
	return nil
}

// socketPath is the socket of a project and profile.
func (iso *isolation) socketPath(projectKey, profile string) (string, error) {
	if iso.sys != nil {
		return ipc.SharedSocketPath(iso.sys.SocketDir, projectKey, profile)
	}
	return ipc.SocketPath(projectKey, profile)
}

// listen opens the socket.
func (iso *isolation) listen(path string) (net.Listener, error) {
	if iso.sys != nil {
		return ipc.ListenShared(path, iso.gid)
	}
	return ipc.Listen(path)
}

// peerCheck decides which peers are served: the console's own account and,
// in a separated setup, allowed_uids and the client group. The group is
// looked up at every connection: a uid removed from it loses access at its
// next connection, not at the next console start.
func (iso *isolation) peerCheck() func(ipc.Cred) bool {
	if iso.sys == nil {
		return nil // the default: the console's own uid
	}
	return func(c ipc.Cred) bool {
		return c.UID == iso.self || iso.allowed(c.UID)
	}
}

// peerKey carries the requesting client's credentials in a request context.
type peerKey struct{}

func withPeer(ctx context.Context, c ipc.Cred) context.Context {
	return context.WithValue(ctx, peerKey{}, c)
}

// withPeerRecord stamps rec with the client behind the request in ctx: its
// uid, pid and account name. The process name, chosen by the agent, stays on
// the screen (peerText) and out of the audit log.
func withPeerRecord(ctx context.Context, rec audit.Record) audit.Record {
	c, ok := ctx.Value(peerKey{}).(ipc.Cred)
	if !ok || c.UID < 0 {
		return rec
	}
	uid := c.UID
	rec.PeerUID = &uid
	if c.PID > 0 {
		rec.PeerPID = c.PID
	}
	if u, err := user.LookupId(strconv.Itoa(c.UID)); err == nil {
		rec.PeerUser = u.Username
	}
	return rec
}

// peerText describes the client behind a request for the approval screen.
func peerText(ctx context.Context) string {
	c, ok := ctx.Value(peerKey{}).(ipc.Cred)
	if !ok || c.UID < 0 {
		return ""
	}
	who := "uid " + strconv.Itoa(c.UID)
	if u, err := user.LookupId(strconv.Itoa(c.UID)); err == nil {
		who += " (" + u.Username + ")"
	}
	if c.PID > 0 {
		who += " · pid " + strconv.Itoa(c.PID)
		if p := processText(c.PID); p != "" {
			who += " · " + p
		}
	}
	return who
}

// processText names the process behind pid on Linux: its executable path
// when the kernel lets the console read it (a process of its own account),
// else the name the process gave itself, labelled as such; "" elsewhere.
// The uid and pid are the kernel's; the name is the process's choice.
func processText(pid int) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	dir := "/proc/" + strconv.Itoa(pid)
	if exe, err := os.Readlink(dir + "/exe"); err == nil && exe != "" {
		return "exe " + exe
	}
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return "process " + strconv.Quote(name) + " (self-reported name)"
		}
	}
	return ""
}
