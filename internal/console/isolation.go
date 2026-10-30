package console

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// The isolation checks are lockkit's (console.CheckIsolation); this file
// gives them locksql's product, environment and names.

// isolation is how the console is kept apart from the agent: see
// kconsole.Isolation.
type isolation struct {
	sys     *sysconf.Config
	display sysconf.Display
	self    int
	gid     int
	// desktop is the desktop shape; verifier is then its fingerprint
	// reader (nil at level 1 and in the session shape).
	desktop  bool
	verifier fingerprint.Verifier

	k *kconsole.Isolation
}

// isolationEnv holds what checkIsolation reads from the system; tests
// replace it.
type isolationEnv struct {
	loadSys        func() (*sysconf.Config, error)
	display        func() sysconf.Display
	uid            func() int
	userName       func() (string, error)
	loginUID       func() (int, bool)
	terminalOwner  func() (int, bool)
	clientAllowed  func(sys *sysconf.Config, uid int) bool
	clientGID      func(sys *sysconf.Config) (int, error)
	accountExists  func(uid int) bool
	relay          func() string
	machinectlUIDs func() ([]int, bool)
	// desktopEnv reports LOCKSQL_DESKTOP=1: the desktop shape is asked for.
	desktopEnv  func() bool
	displaySet  func() bool
	parentChain func() ([]sysconf.Proc, error)
	newVerifier func(user string) (fingerprint.Verifier, error)
}

func realIsolationEnv(tty *os.File) isolationEnv {
	k := kconsole.RealIsolationEnv(product.P, tty)
	return isolationEnv{
		loadSys: k.LoadSys, display: k.Display, uid: k.UID, userName: k.UserName, loginUID: k.LoginUID,
		terminalOwner: k.TerminalOwner, clientAllowed: k.ClientAllowed, clientGID: k.ClientGID,
		accountExists: k.AccountExists, relay: k.Relay, machinectlUIDs: k.MachinectlUIDs,
		desktopEnv: k.DesktopEnv, displaySet: k.DisplaySet, parentChain: k.ParentChain, newVerifier: k.NewVerifier,
	}
}

func (e isolationEnv) kit() kconsole.IsolationEnv {
	return kconsole.IsolationEnv{
		LoadSys: e.loadSys, Display: e.display, UID: e.uid, UserName: e.userName, LoginUID: e.loginUID,
		TerminalOwner: e.terminalOwner, ClientAllowed: e.clientAllowed, ClientGID: e.clientGID,
		AccountExists: e.accountExists, Relay: e.relay, MachinectlUIDs: e.machinectlUIDs,
		DesktopEnv: e.desktopEnv, DisplaySet: e.displaySet, ParentChain: e.parentChain, NewVerifier: e.newVerifier,
		EnrolledTimeout: enrolledTimeout, AllowSameUser: allowSameUserForTests,
	}
}

// allowUIDs returns env whose separated setup also lets uids connect, as
// allowed_uids in the image's system.toml does (console --allowed-uids):
// every check that reads the setup sees them (the peers served, and the
// accounts whose session or terminal the console refuses). The setup read
// is not changed in place. Without a separated setup it refuses.
func allowUIDs(env isolationEnv, uids []int) isolationEnv {
	if len(uids) == 0 {
		return env
	}
	load := env.loadSys
	env.loadSys = func() (*sysconf.Config, error) {
		sys, err := load()
		if err != nil {
			return nil, err
		}
		if sys == nil {
			return nil, errors.New("--allowed-uids needs the separated setup (" + product.SysconfPath() + ", as in the image)")
		}
		return WithAllowedUIDs(sys, uids), nil
	}
	return env
}

// WithAllowedUIDs returns a copy of sys whose allowed_uids also hold uids;
// sys is not changed.
func WithAllowedUIDs(sys *sysconf.Config, uids []int) *sysconf.Config {
	if sys == nil || len(uids) == 0 {
		return sys
	}
	c := *sys
	c.AllowedUIDs = slices.Clone(sys.AllowedUIDs)
	for _, u := range uids {
		if !slices.Contains(c.AllowedUIDs, u) {
			c.AllowedUIDs = append(c.AllowedUIDs, u)
		}
	}
	return &c
}

// uidList prints uids as --allowed-uids takes them.
func uidList(uids []int) string {
	s := make([]string, len(uids))
	for i, u := range uids {
		s[i] = strconv.Itoa(u)
	}
	return strings.Join(s, ",")
}

// allowSameUserForTests lets the console run without a separated setup, in
// the agent's account. Only isolation_testhook.go sets it, in a build with
// the locksql_testhook tag: no config file, flag, environment variable or
// client can.
var allowSameUserForTests bool

// sameUserRefusal is the one text of the same-user refusal.
var sameUserRefusal = kconsole.SameUserRefusal(product.P)

// SameUserRefused is the refusal of a console without a separated setup
// (sys nil, as sysconf.Load returns it), or nil.
func SameUserRefused(sys *sysconf.Config) error {
	return kconsole.SameUserRefused(product.P, sys, allowSameUserForTests)
}

// checkIsolation applies the separation rules before any prompt and before
// the console writes any state (lockkit's CheckIsolation).
func checkIsolation(io IO, env isolationEnv) (*isolation, error) {
	k, err := kconsole.CheckIsolation(product.P, io, env.kit())
	if err != nil {
		return nil, err
	}
	return &isolation{sys: k.Sys, display: k.Display, self: k.Self, gid: k.GID, desktop: k.Desktop, verifier: k.Verifier, k: k}, nil
}

// refuseX11IfProduction applies the production rule once the profile is
// known: a production profile never runs in an X11 session.
func (iso *isolation) refuseX11IfProduction(p config.Profile) error {
	return iso.k.RefuseX11IfProduction(p.Production)
}

// Level is the security level of the isolation.
func (iso *isolation) Level() int { return iso.k.Level() }

// boundary names where the approval screen stands, for the status screen.
func (iso *isolation) boundary() string { return iso.k.Boundary() }

// enrolledTimeout bounds the start-up question to fprintd; past it, the
// reader counts as unavailable.
var enrolledTimeout = 10 * time.Second

// closeVerifier releases a verifier that holds a connection (fprintd's).
func closeVerifier(v fingerprint.Verifier) { kconsole.CloseVerifier(v) }

// socketPath is the socket of a project and profile.
func (iso *isolation) socketPath(projectKey, profile string) (string, error) {
	return iso.k.SocketPath(projectKey, profile)
}

// listen opens the socket.
func (iso *isolation) listen(path string) (net.Listener, error) { return iso.k.Listen(path) }

// peerCheck decides which peers are served (lockkit's PeerCheck).
func (iso *isolation) peerCheck() func(ipc.Cred) bool { return iso.k.PeerCheck() }

func withPeer(ctx context.Context, c ipc.Cred) context.Context { return kconsole.WithPeer(ctx, c) }

// withPeerRecord stamps rec with the client behind the request in ctx: its
// uid, pid and account name. The process name, chosen by the agent, stays on
// the screen (peerText) and out of the audit log.
func withPeerRecord(ctx context.Context, rec audit.Record) audit.Record {
	c, ok := kconsole.PeerFrom(ctx)
	if !ok {
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
func peerText(ctx context.Context) string { return kconsole.PeerText(ctx) }

// processText names the process behind pid on Linux.
func processText(pid int) string { return kconsole.ProcessText(pid) }
