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
	"sync"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// isolation is how the console is kept apart from the agent: in a
// separated setup (sysconf) the console runs as the service account in its
// own login session and serves the client group over a shared socket; in
// same-user mode it serves its own user over a private socket.
type isolation struct {
	sys     *sysconf.Config
	display sysconf.Display
	self    int
	gid     int
	allowed func(uid int) bool
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
	tiocsti       func() (bool, bool)
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
		tiocsti:       sysconf.LegacyTIOCSTI,
	}
}

// checkIsolation applies the separation rules before the console holds any
// secret. Warnings go to the terminal; a violation is an error.
func checkIsolation(io IO, env isolationEnv, p config.Profile) (*isolation, error) {
	sys, err := env.loadSys()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	iso := &isolation{sys: sys, display: env.display(), self: env.uid(), gid: -1}

	if iso.display.Kind == sysconf.DisplayX11 {
		msg := "the console runs in an X11 session (" + iso.display.Detail + "): any X client, the agent's included, can read its keyboard and screen and send it keystrokes"
		if p.Production || sys != nil && sys.X11 == sysconf.X11Refuse {
			return nil, errors.New("console: refused: " + msg + "; run it in a Wayland session or on a text console")
		}
		io.Println(red + "warning: " + msg + "; prefer a Wayland session" + reset)
	}

	if sys == nil {
		io.Println(red + "same-user mode: the agent runs as your account, so it could read this console's terminal or type into it; run `locksql doctor`, then `sudo locksql install` to separate them" + reset)
		if on, known := env.tiocsti(); known && on {
			io.Println(red + "warning: the kernel allows TIOCSTI (dev.tty.legacy_tiocsti = 1): a process of your account can type into this terminal" + reset)
		}
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
	if lu, ok := env.loginUID(); ok && lu >= 0 && lu != iso.self {
		return nil, fmt.Errorf("console: started from the login session of uid %d (sudo or su): that account shares this terminal and display; log in as %q in a session of its own",
			lu, sys.ServiceUser)
	}
	if owner, ok := env.terminalOwner(); ok && owner != iso.self {
		return nil, fmt.Errorf("console: the terminal belongs to uid %d, not to %q: its owner can read it and type into it; open a terminal in %q's own session",
			owner, sys.ServiceUser, sys.ServiceUser)
	}
	gid, err := env.clientGID(sys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (run locksql install)", ErrConfig, err)
	}
	iso.gid = gid
	iso.allowed = func(uid int) bool { return env.clientAllowed(sys, uid) }
	io.Println(fmt.Sprintf("separated mode: console account %s, clients of group %s, display %s", name, sys.ClientGroup, iso.display.Kind))
	return iso, nil
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
// in a separated setup, the client group. The answer per uid is cached for
// the session.
func (iso *isolation) peerCheck() func(ipc.Cred) bool {
	if iso.sys == nil {
		return nil // the default: the console's own uid
	}
	var mu sync.Mutex
	cache := map[int]bool{}
	return func(c ipc.Cred) bool {
		if c.UID == iso.self {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		ok, seen := cache[c.UID]
		if !seen {
			ok = iso.allowed(c.UID)
			cache[c.UID] = ok
		}
		return ok
	}
}

// peerKey carries the requesting client's credentials in a request context.
type peerKey struct{}

func withPeer(ctx context.Context, c ipc.Cred) context.Context {
	return context.WithValue(ctx, peerKey{}, c)
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
		if runtime.GOOS == "linux" {
			if b, err := os.ReadFile("/proc/" + strconv.Itoa(c.PID) + "/comm"); err == nil {
				who += " (" + strings.TrimSpace(string(b)) + ")"
			}
		}
	}
	return who
}
