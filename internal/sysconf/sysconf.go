// Package sysconf reads the machine-wide locksql setup that separates the
// console from the agent: the console runs as a dedicated account
// (locksql, used in its own login session) that alone holds the database
// credentials, and the agent's account reaches it through a socket that a
// group grants access to. The kernel enforces the boundary.
//
// The file is written by `locksql install` and must be owned by root and
// writable by root only: an agent that could edit it could point clients
// at a console of its own or widen the socket's access.
package sysconf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"

	"github.com/BurntSushi/toml"
)

// Path is the system configuration file. Tests may point it elsewhere.
var Path = "/etc/locksql/system.toml"

// SkipOwnerCheck disables the root-ownership check (tests only).
var SkipOwnerCheck = false

// Defaults written by locksql install.
const (
	DefaultServiceUser = "locksql"
	DefaultClientGroup = "locksql-clients"
)

// DefaultSocketDir is where shared sockets live.
func DefaultSocketDir() string {
	if runtime.GOOS == "darwin" {
		return "/usr/local/var/run/locksql"
	}
	return "/run/locksql"
}

// X11 policies.
const (
	X11Warn   = "warn"
	X11Refuse = "refuse"
)

// Config is the system setup.
type Config struct {
	// ServiceUser is the account the console runs as.
	ServiceUser string `toml:"service_user"`
	// ClientGroup's members may connect to the console sockets.
	ClientGroup string `toml:"client_group"`
	// SocketDir holds the sockets: owned by ServiceUser, group
	// ClientGroup, mode 0710 or 0750.
	SocketDir string `toml:"socket_dir"`
	// AllowedUIDs may connect besides the group's members.
	AllowedUIDs []int `toml:"allowed_uids"`
	// X11 is what the console does in an X11 session, where any client can
	// read the keyboard and the screen of the others: "warn" (the default)
	// or "refuse". Production profiles always refuse.
	X11 string `toml:"x11"`
}

// Load reads the system configuration. It returns nil and no error when
// the file does not exist (same-user mode).
func Load() (*Config, error) {
	fi, err := os.Lstat(Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sysconf: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("sysconf: %s is not a regular file", Path)
	}
	if err := checkRootOwned(Path, fi); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(Path)
	if err != nil {
		return nil, fmt.Errorf("sysconf: %w", err)
	}
	var c Config
	md, err := toml.Decode(string(raw), &c)
	if err != nil {
		return nil, fmt.Errorf("sysconf: %s: %w", Path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("sysconf: %s: unknown key %q", Path, und[0].String())
	}
	if c.ServiceUser == "" {
		c.ServiceUser = DefaultServiceUser
	}
	if c.ClientGroup == "" {
		c.ClientGroup = DefaultClientGroup
	}
	if c.SocketDir == "" {
		c.SocketDir = DefaultSocketDir()
	}
	if !filepath.IsAbs(c.SocketDir) {
		return nil, fmt.Errorf("sysconf: %s: socket_dir must be absolute", Path)
	}
	switch c.X11 {
	case "":
		c.X11 = X11Warn
	case X11Warn, X11Refuse:
	default:
		return nil, fmt.Errorf("sysconf: %s: x11 must be %q or %q", Path, X11Warn, X11Refuse)
	}
	return &c, nil
}

// ServiceUID returns the uid of the service account.
func (c *Config) ServiceUID() (int, error) {
	u, err := user.Lookup(c.ServiceUser)
	if err != nil {
		return -1, fmt.Errorf("sysconf: service user %q: %w", c.ServiceUser, err)
	}
	return strconv.Atoi(u.Uid)
}

// ClientGID returns the gid of the client group.
func (c *Config) ClientGID() (int, error) {
	g, err := user.LookupGroup(c.ClientGroup)
	if err != nil {
		return -1, fmt.Errorf("sysconf: client group %q: %w", c.ClientGroup, err)
	}
	return strconv.Atoi(g.Gid)
}

// ClientAllowed reports whether uid may connect: listed in AllowedUIDs or
// a member of the client group.
func (c *Config) ClientAllowed(uid int) bool {
	if slices.Contains(c.AllowedUIDs, uid) {
		return true
	}
	return InGroup(uid, c.ClientGroup)
}

// InGroup reports whether the account uid belongs to group (as its primary
// group or a supplementary one).
func InGroup(uid int, group string) bool {
	g, err := user.LookupGroup(group)
	if err != nil {
		return false
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false
	}
	if u.Gid == g.Gid {
		return true
	}
	ids, err := u.GroupIds()
	return err == nil && slices.Contains(ids, g.Gid)
}
