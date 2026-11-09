package client

import (
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locksql/internal/product"
)

// Locks are the locksql locks a client of the project of a directory
// reaches, and which of them serves each profile.
//
// lea mounts each lock of the agent's workspace on <shared socket
// dir>/<instance> and lists their names in LEA_LOCKSQL_INSTANCES. With one
// lock, or one chosen by --instance or LOCKSQL_INSTANCE, every profile is
// dialled on that lock. With several and none chosen, a profile is dialled
// on the lock whose directory holds its console socket: profile names are
// unique in a workspace, so one server or command reaches them all.
//
// Nothing here is locksql-specific beyond product.P: it is the shape a
// lockkit client.Locks would take for every lock type.
type Locks struct {
	cwd string
	// chosen is the instance every profile is dialled on when route is
	// empty ("" for the socket directory itself).
	chosen string
	// route lists the instances a profile is looked up in: several were
	// mounted and none was chosen.
	route []string
	// listed are the instances lea mounted (LEA_LOCKSQL_INSTANCES), empty
	// when it mounted none or one on the socket directory itself.
	listed []string
}

// ResolveLocks resolves the locks of the project of cwd reached with
// flagValue (the --instance flag): ResolveInstance, except that several
// mounted locks and none chosen is not an error but routing by profile.
// Every name is checked before any path is built; errors never echo one.
func ResolveLocks(cwd, flagValue string) (Locks, error) {
	listed := strings.Fields(os.Getenv(instancesEnv))
	if flagValue == "" && os.Getenv(product.P.Env("INSTANCE")) == "" && len(listed) > 1 {
		for _, n := range listed {
			// Checks the list and n against lox's rule for instance names.
			if _, err := ResolveInstance(n); err != nil {
				return Locks{}, err
			}
		}
		return Locks{cwd: cwd, route: listed, listed: listed}, nil
	}
	chosen, err := ResolveInstance(flagValue)
	if err != nil {
		return Locks{}, err
	}
	return Locks{cwd: cwd, chosen: chosen, listed: listed}, nil
}

// instancesEnv is the variable in which lea lists the locks it mounted.
var instancesEnv = "LEA_" + product.P.Env("INSTANCES")

// Instance is the instance that serves profile. When routing, it is the one
// whose directory holds the profile's console socket; a *NoConsoleError when
// none does, and an error naming the instances when several do.
func (l Locks) Instance(profile string) (string, error) {
	if len(l.route) == 0 {
		return l.chosen, nil
	}
	hits := l.holding(profile, l.route)
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		root, _ := kconfig.FindProjectRoot(product.P, l.cwd)
		return "", &NoConsoleError{Product: product.P, Profile: profile, Project: root, Err: fs.ErrNotExist}
	}
	return "", fmt.Errorf("a %s console for profile %s runs in several locks: %s; pass --%s NAME (or set %s)",
		product.P.Name, profile, strings.Join(hits, " "), FlagInstance, product.P.Env("INSTANCE"))
}

// Serves reports whether profile belongs on these locks. It is false only
// when one lock is chosen among those lea mounted and the profile's console
// socket is in another of them: that profile is another lock's, and a
// server bound to this one neither reports it nor counts it.
func (l Locks) Serves(profile string) bool {
	if len(l.route) > 0 || len(l.listed) < 2 {
		return true
	}
	if len(l.holding(profile, []string{l.chosen})) > 0 {
		return true
	}
	others := slices.DeleteFunc(slices.Clone(l.listed), func(n string) bool { return n == l.chosen })
	return len(l.holding(profile, others)) == 0
}

// Filter keeps the profiles of names these locks serve (Serves).
func (l Locks) Filter(names []string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool { return !l.Serves(n) })
}

// Dial is DialInstance on the instance that serves profile.
func (l Locks) Dial(profile string) (*Client, error) {
	instance, err := l.Instance(profile)
	if err != nil {
		return nil, err
	}
	return DialInstance(l.cwd, profile, instance)
}

// holding returns the instances of names whose directory holds the console
// socket of profile.
func (l Locks) holding(profile string, names []string) []string {
	var hits []string
	for _, n := range names {
		path, err := SocketPathInstance(l.cwd, profile, n)
		if err != nil {
			continue
		}
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			hits = append(hits, n)
		}
	}
	return hits
}
