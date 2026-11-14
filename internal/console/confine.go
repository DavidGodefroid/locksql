package console

import (
	"fmt"
	"slices"

	"github.com/DavidGodefroid/lockkit/confine"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// The confined agent check (lockkit#133) is lockkit's server's: it refuses
// an agent that does not run confined unless the policy in force sets
// unconfined = true. Run, which does not use lockkit's console.Run, adds
// what that one does at start: a production profile with unconfined is
// refused, and the runtime gids of --runtime-gids and of this machine are
// given to the server.

// refuseUnconfinedProduction refuses a production profile that sets
// unconfined = true.
func refuseUnconfinedProduction(p config.Profile) error {
	if p.Unconfined && p.Production {
		return fmt.Errorf("%w: unconfined is never allowed on a production profile", ErrConfig)
	}
	return nil
}

// hostRuntimeGIDs are this machine's runtime gids; tests replace it, a CI
// runner being in the docker group.
var hostRuntimeGIDs = confine.RuntimeGIDs

// runtimeGIDs are the gids given (--runtime-gids) and those of this
// machine's runtime sockets.
func runtimeGIDs(given []int) []int {
	out := slices.Clone(given)
	for _, g := range hostRuntimeGIDs() {
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}
