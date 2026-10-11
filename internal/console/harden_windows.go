package console

import "errors"

// harden cannot disable core dumps on Windows: a production profile is
// refused, as on a failed harden() elsewhere.
func harden() error {
	return errors.New("process hardening is not supported on Windows")
}
