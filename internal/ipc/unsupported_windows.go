package ipc

import "errors"

// ErrUnsupported is returned on a platform where the console's socket and
// its peer checks do not exist (Windows): locksql runs there inside WSL2.
var ErrUnsupported = errors.New("not supported on Windows: run locksql inside WSL2 (see docs/usage.md, Windows)")
