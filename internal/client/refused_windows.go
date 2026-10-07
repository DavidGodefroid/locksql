package client

import (
	"errors"
	"syscall"
)

// wsaECONNREFUSED is the Winsock "connection refused" error: a socket file
// left by a console that died.
const wsaECONNREFUSED syscall.Errno = 10061

func refusedOS(err error) bool { return errors.Is(err, wsaECONNREFUSED) }
