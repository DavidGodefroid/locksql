//go:build !linux && !darwin

package main

// locksql builds for Linux and macOS only: the console's separation from
// the agent relies on their accounts, sockets and terminals.
var _ = locksqlBuildsForLinuxAndMacOSOnly
