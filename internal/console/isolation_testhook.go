//go:build locksql_testhook

package console

// This file is only compiled with the locksql_testhook build tag, which the
// integration tests use to run a same-user console in a pseudo-terminal.
// Release builds never carry the tag: there, nothing (config file, flag,
// environment variable or client) lets the console run in the agent's
// account.
func init() { allowSameUserForTests = true }
