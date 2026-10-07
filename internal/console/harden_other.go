//go:build !unix

package console

// harden has nothing to do here: Windows writes no core dumps by default.
func harden() error { return nil }
