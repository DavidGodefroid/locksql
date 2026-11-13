//go:build lockfamily_managed_test

package main

import (
	"os"

	"github.com/DavidGodefroid/lockkit/managed"
)

// A binary built with the lockfamily_managed_test tag (the integration
// tests) reads the managed file at LOCKSQL_TEST_MANAGED, without the
// ownership check. A release build has no such tag: it always reads the
// machine's managed file.
func init() {
	if p := os.Getenv("LOCKSQL_TEST_MANAGED"); p != "" {
		managed.SetTestPath(p)
	}
}
