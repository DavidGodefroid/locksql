// Package product is locksql's identity on lockkit: its names, accounts,
// directories and keychain service.
package product

import (
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// P is locksql. main sets P.Version at start.
var P = kit.Product{
	Name:            "locksql",
	Tagline:         "Your AI writes the query. You hold the key.",
	Account:         "locksql",
	ClientsGroup:    "locksql-clients",
	KeychainService: "locksql",
	EnvPrefix:       "LOCKSQL_",
}

// Keychain is locksql's OS keychain.
var Keychain = secrets.NewKeychain(P.KeychainService)

// LoadSys reads locksql's system setup (sysconf.Load for P).
func LoadSys() (*sysconf.Config, error) { return sysconf.Load(P) }

// SysconfPath is locksql's system setup file.
func SysconfPath() string { return sysconf.File(P) }
