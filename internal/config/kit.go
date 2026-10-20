package config

import (
	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// The profile base, TLS, SSH and diff helpers come from lockkit's config
// package, under their locksql names.

// TLS modes of a network profile, as libpq's sslmode, in increasing
// strength.
const (
	TLSDisable    = kconfig.TLSDisable
	TLSPrefer     = kconfig.TLSPrefer
	TLSRequire    = kconfig.TLSRequire
	TLSVerifyCA   = kconfig.TLSVerifyCA
	TLSVerifyFull = kconfig.TLSVerifyFull
)

// Credentials modes. CredentialsVault reads the user and password from
// HashiCorp Vault with the vault CLI at every connection (Profile.VaultPath).
const (
	CredentialsAsk      = kconfig.CredentialsAsk
	CredentialsKeychain = kconfig.CredentialsKeychain
	CredentialsVault    = kconfig.CredentialsVault
)

// DefaultSSHPort is the port of an ssh table that leaves port unset.
const DefaultSSHPort = kconfig.DefaultSSHPort

// SSH authentication methods.
const (
	SSHAuthKey      = kconfig.SSHAuthKey
	SSHAuthAgent    = kconfig.SSHAuthAgent
	SSHAuthPassword = kconfig.SSHAuthPassword
)

// SSHProfile is the bastion a network profile is reached through.
type SSHProfile = kconfig.SSHProfile

type rawSSH = kconfig.RawSSH

// Change is one difference between two policies.
type Change = kconfig.Change

// TLSRank orders TLS modes by strength ("" is prefer, unknown is -1).
func TLSRank(mode string) int { return kconfig.TLSRank(mode) }

// TLSVerifiesChain reports a tls mode that verifies the server's
// certificate chain: verify-ca and verify-full, and require with tls_ca.
func TLSVerifiesChain(mode, ca string) bool { return kconfig.TLSVerifiesChain(mode, ca) }

// IsLoopback reports "localhost" or a loopback IP literal.
func IsLoopback(host string) bool { return kconfig.IsLoopback(host) }

// SSHString shows a bastion in a policy change.
func SSHString(s *SSHProfile) string { return kconfig.SSHString(s) }
