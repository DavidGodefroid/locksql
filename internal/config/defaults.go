package config

import (
	"strings"
	"time"
)

// Supported engines.
const (
	EngineMariaDB  = "mariadb"
	EngineMySQL    = "mysql"
	EnginePostgres = "postgres"
	EngineSQLite   = "sqlite"
)

// Credentials modes.
const (
	CredentialsAsk      = "ask"
	CredentialsKeychain = "keychain"
)

// defaultPorts holds the port used when a network profile leaves port unset.
var defaultPorts = map[string]int{
	EngineMariaDB:  3306,
	EngineMySQL:    3306,
	EnginePostgres: 5432,
}

// DefaultPort is the port of engine when a profile leaves port unset, 0
// for an engine without one (sqlite).
func DefaultPort(engine string) int { return defaultPorts[engine] }

// DefaultSSHPort is the port of an ssh table that leaves port unset.
const DefaultSSHPort = 22

// knownDetectors lists the value detectors a profile may enable.
var knownDetectors = map[string]bool{
	"email": true, "phone": true, "iban": true, "card": true,
	"be_niss": true, "fr_nir": true, "nl_bsn": true, "us_ssn": true,
}

// DefaultDetectors is the detector set used when a profile does not set
// detectors. National id detectors are opt-in.
func DefaultDetectors() []string {
	return []string{"email", "phone", "iban", "card"}
}

// DefaultLimits returns the limits applied to unset (zero) limit fields.
func DefaultLimits(production bool) Limits {
	if production {
		return Limits{
			StatementTimeout:  10 * time.Second,
			ExplainRowsWarn:   20_000,
			ExplainRowsRefuse: 200_000,
			MaxRows:           200,
			MaxCellChars:      200,
			MaxOutputBytes:    65_536,
			KAnonymity:        10,
			ReferenceProbe:    5,
		}
	}
	return Limits{
		StatementTimeout:  30 * time.Second,
		ExplainRowsWarn:   100_000,
		ExplainRowsRefuse: 1_000_000,
		MaxRows:           200,
		MaxCellChars:      200,
		MaxOutputBytes:    65_536,
		KAnonymity:        5,
		ReferenceProbe:    5,
	}
}

// applyDefaults replaces zero values of p with the defaults.
// detectorsSet reports whether the detectors key was present in the file;
// an explicit empty list is kept.
func applyDefaults(p *Profile, detectorsSet bool) {
	if p.Credentials == "" {
		p.Credentials = CredentialsAsk
	}
	if p.TLS == "" && p.Engine != EngineSQLite {
		p.TLS = TLSVerifyFull
		if strings.HasPrefix(p.Host, "/") || IsLoopback(p.Host) {
			p.TLS = TLSPrefer
		}
	}
	if p.Port == 0 {
		p.Port = defaultPorts[p.Engine]
	}
	if !detectorsSet {
		p.Detectors = DefaultDetectors()
	}
	if p.Detectors == nil {
		p.Detectors = []string{}
	}
	d := DefaultLimits(p.Production)
	l := &p.Limits
	if l.StatementTimeout == 0 {
		l.StatementTimeout = d.StatementTimeout
	}
	if l.ExplainRowsRefuse == 0 {
		l.ExplainRowsRefuse = d.ExplainRowsRefuse
	}
	if l.ExplainRowsWarn == 0 {
		// A defaulted warn threshold never exceeds an explicit refuse one.
		l.ExplainRowsWarn = min(d.ExplainRowsWarn, l.ExplainRowsRefuse)
	}
	if l.MaxRows == 0 {
		l.MaxRows = d.MaxRows
	}
	if l.MaxCellChars == 0 {
		l.MaxCellChars = d.MaxCellChars
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = d.MaxOutputBytes
	}
	if l.KAnonymity == 0 {
		l.KAnonymity = d.KAnonymity
	}
	if l.ReferenceProbe == 0 {
		l.ReferenceProbe = d.ReferenceProbe
	}
}
