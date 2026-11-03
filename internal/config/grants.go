package config

import (
	"errors"
	"strconv"
	"time"
)

// Grant limits: the most a grant may ask for (#171). A grant is one human
// decision covering a bounded read scope: a database, tables, a duration
// and a read budget. The limits are profile limits; a request above them
// is clamped to them, never refused.
const (
	DefaultGrantMaxDuration   = time.Hour
	DefaultGrantMaxStatements = 200
	DefaultGrantMaxRows       = 10_000
	DefaultGrantMaxBytes      = 1 << 20 // 1 MiB
	// MaxGrantDuration bounds limits.grant_max_duration: a grant never
	// outlives the longest session anyway.
	MaxGrantDuration = MaxMaxSession
)

// GrantLimits are the effective grant limits of a profile.
type GrantLimits struct {
	Duration   time.Duration
	Statements int64
	Rows       int64
	Bytes      int64
}

// Grants returns the effective grant limits of l (an unset limit is its
// default) and whether grants are enabled: limits.grant_max_duration = 0
// disables them.
func (l Limits) Grants() (GrantLimits, bool) {
	g := GrantLimits{Duration: l.GrantMaxDuration, Statements: l.GrantMaxStatements, Rows: l.GrantMaxRows, Bytes: l.GrantMaxBytes}
	if g.Duration == 0 {
		g.Duration = DefaultGrantMaxDuration
	}
	if g.Statements == 0 {
		g.Statements = DefaultGrantMaxStatements
	}
	if g.Rows == 0 {
		g.Rows = DefaultGrantMaxRows
	}
	if g.Bytes == 0 {
		g.Bytes = DefaultGrantMaxBytes
	}
	if l.GrantsOff {
		g.Duration = 0
		return g, false
	}
	return g, true
}

// canonicalGrants keeps the grant limits of l in one form: an explicit
// default is unset, so that a policy written with the default values has
// the fingerprint of one that leaves them out (and of one approved before
// grants existed).
func canonicalGrants(l *Limits) {
	if l.GrantsOff {
		l.GrantMaxDuration = 0
	}
	if l.GrantMaxDuration == DefaultGrantMaxDuration {
		l.GrantMaxDuration = 0
	}
	if l.GrantMaxStatements == DefaultGrantMaxStatements {
		l.GrantMaxStatements = 0
	}
	if l.GrantMaxRows == DefaultGrantMaxRows {
		l.GrantMaxRows = 0
	}
	if l.GrantMaxBytes == DefaultGrantMaxBytes {
		l.GrantMaxBytes = 0
	}
}

// grantDuration is limits.grant_max_duration as written: a duration
// string ("30m"), or the integer 0, which disables grants like "0".
type grantDuration string

var errGrantDuration = errors.New(`want a duration string such as "30m", or 0 to disable grants`)

// UnmarshalTOML implements toml.Unmarshaler.
func (g *grantDuration) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case string:
		*g = grantDuration(x)
	case int64:
		if x != 0 {
			return errGrantDuration
		}
		*g = "0s"
	default:
		return errGrantDuration
	}
	return nil
}

// parseGrantDuration sets the grant duration limit of l from s ("" leaves
// it unset).
func parseGrantDuration(l *Limits, s string, errf func(string, ...any) error) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return errf("limits.grant_max_duration: invalid duration (want a Go duration such as \"30m\", or \"0\" to disable grants)")
	case d < 0:
		return errf("limits.grant_max_duration must not be negative")
	case d > MaxGrantDuration:
		return errf("limits.grant_max_duration (%s) is above %s", d, MaxGrantDuration)
	case d == 0:
		l.GrantsOff = true
	default:
		l.GrantMaxDuration = d
	}
	return nil
}

// grantDurationString is the grant duration limit of l as the config
// writes it: "0s" when grants are off, "" when unset.
func grantDurationString(l Limits) string {
	if l.GrantsOff {
		return "0s"
	}
	return durString(l.GrantMaxDuration)
}

// grantDiff lists the changes of the grant limits from approved a to
// current c, on their effective values (an unset limit is its default):
// raising any of them loosens, and so does turning grants on (a duration
// of 0 is grants off).
func grantDiff(a, c Limits) []Change {
	ag, aon := a.Grants()
	cg, con := c.Grants()
	if !aon {
		ag.Duration = 0
	}
	if !con {
		cg.Duration = 0
	}
	dur := func(d time.Duration) string {
		if d == 0 {
			return "0 (grants off)"
		}
		return d.String()
	}
	var out []Change
	if ag.Duration != cg.Duration {
		out = append(out, Change{Field: "limits.grant_max_duration", Old: dur(ag.Duration), New: dur(cg.Duration), Loosens: cg.Duration > ag.Duration})
	}
	for _, f := range []struct {
		field string
		o, n  int64
	}{
		{"grant_max_statements", ag.Statements, cg.Statements},
		{"grant_max_rows", ag.Rows, cg.Rows},
		{"grant_max_bytes", ag.Bytes, cg.Bytes},
	} {
		if f.o != f.n {
			out = append(out, Change{Field: "limits." + f.field, Old: strconv.FormatInt(f.o, 10), New: strconv.FormatInt(f.n, 10), Loosens: f.n > f.o})
		}
	}
	return out
}
