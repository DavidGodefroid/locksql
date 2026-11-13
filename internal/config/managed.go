package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/managed"
)

// ManagedTool is locksql's section of the company's managed file
// ([locksql.bounds], [locksql.defaults], [locksql.profiles.<name>]).
const ManagedTool = "locksql"

// Managed is locksql's part of the company's managed file (lockkit
// managed): its defaults, its profiles and its bounds. A nil *Managed is no
// managed file.
type Managed struct {
	File *managed.File
	// Defaults is [locksql.defaults] as the file holds it (nil: none): the
	// keys a profile leaves unset take it.
	Defaults map[string]any
	// Profiles are [locksql.profiles.<name>], built with the defaults.
	Profiles map[string]Profile
	// Bounds are [locksql.bounds] and the [family] rules locksql enforces
	// (nil: none).
	Bounds *Bounds
}

// loadManaged reads the machine's managed file; tests replace it.
var loadManaged = managed.Load

// LoadManaged reads the machine's managed file: nil and no error when there
// is none. A file lockkit refuses (badly owned, invalid, badly signed) or a
// locksql section that is invalid or beyond its own bounds is an error: the
// caller refuses to start.
func LoadManaged() (*Managed, error) {
	f, err := loadManaged(context.Background())
	if err != nil || f == nil {
		return nil, err
	}
	return ParseManaged(f)
}

// ParseManaged reads locksql's part of f (nil: none). A managed default or
// a managed profile beyond the bounds is an error.
func ParseManaged(f *managed.File) (*Managed, error) {
	if f == nil {
		return nil, nil
	}
	m := &Managed{File: f, Profiles: map[string]Profile{}}
	where := func(kind string, err error) error {
		return fmt.Errorf("managed: %s: [%s.%s]: %w", f.Path, ManagedTool, kind, err)
	}
	b, err := parseBounds(f)
	if err != nil {
		return nil, where(managed.KindBounds, err)
	}
	m.Bounds = b
	// Decoded into rawProfile first: an unknown key is refused, strictly.
	if ok, err := f.Decode(&rawProfile{}, ManagedTool, managed.KindDefaults); err != nil {
		return nil, err
	} else if ok {
		var t map[string]any
		if _, err := f.Decode(&t, ManagedTool, managed.KindDefaults); err != nil {
			return nil, err
		}
		m.Defaults = t
		if err := m.checkDefaults(); err != nil {
			return nil, where(managed.KindDefaults, err)
		}
	}
	baseDir := "/"
	if f.Path != "" {
		baseDir = filepath.Dir(f.Path)
	}
	for _, name := range f.Profiles(ManagedTool) {
		key := managed.KindProfiles + "." + name
		if _, err := f.Decode(&rawProfile{}, ManagedTool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		var t map[string]any
		if _, err := f.Decode(&t, ManagedTool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		p, err := profileFromTable(name, t, m.Defaults, baseDir)
		if err != nil {
			return nil, where(key, err)
		}
		m.Bounds.require(&p)
		lines, err := m.Bounds.Violations(m.Bounds.policyOf(p))
		if err != nil {
			return nil, where(key, err)
		}
		if len(lines) > 0 {
			return nil, where(key, fmt.Errorf("the managed profile is beyond the managed bounds: %s", lines[0]))
		}
		m.Profiles[name] = p
	}
	return m, nil
}

// checkDefaults refuses a managed default beyond the bounds: the defaults
// make a profile of their own, and a violation of a key they set is an
// error.
func (m *Managed) checkDefaults() error {
	t := maps.Clone(m.Defaults)
	if _, ok := t["engine"]; !ok {
		t["engine"] = EnginePostgres
	}
	if t["engine"] == EngineSQLite {
		if _, ok := t["path"]; !ok {
			t["path"] = ":memory:"
		}
	} else if _, ok := t["host"]; !ok {
		t["host"] = "localhost"
	}
	p, err := profileFromTable("managed-defaults", t, nil, "/")
	if err != nil {
		return err
	}
	m.Bounds.require(&p)
	vs, err := m.Bounds.violations(m.Bounds.policyOf(p))
	if err != nil {
		return err
	}
	set := flatKeys(m.Defaults, "")
	for _, v := range vs {
		for _, k := range set {
			if v.Field == k || strings.HasPrefix(v.Field, k+".") {
				return fmt.Errorf("the managed default is beyond the managed bounds: %s", strings.Replace(v.String(), "(profile managed-defaults: ", "(defaults: ", 1))
			}
		}
	}
	return nil
}

// flatKeys lists the keys of t, a limits table's keys as "limits.max_rows".
func flatKeys(t map[string]any, prefix string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(t)) {
		out = append(out, prefix+k)
		if sub, ok := t[k].(map[string]any); ok && k == "limits" {
			out = append(out, flatKeys(sub, prefix+k+".")...)
		}
	}
	return out
}

// DescribeDefaults is [locksql.defaults] as lines for `locksql managed
// show` ("locksql.defaults.limits.max_rows = 100").
func (m *Managed) DescribeDefaults() []string {
	if m == nil {
		return nil
	}
	var out []string
	var walk func(t map[string]any, prefix string)
	walk = func(t map[string]any, prefix string) {
		for _, k := range slices.Sorted(maps.Keys(t)) {
			if sub, ok := t[k].(map[string]any); ok {
				walk(sub, prefix+k+".")
				continue
			}
			var buf bytes.Buffer
			if err := toml.NewEncoder(&buf).Encode(map[string]any{"v": t[k]}); err != nil {
				continue
			}
			v := strings.TrimSpace(strings.TrimPrefix(buf.String(), "v = "))
			v = strings.Join(strings.Fields(v), " ")
			out = append(out, ManagedTool+"."+managed.KindDefaults+"."+prefix+k+" = "+v)
		}
	}
	walk(m.Defaults, "")
	return out
}

// defaults is the managed defaults (nil for a nil m).
func (m *Managed) defaults() map[string]any {
	if m == nil {
		return nil
	}
	return m.Defaults
}

// profiles is the managed profiles (nil for a nil m).
func (m *Managed) profiles() map[string]Profile {
	if m == nil {
		return nil
	}
	return m.Profiles
}

// BoundsOf is m's bounds, nil for a nil m.
func (m *Managed) BoundsOf() *Bounds {
	if m == nil {
		return nil
	}
	return m.Bounds
}

// withDefaults is the profile table t with the keys it does not set taken
// from the defaults d; the limits table is merged key by key, the ssh and
// auto keys are taken whole.
func withDefaults(t, d map[string]any) map[string]any {
	out := maps.Clone(t)
	if out == nil {
		out = map[string]any{}
	}
	for k, v := range d {
		cur, ok := out[k]
		if !ok {
			out[k] = v
			continue
		}
		cl, ok1 := cur.(map[string]any)
		dl, ok2 := v.(map[string]any)
		if k == "limits" && ok1 && ok2 {
			out[k] = withDefaults(cl, dl)
		}
	}
	return out
}

// profileFromTable builds the profile name from its table t and the
// defaults d, through ParseProfiles: the same checks as a config file.
func profileFromTable(name string, t, d map[string]any, baseDir string) (Profile, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(map[string]any{"profiles": map[string]any{name: withDefaults(t, d)}}); err != nil {
		return Profile{}, fmt.Errorf("profile %q: %w", name, err)
	}
	ps, err := parseProfiles(buf.Bytes(), managed.FileName, baseDir, nil)
	if err != nil {
		if u := errors.Unwrap(err); u != nil {
			err = u // "profile %q: …", without the file name the caller gives
		}
		return Profile{}, err
	}
	return ps[name], nil
}

// MaskRule is one [[locksql.bounds.pii_mask]]: a column pattern
// (db.table.column, as [[mask]] in a PII rule set) and its mode.
type MaskRule struct {
	Column, Mode string
}

// maskModes are the modes of a mask rule (package pii).
var maskModes = []string{DefaultMaskMode, "partial", "email"}

// Bounds are [locksql.bounds] and the [family] rules locksql enforces: the
// loosest policy the company allows. A nil *Bounds bounds nothing.
type Bounds struct {
	production     bool
	tier           *Tier
	tls            string
	credentials    []string
	engines        []string
	hosts          []string
	writeFunctions string
	credentialsTTL time.Duration
	auto           map[AutoAction]AutoValue
	ints           map[string]int64
	durations      map[string]time.Duration
	// grantsOff: limits.grant_max_duration = 0, grants are disabled.
	grantsOff     bool
	detectors     []string
	masks         []MaskRule
	vaultRequired bool
}

type rawBoundLimits struct {
	StatementTimeout   string         `toml:"statement_timeout"`
	MaxRows            *int64         `toml:"max_rows"`
	MaxCellChars       *int64         `toml:"max_cell_chars"`
	MaxOutputBytes     *int64         `toml:"max_output_bytes"`
	ExplainRowsRefuse  *int64         `toml:"explain_rows_refuse"`
	KAnonymity         *int64         `toml:"k_anonymity"`
	IdleTimeout        string         `toml:"idle_timeout"`
	MaxSession         string         `toml:"max_session"`
	GrantMaxDuration   *grantDuration `toml:"grant_max_duration"`
	GrantMaxStatements *int64         `toml:"grant_max_statements"`
	GrantMaxRows       *int64         `toml:"grant_max_rows"`
	GrantMaxBytes      *int64         `toml:"grant_max_bytes"`
}

type rawMaskRule struct {
	Column string `toml:"column"`
	Mode   string `toml:"mode"`
}

type rawBounds struct {
	Production     *bool             `toml:"production"`
	Tier           string            `toml:"tier"`
	TLS            string            `toml:"tls"`
	Credentials    []string          `toml:"credentials"`
	Engine         []string          `toml:"engine"`
	Hosts          []string          `toml:"hosts"`
	WriteFunctions string            `toml:"write_functions"`
	CredentialsTTL string            `toml:"credentials_ttl"`
	Auto           map[string]string `toml:"auto"`
	Limits         rawBoundLimits    `toml:"limits"`
	Detectors      []string          `toml:"detectors"`
	PIIMask        []rawMaskRule     `toml:"pii_mask"`
}

// boundKey is the managed key of a bound ("locksql.bounds.tier").
func boundKey(k string) string { return ManagedTool + "." + managed.KindBounds + "." + k }

// parseBounds reads [locksql.bounds] and the [family] vault rule: nil when
// f has neither. Its errors name the key, never quote a value.
func parseBounds(f *managed.File) (*Bounds, error) {
	var r rawBounds
	ok, err := f.Decode(&r, ManagedTool, managed.KindBounds)
	if err != nil {
		return nil, err
	}
	vault := f.Family.Vault != nil && f.Family.Vault.Required
	if !ok && !vault {
		return nil, nil
	}
	b := &Bounds{vaultRequired: vault, ints: map[string]int64{}, durations: map[string]time.Duration{}}
	if r.Production != nil {
		if !*r.Production {
			return nil, errors.New("production: only true bounds anything (every profile is production)")
		}
		b.production = true
	}
	if r.Tier != "" {
		t, err := ParseTier(r.Tier)
		if err != nil {
			return nil, fmt.Errorf("tier: %w", err)
		}
		b.tier = &t
	}
	if r.TLS != "" {
		if TLSRank(r.TLS) < 0 {
			return nil, errors.New("tls: unknown tls mode (want disable, prefer, require, verify-ca or verify-full)")
		}
		b.tls = r.TLS
	}
	for _, c := range r.Credentials {
		switch c {
		case CredentialsAsk, CredentialsKeychain, CredentialsVault:
		default:
			return nil, errors.New("credentials: unknown credentials mode (want ask, keychain or vault)")
		}
	}
	if r.Credentials != nil && len(r.Credentials) == 0 {
		return nil, errors.New("credentials: list at least one credentials mode")
	}
	b.credentials = r.Credentials
	for _, e := range r.Engine {
		switch e {
		case EngineMariaDB, EngineMySQL, EnginePostgres, EngineSQLite:
		default:
			return nil, errors.New("engine: unknown engine (want mariadb, mysql, postgres or sqlite)")
		}
	}
	if r.Engine != nil && len(r.Engine) == 0 {
		return nil, errors.New("engine: list at least one engine")
	}
	b.engines = r.Engine
	for i, h := range r.Hosts {
		if _, err := path.Match(h, ""); err != nil || h == "" {
			return nil, fmt.Errorf("hosts entry %d: want a host pattern such as \"*.db.example.internal\"", i+1)
		}
	}
	if r.Hosts != nil && len(r.Hosts) == 0 {
		return nil, errors.New("hosts: list at least one host pattern")
	}
	b.hosts = r.Hosts
	switch r.WriteFunctions {
	case "":
	case WriteFunctionsAllowlist:
		b.writeFunctions = WriteFunctionsAllowlist
	default:
		return nil, fmt.Errorf("write_functions: only %q bounds anything", WriteFunctionsAllowlist)
	}
	if r.CredentialsTTL != "" {
		d, err := time.ParseDuration(r.CredentialsTTL)
		if err != nil || d < time.Minute {
			return nil, errors.New("credentials_ttl: want a duration of at least 1m")
		}
		b.credentialsTTL = d
	}
	for _, act := range slices.Sorted(maps.Keys(r.Auto)) {
		if !slices.Contains(AutoActions, AutoAction(act)) {
			return nil, fmt.Errorf("auto: unknown action (want %s)", actionNames())
		}
		v, err := ParseAutoValue(r.Auto[act])
		if err != nil {
			return nil, fmt.Errorf("auto.%s: %w", act, err)
		}
		if b.auto == nil {
			b.auto = map[AutoAction]AutoValue{}
		}
		b.auto[AutoAction(act)] = v
	}
	l := r.Limits
	for _, f := range []struct {
		key string
		v   *int64
	}{{"max_rows", l.MaxRows}, {"max_cell_chars", l.MaxCellChars}, {"max_output_bytes", l.MaxOutputBytes},
		{"explain_rows_refuse", l.ExplainRowsRefuse}, {"k_anonymity", l.KAnonymity},
		{"grant_max_statements", l.GrantMaxStatements}, {"grant_max_rows", l.GrantMaxRows}, {"grant_max_bytes", l.GrantMaxBytes}} {
		if f.v == nil {
			continue
		}
		if *f.v < 1 {
			return nil, fmt.Errorf("limits.%s: want at least 1", f.key)
		}
		b.ints[f.key] = *f.v
	}
	for _, f := range []struct{ key, v string }{{"statement_timeout", l.StatementTimeout},
		{"idle_timeout", l.IdleTimeout}, {"max_session", l.MaxSession}} {
		if f.v == "" {
			continue
		}
		d, err := time.ParseDuration(f.v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("limits.%s: want a positive duration such as \"10s\" or \"20m\"", f.key)
		}
		b.durations[f.key] = d
	}
	if l.GrantMaxDuration != nil {
		var gl Limits
		if err := parseGrantDuration(&gl, string(*l.GrantMaxDuration), func(format string, a ...any) error { return fmt.Errorf(format, a...) }); err != nil {
			return nil, err
		}
		if gl.GrantsOff {
			b.grantsOff = true
		} else {
			b.durations["grant_max_duration"] = gl.GrantMaxDuration
		}
	}
	for i, d := range r.Detectors {
		if !knownDetectors[d] {
			return nil, fmt.Errorf("detectors: unknown detector (entry %d; known: %s)", i+1, strings.Join(slices.Sorted(maps.Keys(knownDetectors)), ", "))
		}
	}
	b.detectors = kconfig.SortedSet(r.Detectors)
	for i, m := range r.PIIMask {
		col, err := ParsePIIPattern(m.Column)
		if err != nil {
			return nil, fmt.Errorf("pii_mask %d: %w", i+1, err)
		}
		mode := m.Mode
		if mode == "" {
			mode = DefaultMaskMode
		}
		if !slices.Contains(maskModes, mode) {
			return nil, fmt.Errorf("pii_mask %d: unknown mode (want redact, partial or email)", i+1)
		}
		b.masks = append(b.masks, MaskRule{Column: col, Mode: mode})
	}
	return b, nil
}

// Describe is the bounds as lines for `locksql managed show`.
func (b *Bounds) Describe() []string {
	if b == nil {
		return nil
	}
	var out []string
	add := func(k, v string) { out = append(out, boundKey(k)+" = "+v) }
	if b.production {
		add("production", "true")
	}
	if b.tier != nil {
		add("tier", b.tier.String())
	}
	if b.tls != "" {
		add("tls", b.tls)
	}
	if b.credentials != nil {
		add("credentials", strings.Join(b.credentials, ", "))
	}
	if b.engines != nil {
		add("engine", strings.Join(b.engines, ", "))
	}
	if b.hosts != nil {
		add("hosts", strings.Join(b.hosts, ", "))
	}
	if b.writeFunctions != "" {
		add("write_functions", b.writeFunctions)
	}
	if b.credentialsTTL > 0 {
		add("credentials_ttl", b.credentialsTTL.String())
	}
	for _, act := range AutoActions {
		if v, ok := b.auto[act]; ok {
			add("auto."+string(act), string(v))
		}
	}
	lim := map[string]string{}
	for k, v := range b.ints {
		lim[k] = strconv.FormatInt(v, 10)
	}
	for k, v := range b.durations {
		lim[k] = v.String()
	}
	if b.grantsOff {
		lim["grant_max_duration"] = "0 (grants off)"
	}
	for _, k := range slices.Sorted(maps.Keys(lim)) {
		add("limits."+k, lim[k])
	}
	if len(b.detectors) > 0 {
		add("detectors", strings.Join(b.detectors, ", "))
	}
	for _, m := range b.masks {
		add("pii_mask", m.Column+" ("+m.Mode+")")
	}
	if b.vaultRequired {
		out = append(out, "family.vault.required = true")
	}
	return out
}

// require adds the required detectors to p.
func (b *Bounds) require(p *Profile) {
	if b == nil || len(b.detectors) == 0 {
		return
	}
	p.Detectors = kconfig.SortedSet(append(slices.Clone(p.Detectors), b.detectors...))
}

// Require adds the detectors the bounds require to every profile of ps.
func (b *Bounds) Require(ps map[string]Profile) {
	for n, p := range ps {
		b.require(&p)
		ps[n] = p
	}
}

// policyOf is p's policy with the managed mask rules only.
func (b *Bounds) policyOf(p Profile) Policy {
	mask, allow, modes, _ := b.ApplyPII(nil, nil, nil)
	return NewPolicy(p, mask, allow).WithModes(modes)
}

// Masks are the managed mask rules, nil for a nil b.
func (b *Bounds) Masks() []MaskRule {
	if b == nil {
		return nil
	}
	return slices.Clone(b.masks)
}

// ApplyPII adds the managed mask rules to the PII rules of a profile (its
// mask and allow patterns, and the modes of its masks), whatever its rule
// set: a user mask of a managed pattern takes the managed mode. A user
// allow rule that could clear what a managed rule masks is refused: a
// user can add rules, never remove or weaken a managed one.
func (b *Bounds) ApplyPII(mask, allow []string, modes map[string]string) ([]string, []string, map[string]string, error) {
	if b == nil || len(b.masks) == 0 {
		return mask, allow, modes, nil
	}
	for _, a := range allow {
		for _, m := range b.masks {
			if PIIPatternsOverlap(a, m.Column) {
				return nil, nil, nil, fmt.Errorf("pii rules: the allow rule %s would clear what the company's managed configuration masks (%s %s): remove it", a, boundKey("pii_mask"), m.Column)
			}
		}
	}
	mask = slices.Clone(mask)
	modes = maps.Clone(modes)
	if modes == nil {
		modes = map[string]string{}
	}
	for _, m := range b.masks {
		if !slices.Contains(mask, m.Column) {
			mask = append(mask, m.Column)
		}
		if m.Mode == DefaultMaskMode {
			delete(modes, m.Column)
		} else {
			modes[m.Column] = m.Mode
		}
	}
	return mask, slices.Clone(allow), modes, nil
}

// BoundsError is a policy outside an allowlist bound: credentials, engine,
// hosts, family.vault.required. The console refuses it as a violation.
type BoundsError struct {
	Violations []managed.Violation
}

// Error cites each violation as managed.Violation does, without its
// "blocked by company policy: " lead, which the console adds.
func (e *BoundsError) Error() string {
	lines := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		lines[i] = strings.TrimPrefix(v.String(), violationLead)
	}
	return strings.Join(lines, "; ")
}

// violationLead starts every managed.Violation line.
const violationLead = "blocked by company policy: "

// Ceiling returns pol at its ceiling under b: pol with every bounded field
// set to its bound, which Diff then compares pol with, and the bound keys
// of the Diff fields whose names differ. A value outside an allowlist Diff
// cannot express (credentials, engine, hosts, family.vault.required) is a
// *BoundsError naming the managed key. A nil b bounds nothing: nil.
func (b *Bounds) Ceiling(pol Policy) (*Policy, map[string]string, error) {
	if b == nil {
		return nil, nil, nil
	}
	pol = canonical(pol)
	pr := pol.Profile
	var vs []managed.Violation
	if b.credentials != nil && !slices.Contains(b.credentials, pr.Credentials) {
		vs = append(vs, managed.Violation{Key: boundKey("credentials"), Profile: pr.Name, Field: "credentials", Value: pr.Credentials})
	}
	if b.vaultRequired && pr.Engine != EngineSQLite && pr.Credentials != CredentialsVault {
		vs = append(vs, managed.Violation{Key: "family.vault.required", Profile: pr.Name, Field: "credentials", Value: pr.Credentials, Bound: "true"})
	}
	if b.engines != nil && !slices.Contains(b.engines, pr.Engine) {
		vs = append(vs, managed.Violation{Key: boundKey("engine"), Profile: pr.Name, Field: "engine", Value: pr.Engine})
	}
	if b.hosts != nil {
		for _, h := range profileHosts(pr) {
			if !b.hostAllowed(h.host) {
				vs = append(vs, managed.Violation{Key: boundKey("hosts"), Profile: pr.Name, Field: h.key, Value: h.host})
			}
		}
	}
	c := pol
	cp := &c.Profile
	if b.production {
		cp.Production = true
	}
	if b.tier != nil {
		cp.Tier = *b.tier
	}
	if b.tls != "" && cp.Engine != EngineSQLite {
		cp.TLS = b.tls
	}
	if b.writeFunctions != "" {
		cp.WriteFunctions = b.writeFunctions
	}
	if b.credentialsTTL > 0 {
		cp.CredentialsTTL = b.credentialsTTL
	}
	if len(b.auto) > 0 {
		rules := pr.AutoRules()
		for act, v := range b.auto {
			*rules.field(act) = v
		}
		cp.Auto = rules.sparse()
	}
	l := &cp.Limits
	for k, v := range b.ints {
		switch k {
		case "max_rows":
			l.MaxRows = int(v)
		case "max_cell_chars":
			l.MaxCellChars = int(v)
		case "max_output_bytes":
			l.MaxOutputBytes = int(v)
		case "explain_rows_refuse":
			l.ExplainRowsRefuse = v
		case "k_anonymity":
			l.KAnonymity = int(v)
		case "grant_max_statements":
			l.GrantMaxStatements = v
		case "grant_max_rows":
			l.GrantMaxRows = v
		case "grant_max_bytes":
			l.GrantMaxBytes = v
		}
	}
	for k, v := range b.durations {
		switch k {
		case "statement_timeout":
			l.StatementTimeout = v
		case "idle_timeout":
			l.IdleTimeout = v
		case "max_session":
			l.MaxSession = v
		case "grant_max_duration":
			l.GrantMaxDuration, l.GrantsOff = v, false
		}
	}
	if b.grantsOff {
		l.GrantMaxDuration, l.GrantsOff = 0, true
	}
	cp.Detectors = kconfig.SortedSet(append(slices.Clone(cp.Detectors), b.detectors...))
	keys := map[string]string{}
	if len(b.masks) > 0 {
		keys["pii.mask"], keys["pii.allow"], keys["pii.mode"] = "pii_mask", "pii_mask", "pii_mask"
		c.PIIAllow = nil
		for _, a := range pol.PIIAllow {
			if !slices.ContainsFunc(b.masks, func(m MaskRule) bool { return PIIPatternsOverlap(a, m.Column) }) {
				c.PIIAllow = append(c.PIIAllow, a)
			}
		}
		c.PIIMask, _, c.PIIModes, _ = b.ApplyPII(pol.PIIMask, nil, pol.PIIModes)
	}
	ceiling := canonical(c)
	if len(vs) > 0 {
		return &ceiling, keys, &BoundsError{Violations: vs}
	}
	return &ceiling, keys, nil
}

// violations lists what refuses pol: its allowlist violations and the
// fields of pol that loosen its ceiling, as managed.Check finds them. An
// error is a bounds section that cannot be applied.
func (b *Bounds) violations(pol Policy) ([]managed.Violation, error) {
	ceiling, keys, err := b.Ceiling(pol)
	var vs []managed.Violation
	var be *BoundsError
	switch {
	case errors.As(err, &be):
		vs = append(vs, be.Violations...)
	case err != nil:
		return nil, err
	}
	if ceiling == nil {
		return nil, nil
	}
	for _, c := range Diff(*ceiling, pol) {
		if !c.Loosens {
			continue
		}
		key := c.Field
		if k, ok := keys[c.Field]; ok {
			key = k
		}
		vs = append(vs, managed.Violation{Key: boundKey(key), Profile: pol.Profile.Name, Field: c.Field, Value: c.New, Bound: c.Old})
	}
	return vs, nil
}

// Violations are the lines that refuse pol, each "blocked by company
// policy: …". An error is a bounds section that cannot be applied.
func (b *Bounds) Violations(pol Policy) ([]string, error) {
	vs, err := b.violations(pol)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(vs))
	for _, v := range vs {
		lines = append(lines, v.String())
	}
	return lines, nil
}

type profileHost struct{ key, host string }

// profileHosts are the hosts p reaches: host and ssh.host. A SQLite
// profile reaches none.
func profileHosts(p Profile) []profileHost {
	var out []profileHost
	if p.Engine != EngineSQLite && p.Host != "" {
		out = append(out, profileHost{"host", p.Host})
	}
	if p.SSH != nil {
		out = append(out, profileHost{"ssh.host", p.SSH.Host})
	}
	return out
}

func (b *Bounds) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range b.hosts {
		if ok, _ := path.Match(strings.ToLower(pat), host); ok {
			return true
		}
	}
	return false
}
