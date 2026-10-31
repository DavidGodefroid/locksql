package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locksql/internal/product"
)

// ShareFormat is the version of the shared configuration file this
// release reads and writes. A newer file is refused; an older one is
// migrated in DecodeShare.
const ShareFormat = 1

// Share is a shareable locksql configuration (locksql config export): the
// shared keys of some profiles and the PII rule sets they use, keyed by
// set name. It never holds a secret nor a machine-specific value.
type Share struct {
	Format   int                      `json:"locksql_config_format"`
	Version  string                   `json:"locksql_version,omitempty"`
	Profiles map[string]SharedProfile `json:"profiles"`
	PII      map[string]SharedRules   `json:"pii,omitempty"`
}

// SharedRules is one PII rule set in a Share.
type SharedRules struct {
	Mask  []SharedRule `json:"mask"`
	Allow []SharedRule `json:"allow"`
}

// SharedRule is one PII rule: a column pattern and, for a mask rule, its
// mode when it is not redact.
type SharedRule struct {
	Column string `json:"column"`
	Mode   string `json:"mode,omitempty"`
}

// SharedProfile holds the keys of a profile that a team shares. The keys
// of one machine (LocalKeys) are never in it: NeedsLocal names those the
// source profile had, which the importer supplies with --local. User is
// exported only on request: it is the employee's own login.
type SharedProfile struct {
	Engine         string        `json:"engine"`
	Host           string        `json:"host,omitempty"`
	Port           int           `json:"port,omitempty"`
	User           string        `json:"user,omitempty"`
	Database       string        `json:"database,omitempty"`
	Credentials    string        `json:"credentials,omitempty"`
	VaultPath      string        `json:"vault_path,omitempty"`
	CredentialsTTL string        `json:"credentials_ttl,omitempty"`
	TLS            string        `json:"tls,omitempty"`
	TLSServerName  string        `json:"tls_server_name,omitempty"`
	Tier           string        `json:"tier,omitempty"`
	Production     bool          `json:"production,omitempty"`
	Detectors      []string      `json:"detectors"`
	PIIRules       string        `json:"pii_rules,omitempty"`
	WriteFunctions string        `json:"write_functions,omitempty"`
	Limits         *SharedLimits `json:"limits,omitempty"`
	SSH            *SharedSSH    `json:"ssh,omitempty"`
	NeedsLocal     []string      `json:"needs_local,omitempty"`
}

// SharedLimits are the limits of a SharedProfile; durations as Go
// duration strings.
type SharedLimits struct {
	StatementTimeout  string  `json:"statement_timeout,omitempty"`
	ExplainRowsWarn   int64   `json:"explain_rows_warn,omitempty"`
	ExplainRowsRefuse int64   `json:"explain_rows_refuse,omitempty"`
	MaxRows           int     `json:"max_rows,omitempty"`
	MaxCellChars      int     `json:"max_cell_chars,omitempty"`
	MaxOutputBytes    int     `json:"max_output_bytes,omitempty"`
	ExplainCostRefuse float64 `json:"explain_cost_refuse,omitempty"`
	KAnonymity        int     `json:"k_anonymity,omitempty"`
	ReferenceProbe    int     `json:"reference_probe,omitempty"`
	IdleTimeout       string  `json:"idle_timeout,omitempty"`
	MaxSession        string  `json:"max_session,omitempty"`
}

// SharedSSH is the bastion of a SharedProfile, without its key file.
type SharedSSH struct {
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	User        string `json:"user"`
	Auth        string `json:"auth"`
	Credentials string `json:"credentials,omitempty"`
}

// LocalKeys are the keys that name files of one machine: never exported,
// listed in needs_local, given on import with --local NAME.KEY=VALUE.
var LocalKeys = []string{"tls_ca", "tls_cert", "tls_key", "ssh.key"}

// HandLocalKeys are local keys that only the importer's own config file
// may set: proxy_command is a command line, which neither a shared file
// nor --local may bring. An import keeps the local value, or skips the
// profile.
var HandLocalKeys = []string{"proxy_command"}

// IsLocalKey reports whether key is one of LocalKeys.
func IsLocalKey(key string) bool {
	for _, k := range LocalKeys {
		if k == key {
			return true
		}
	}
	return false
}

// ErrNotShareable marks a profile that cannot be shared: a SQLite file or
// a Unix socket is a path of one machine.
var ErrNotShareable = errors.New("not shareable")

// ExportProfile is the shared form of the resolved profile p, whose PII
// rule set is set. It fails with ErrNotShareable for a SQLite or Unix
// socket profile, and refuses a value that looks like a secret.
func ExportProfile(p Profile, set string, includeUser bool) (SharedProfile, error) {
	if p.Engine == EngineSQLite {
		return SharedProfile{}, fmt.Errorf("profile %q: a sqlite path is a file of this machine: %w", p.Name, ErrNotShareable)
	}
	if strings.HasPrefix(p.Host, "/") {
		return SharedProfile{}, fmt.Errorf("profile %q: a Unix socket is a file of this machine: %w", p.Name, ErrNotShareable)
	}
	l := p.Limits
	s := SharedProfile{
		Engine: p.Engine, Host: p.Host, Port: p.Port, Database: p.Database,
		Credentials: p.Credentials, VaultPath: p.VaultPath, TLS: p.TLS, TLSServerName: p.TLSServerName,
		Tier: p.Tier.String(), Production: p.Production, Detectors: append([]string{}, p.Detectors...), PIIRules: set,
		WriteFunctions: p.WriteFunctions,
		Limits: &SharedLimits{
			StatementTimeout: durString(l.StatementTimeout), ExplainRowsWarn: l.ExplainRowsWarn, ExplainRowsRefuse: l.ExplainRowsRefuse,
			MaxRows: l.MaxRows, MaxCellChars: l.MaxCellChars, MaxOutputBytes: l.MaxOutputBytes, ExplainCostRefuse: l.ExplainCostRefuse,
			KAnonymity: l.KAnonymity, ReferenceProbe: l.ReferenceProbe, IdleTimeout: durString(l.IdleTimeout), MaxSession: durString(l.MaxSession),
		},
	}
	if includeUser {
		s.User = p.User
	}
	if p.CredentialsTTL != 0 {
		s.CredentialsTTL = p.CredentialsTTL.String()
	}
	for _, f := range []struct{ key, val string }{{"tls_ca", p.TLSCA}, {"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		if f.val != "" {
			s.NeedsLocal = append(s.NeedsLocal, f.key)
		}
	}
	if len(p.ProxyCommand) > 0 {
		s.NeedsLocal = append(s.NeedsLocal, "proxy_command")
	}
	if p.SSH != nil {
		s.SSH = &SharedSSH{Host: p.SSH.Host, Port: p.SSH.Port, User: p.SSH.User, Auth: p.SSH.Auth, Credentials: p.SSH.Credentials}
		if p.SSH.Key != "" {
			s.NeedsLocal = append(s.NeedsLocal, "ssh.key")
		}
	}
	if err := s.checkValues(p.Name); err != nil {
		return SharedProfile{}, err
	}
	return s, nil
}

func durString(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

// strings lists the string values of s with their keys.
func (s SharedProfile) strings() [][2]string {
	out := [][2]string{{"engine", s.Engine}, {"host", s.Host}, {"user", s.User}, {"database", s.Database},
		{"credentials", s.Credentials}, {"vault_path", s.VaultPath}, {"credentials_ttl", s.CredentialsTTL},
		{"tls", s.TLS}, {"tls_server_name", s.TLSServerName}, {"tier", s.Tier}, {"pii_rules", s.PIIRules},
		{"write_functions", s.WriteFunctions}}
	for _, d := range s.Detectors {
		out = append(out, [2]string{"detectors", d})
	}
	if l := s.Limits; l != nil {
		out = append(out, [2]string{"limits.statement_timeout", l.StatementTimeout}, [2]string{"limits.idle_timeout", l.IdleTimeout},
			[2]string{"limits.max_session", l.MaxSession})
	}
	if h := s.SSH; h != nil {
		out = append(out, [2]string{"ssh.host", h.Host}, [2]string{"ssh.user", h.User}, [2]string{"ssh.auth", h.Auth},
			[2]string{"ssh.credentials", h.Credentials})
	}
	return out
}

// checkValues refuses a value that embeds a password or holds a control
// or formatting character. Errors name the key, never the value.
func (s SharedProfile) checkValues(name string) error {
	for _, kv := range s.strings() {
		if err := kconfig.CheckValue(product.P, kv[0], kv[1]); err != nil {
			return fmt.Errorf("profile %q: %v", name, err)
		}
	}
	return nil
}

// EncodeShare writes s as indented JSON, keys sorted.
func EncodeShare(w io.Writer, s Share) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(s)
}

// DecodeShare reads a shared configuration strictly: an unknown field at
// any depth, a format newer than ShareFormat, a profile or set name that
// is not valid, a secret-like or unsafe value, a needs_local key that is
// not local, or trailing data are refused. Errors never quote a value.
func DecodeShare(data []byte) (*Share, error) {
	var probe struct {
		Format *int `json:"locksql_config_format"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("config import: not a locksql configuration file: %s", jsonError(err))
	}
	switch {
	case probe.Format == nil:
		return nil, errors.New("config import: not a locksql configuration file: no locksql_config_format")
	case *probe.Format > ShareFormat:
		return nil, fmt.Errorf("config import: format %d is newer than this locksql reads (%d): upgrade locksql", *probe.Format, ShareFormat)
	case *probe.Format < 1:
		return nil, fmt.Errorf("config import: unknown format %d", *probe.Format)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Share
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("config import: %s", jsonError(err))
	}
	if dec.More() {
		return nil, errors.New("config import: data after the configuration")
	}
	if len(s.Profiles) == 0 && len(s.PII) == 0 {
		return nil, errors.New("config import: the file holds no profile and no PII rule set")
	}
	for _, name := range sortedKeys(s.Profiles) {
		p := s.Profiles[name]
		if err := kconfig.CheckProfileName(name, p.Production); err != nil {
			return nil, fmt.Errorf("config import: %v", err)
		}
		if err := p.checkValues(name); err != nil {
			return nil, fmt.Errorf("config import: %v", err)
		}
		if p.PIIRules != "" && !ValidRuleSet(p.PIIRules) {
			return nil, fmt.Errorf("config import: profile %q: invalid pii_rules", name)
		}
		for i, k := range p.NeedsLocal {
			if !IsLocalKey(k) && !slices.Contains(HandLocalKeys, k) {
				return nil, fmt.Errorf("config import: profile %q: needs_local entry %d is not a local key (%s)", name, i+1, strings.Join(LocalKeys, ", "))
			}
		}
	}
	for _, set := range sortedKeys(s.PII) {
		if !ValidRuleSet(set) {
			return nil, errors.New("config import: invalid PII rule set name (want 1 to 64 lower-case letters, digits, '_', '-' or '.', starting with a letter or digit)")
		}
	}
	return &s, nil
}

// jsonError describes a JSON decoding error without the value it read.
func jsonError(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("invalid JSON at byte %d", se.Offset)
	case errors.As(err, &te):
		return fmt.Sprintf("field %q: want a %s", te.Field, te.Type)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field ")
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "the file ends too early"
	}
	return "invalid JSON"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ConfigFile is a config file as written, for editing: profiles the edit
// does not touch are written back with the keys they had.
type ConfigFile struct {
	profiles map[string]rawProfile
}

// ParseConfigFile decodes config data for editing. It is checked like
// ParseProfiles; name labels errors and baseDir resolves sqlite paths.
func ParseConfigFile(data []byte, name, baseDir string) (*ConfigFile, error) {
	if _, err := ParseProfiles(data, name, baseDir); err != nil {
		return nil, err
	}
	var raw rawFile
	if _, err := kconfig.Decode(product.P, data, name, &raw); err != nil {
		return nil, err
	}
	if raw.Profiles == nil {
		raw.Profiles = map[string]rawProfile{}
	}
	return &ConfigFile{profiles: raw.Profiles}, nil
}

// Names lists the profiles of f, sorted.
func (f *ConfigFile) Names() []string { return sortedKeys(f.profiles) }

// ImportOptions steer ConfigFile.Import.
type ImportOptions struct {
	// Only, when not empty, limits the import to these profiles.
	Only []string
	// Replace drops the profiles of the file that the import does not
	// hold; by default they are kept.
	Replace bool
	// Local are the --local values: profile -> key -> value.
	Local map[string]map[string]string
}

// Skipped is a profile of the share that was not imported, and why.
type Skipped struct{ Profile, Reason string }

// Import merges the profiles of s into f. An imported profile replaces
// the profile of the same name, but keeps its user (unless the share sets
// one) and its local keys (unless --local sets them). A profile whose
// needs_local keys are neither given nor kept is skipped. --local values
// for a key that is not local, or for a profile not imported, are refused.
func (f *ConfigFile) Import(s *Share, o ImportOptions) ([]Skipped, error) {
	names := sortedKeys(s.Profiles)
	if len(o.Only) > 0 {
		for i, n := range o.Only {
			if _, ok := s.Profiles[n]; !ok {
				// Named by position, not quoted back: it may be a token
				// or a URL pasted in the wrong place.
				return nil, fmt.Errorf("config import: --profile %d: no such profile in the file", i+1)
			}
		}
		names = o.Only
	}
	for pn, kv := range o.Local {
		if _, ok := s.Profiles[pn]; !ok {
			// Not quoted back: the left side of --local may be a token
			// or a URL pasted in the wrong place.
			return nil, fmt.Errorf("config import: --local names a profile that is not in the file")
		}
		for k := range kv {
			if !IsLocalKey(k) {
				return nil, fmt.Errorf("config import: --local %s.%s: only %s are local", pn, k, strings.Join(LocalKeys, ", "))
			}
		}
	}
	next := map[string]rawProfile{}
	if !o.Replace {
		for n, r := range f.profiles {
			next[n] = r
		}
	}
	var skipped []Skipped
	for _, name := range names {
		sp := s.Profiles[name]
		old, had := f.profiles[name]
		r := sp.raw()
		local := o.Local[name]
		keep := func(key string, oldVal string, dst *string) {
			if v, ok := local[key]; ok {
				*dst = v
			} else if had {
				*dst = oldVal
			}
		}
		keep("tls_ca", old.TLSCA, &r.TLSCA)
		keep("tls_cert", old.TLSCert, &r.TLSCert)
		keep("tls_key", old.TLSKey, &r.TLSKey)
		if r.SSH != nil {
			var oldKey string
			if had && old.SSH != nil {
				oldKey = old.SSH.Key
			}
			keep("ssh.key", oldKey, &r.SSH.Key)
		}
		if r.User == "" && had {
			r.User = old.User
		}
		if had {
			r.ProxyCmd = old.ProxyCmd
		}
		var missing []string
		for _, k := range sp.NeedsLocal {
			if localValue(r, k) == "" {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			how := "give --local " + name + "." + missing[0] + "=..."
			if slices.Contains(HandLocalKeys, missing[0]) {
				how = "add " + missing[0] + " to the profile in your config file first"
			}
			skipped = append(skipped, Skipped{name, "needs " + strings.Join(missing, ", ") + " of this machine: " + how})
			if had && o.Replace {
				next[name] = old
			}
			continue
		}
		next[name] = r
	}
	f.profiles = next
	return skipped, nil
}

func localValue(r rawProfile, key string) string {
	switch key {
	case "tls_ca":
		return r.TLSCA
	case "tls_cert":
		return r.TLSCert
	case "tls_key":
		return r.TLSKey
	case "ssh.key":
		if r.SSH != nil {
			return r.SSH.Key
		}
	case "proxy_command":
		return strings.Join(r.ProxyCmd, " ")
	}
	return ""
}

// raw is s as the config keys it sets.
func (s SharedProfile) raw() rawProfile {
	r := rawProfile{
		Engine: s.Engine, Host: s.Host, Port: s.Port, User: s.User, Database: s.Database, Credentials: s.Credentials,
		TLS: s.TLS, TLSServer: s.TLSServerName, Tier: s.Tier, Production: s.Production,
		Detectors: append([]string{}, s.Detectors...), CredentialsTTL: s.CredentialsTTL, VaultPath: s.VaultPath,
		WriteFunctions: s.WriteFunctions,
	}
	if s.Detectors == nil {
		r.Detectors = nil
	}
	if s.PIIRules != "" {
		set := s.PIIRules
		r.PIIRules = &set
	}
	if l := s.Limits; l != nil {
		r.Limits = rawLimits{StatementTimeout: l.StatementTimeout, ExplainRowsWarn: l.ExplainRowsWarn, ExplainRowsRefuse: l.ExplainRowsRefuse,
			MaxRows: l.MaxRows, MaxCellChars: l.MaxCellChars, MaxOutputBytes: l.MaxOutputBytes, ExplainCostRefuse: l.ExplainCostRefuse,
			KAnonymity: l.KAnonymity, ReferenceProbe: l.ReferenceProbe, IdleTimeout: l.IdleTimeout, MaxSession: l.MaxSession}
	}
	if h := s.SSH; h != nil {
		r.SSH = &rawSSH{Host: h.Host, Port: h.Port, User: h.User, Auth: h.Auth, Credentials: h.Credentials}
	}
	return r
}

// TOML writes f as a config file: header, then one table per profile,
// sorted, with only the keys a profile sets. Every string is quoted and
// escaped; values were checked for control characters on the way in, and
// the result is parsed again by the caller before it is written.
func (f *ConfigFile) TOML(header string) []byte {
	var b strings.Builder
	b.WriteString(header)
	for _, name := range f.Names() {
		r := f.profiles[name]
		fmt.Fprintf(&b, "\n[profiles.%s]\n", tomlQuote(name))
		str := func(k, v string) {
			if v != "" {
				fmt.Fprintf(&b, "%s = %s\n", k, tomlQuote(v))
			}
		}
		num := func(k string, v int64) {
			if v != 0 {
				fmt.Fprintf(&b, "%s = %d\n", k, v)
			}
		}
		str("engine", r.Engine)
		str("host", r.Host)
		str("path", r.Path)
		num("port", int64(r.Port))
		str("user", r.User)
		str("database", r.Database)
		str("credentials", r.Credentials)
		str("vault_path", r.VaultPath)
		str("credentials_ttl", r.CredentialsTTL)
		str("tls", r.TLS)
		str("tls_ca", r.TLSCA)
		str("tls_cert", r.TLSCert)
		str("tls_key", r.TLSKey)
		str("tls_server_name", r.TLSServer)
		str("tier", r.Tier)
		if r.Production {
			b.WriteString("production = true\n")
		}
		if r.Detectors != nil {
			q := make([]string, len(r.Detectors))
			for i, d := range r.Detectors {
				q[i] = tomlQuote(d)
			}
			fmt.Fprintf(&b, "detectors = [%s]\n", strings.Join(q, ", "))
		}
		if r.ProxyCmd != nil {
			q := make([]string, len(r.ProxyCmd))
			for i, a := range r.ProxyCmd {
				q[i] = tomlQuote(a)
			}
			fmt.Fprintf(&b, "proxy_command = [%s]\n", strings.Join(q, ", "))
		}
		if r.PIIRules != nil {
			fmt.Fprintf(&b, "pii_rules = %s\n", tomlQuote(*r.PIIRules))
		}
		str("write_functions", r.WriteFunctions)
		if l := r.Limits; l != (rawLimits{}) {
			fmt.Fprintf(&b, "\n[profiles.%s.limits]\n", tomlQuote(name))
			str("statement_timeout", l.StatementTimeout)
			num("explain_rows_warn", l.ExplainRowsWarn)
			num("explain_rows_refuse", l.ExplainRowsRefuse)
			num("max_rows", int64(l.MaxRows))
			num("max_cell_chars", int64(l.MaxCellChars))
			num("max_output_bytes", int64(l.MaxOutputBytes))
			if l.ExplainCostRefuse != 0 {
				fmt.Fprintf(&b, "explain_cost_refuse = %s\n", strconv.FormatFloat(l.ExplainCostRefuse, 'f', -1, 64))
			}
			num("k_anonymity", int64(l.KAnonymity))
			num("reference_probe", int64(l.ReferenceProbe))
			str("idle_timeout", l.IdleTimeout)
			str("max_session", l.MaxSession)
		}
		if h := r.SSH; h != nil {
			fmt.Fprintf(&b, "\n[profiles.%s.ssh]\n", tomlQuote(name))
			str("host", h.Host)
			num("port", int64(h.Port))
			str("user", h.User)
			str("auth", h.Auth)
			str("key", h.Key)
			str("credentials", h.Credentials)
		}
	}
	return []byte(b.String())
}

// tomlQuote is s as a TOML basic string. Control characters, refused
// before, are escaped anyway, so that no value can end its line.
func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
