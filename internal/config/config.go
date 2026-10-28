// Package config loads locksql profiles from the project and user config
// files, applies defaults, refuses anything that looks like a secret, and
// computes the security-relevant policy of a profile.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locksql/internal/product"
)

// Tier is the highest statement class a profile may run.
// The order is TierRead < TierWrite < TierDDL < TierAdmin.
type Tier int

// Tiers, in increasing order of privilege.
const (
	TierRead Tier = iota
	TierWrite
	TierDDL
	TierAdmin
)

var tierNames = [...]string{"read", "write", "ddl", "admin"}

// ParseTier parses "read", "write", "ddl" or "admin".
func ParseTier(s string) (Tier, error) {
	for i, n := range tierNames {
		if s == n {
			return Tier(i), nil
		}
	}
	return TierRead, fmt.Errorf("unknown tier %q (want read, write, ddl or admin)", s)
}

func (t Tier) String() string {
	if t >= 0 && int(t) < len(tierNames) {
		return tierNames[t]
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

// MarshalText encodes the tier by name.
func (t Tier) MarshalText() ([]byte, error) {
	if t < 0 || int(t) >= len(tierNames) {
		return nil, fmt.Errorf("invalid tier %d", int(t))
	}
	return []byte(t.String()), nil
}

// UnmarshalText decodes a tier name.
func (t *Tier) UnmarshalText(b []byte) error {
	v, err := ParseTier(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// Limits bound the cost and size of one statement.
type Limits struct {
	StatementTimeout  time.Duration `toml:"statement_timeout" json:"statement_timeout"`
	ExplainRowsWarn   int64         `toml:"explain_rows_warn" json:"explain_rows_warn"`
	ExplainRowsRefuse int64         `toml:"explain_rows_refuse" json:"explain_rows_refuse"`
	MaxRows           int           `toml:"max_rows" json:"max_rows"`
	MaxCellChars      int           `toml:"max_cell_chars" json:"max_cell_chars"`
	MaxOutputBytes    int           `toml:"max_output_bytes" json:"max_output_bytes"`
	// ExplainCostRefuse refuses a plan whose total cost, in the engine's
	// own units, is above it; 0 disables the check. Engines without a cost
	// (SQLite) are not checked.
	ExplainCostRefuse float64 `toml:"explain_cost_refuse" json:"explain_cost_refuse,omitempty"`
	// KAnonymity is the smallest number of rows a PII filter, a grouping
	// on a PII column or an aggregate of one may cover without a warning
	// on the approval screen.
	KAnonymity int `toml:"k_anonymity" json:"k_anonymity,omitempty"`
	// ReferenceProbe is how many distinct cells of one result the agent may
	// filter on, one statement each, before the console warns of equality
	// probing; raising it is a loosening.
	ReferenceProbe int `toml:"reference_probe" json:"reference_probe,omitempty"`
	// IdleTimeout ends the console session after that long without
	// activity, MaxSession after that long in all; raising either is a
	// loosening. Bounds: 1m <= IdleTimeout <= MaxSession <= 24h.
	IdleTimeout time.Duration `toml:"idle_timeout" json:"idle_timeout,omitempty"`
	MaxSession  time.Duration `toml:"max_session" json:"max_session,omitempty"`
}

// Profile is one named database target with its policy.
// It never holds a secret.
type Profile struct {
	Name        string `json:"name"`
	Engine      string `json:"engine"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	User        string `json:"user"`
	Database    string `json:"database"`
	Credentials string `json:"credentials"`
	// TLS is the transport mode (TLSDisable ... TLSVerifyFull) and TLSCA an
	// optional PEM bundle that replaces the system roots.
	TLS   string `json:"tls,omitempty"`
	TLSCA string `json:"tls_ca,omitempty"`
	// TLSCert and TLSKey are the PEM files of a client certificate and its
	// private key, presented when the server asks for one. TLSServerName
	// replaces host as the name verify-full checks in the certificate.
	TLSCert       string `json:"tls_cert,omitempty"`
	TLSKey        string `json:"tls_key,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	// SSH, when set, is the bastion the profile is reached through.
	SSH        *SSHProfile `json:"ssh,omitempty"`
	Port       int         `json:"port"`
	Tier       Tier        `json:"tier"`
	Production bool        `json:"production"`
	Detectors  []string    `json:"detectors"`
	Limits     Limits      `json:"limits"`
	// CredentialsTTL makes the console ask for the secret again (and
	// reconnect) once the connection is that old; 0 keeps it for the
	// session. It suits short-lived secrets from a vault.
	CredentialsTTL time.Duration `json:"credentials_ttl,omitempty"`
	// VaultPath is the Vault path read for the login when Credentials is
	// "vault", such as "database/creds/app-readonly".
	VaultPath string `json:"vault_path,omitempty"`
	// PIIRules names the PII rule set of the profile: the file
	// pii/<set>.toml next to the config. The config holds the pii_rules
	// key, "" when it is not set; the console stores the set it resolved
	// (RuleSetOf, or the migrated default set) in the policy it approves.
	PIIRules string `json:"pii_rules,omitempty"`
	// WriteFunctions is "" (the denylist of every class) or
	// WriteFunctionsAllowlist: writes may call allowlisted functions only.
	WriteFunctions string `json:"write_functions,omitempty"`
}

// ruleSetRe is a valid PII rule set name: it becomes a file name, so no
// path separator, no leading dot, and lower case so that two names never
// meet in one file on a case-insensitive file system.
var ruleSetRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// ValidRuleSet reports whether s may name a PII rule set.
func ValidRuleSet(s string) bool { return ruleSetRe.MatchString(s) }

// RuleSetOf is the PII rule set of p from its config: pii_rules, or the
// profile name in lower case. Sharing a set is opt-in.
func RuleSetOf(p Profile) string {
	if p.PIIRules != "" {
		return p.PIIRules
	}
	return strings.ToLower(p.Name)
}

// Values of write_functions. The default, denylist, is stored as "" so that
// policies approved before the setting existed keep their fingerprint.
const (
	WriteFunctionsDenylist  = "denylist"
	WriteFunctionsAllowlist = "allowlist"
)

// Config is the merged set of profiles visible from a working directory.
type Config struct {
	// ProjectRoot is the directory holding .locksql/config.toml, or "" when
	// no project config was found.
	ProjectRoot string
	Profiles    map[string]Profile
}

// Load reads the project config (found by walking up from cwd) and the user
// config (<user config dir>/locksql/config.toml). On a profile name present
// in both, the project profile wins as a whole.
func Load(cwd string) (*Config, error) {
	userPath, _ := UserConfigPath()
	return LoadFrom(cwd, userPath)
}

// UserConfigPath returns <user config dir>/locksql/config.toml.
func UserConfigPath() (string, error) { return kconfig.UserConfigPath(product.P) }

// LoadFrom is Load with an explicit user config path ("" for none).
// A missing user config file is not an error.
func LoadFrom(cwd, userConfigPath string) (*Config, error) {
	cfg := &Config{Profiles: map[string]Profile{}}
	if userConfigPath != "" {
		profiles, err := loadFile(userConfigPath, filepath.Dir(userConfigPath))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for name, p := range profiles {
			cfg.Profiles[name] = p
		}
	}
	if root, ok := FindProjectRoot(cwd); ok {
		profiles, err := loadFile(kconfig.ProjectConfigPath(product.P, root), root)
		if err != nil {
			return nil, err
		}
		cfg.ProjectRoot = root
		for name, p := range profiles {
			cfg.Profiles[name] = p
		}
	}
	return cfg, nil
}

// FindProjectRoot walks up from cwd to the first directory holding
// .locksql/config.toml.
func FindProjectRoot(cwd string) (string, bool) { return kconfig.FindProjectRoot(product.P, cwd) }

// ProjectKey names the project of cwd in socket paths: ProjectHash of the
// project root, or "user" when cwd is outside any project (profiles from
// the user config only). The console and its clients must agree on it.
func ProjectKey(cwd string) string { return kconfig.ProjectKey(product.P, cwd) }

// ProjectHash returns the first 8 hex digits of sha256 of the absolute,
// cleaned project root.
func ProjectHash(root string) string { return kconfig.ProjectHash(root) }

type rawLimits struct {
	StatementTimeout  string  `toml:"statement_timeout"`
	ExplainRowsWarn   int64   `toml:"explain_rows_warn"`
	ExplainRowsRefuse int64   `toml:"explain_rows_refuse"`
	MaxRows           int     `toml:"max_rows"`
	MaxCellChars      int     `toml:"max_cell_chars"`
	MaxOutputBytes    int     `toml:"max_output_bytes"`
	ExplainCostRefuse float64 `toml:"explain_cost_refuse"`
	KAnonymity        int     `toml:"k_anonymity"`
	ReferenceProbe    int     `toml:"reference_probe"`
	IdleTimeout       string  `toml:"idle_timeout"`
	MaxSession        string  `toml:"max_session"`
}

type rawProfile struct {
	Engine      string    `toml:"engine"`
	Host        string    `toml:"host"`
	Path        string    `toml:"path"`
	Port        int       `toml:"port"`
	User        string    `toml:"user"`
	Database    string    `toml:"database"`
	Credentials string    `toml:"credentials"`
	TLS         string    `toml:"tls"`
	TLSCA       string    `toml:"tls_ca"`
	TLSCert     string    `toml:"tls_cert"`
	TLSKey      string    `toml:"tls_key"`
	TLSServer   string    `toml:"tls_server_name"`
	SSH         *rawSSH   `toml:"ssh"`
	Tier        string    `toml:"tier"`
	Production  bool      `toml:"production"`
	Detectors   []string  `toml:"detectors"`
	Limits      rawLimits `toml:"limits"`
	// CredentialsTTL is a duration ("20m", "1h").
	CredentialsTTL string `toml:"credentials_ttl"`
	VaultPath      string `toml:"vault_path"`
	// PIIRules is nil when the key is absent: "" is refused.
	PIIRules       *string `toml:"pii_rules"`
	WriteFunctions string  `toml:"write_functions"`
}

type rawFile struct {
	Profiles map[string]rawProfile `toml:"profiles"`
}

// loadFile decodes one config file; see ParseProfiles.
func loadFile(path, baseDir string) (map[string]Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return ParseProfiles(data, path, baseDir)
}

// ParseProfiles decodes and validates config data. name labels errors.
// Relative sqlite paths are resolved against baseDir. Errors never quote
// config values that could be secrets.
func ParseProfiles(data []byte, name, baseDir string) (map[string]Profile, error) {
	var raw rawFile
	md, err := kconfig.Decode(product.P, data, name, &raw)
	if err != nil {
		return nil, err
	}

	out := make(map[string]Profile, len(raw.Profiles))
	names := make([]string, 0, len(raw.Profiles))
	for pn := range raw.Profiles {
		names = append(names, pn)
	}
	sort.Strings(names)
	for _, pn := range names {
		p, err := buildProfile(pn, raw.Profiles[pn], md.IsDefined("profiles", pn, "detectors"), baseDir)
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", name, err)
		}
		out[pn] = p
	}
	return out, nil
}

func buildProfile(name string, r rawProfile, detectorsSet bool, baseDir string) (Profile, error) {
	if err := kconfig.CheckProfileName(name, false); err != nil {
		return Profile{}, err
	}
	errf := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{name}, a...)...)
	}
	for _, f := range []struct{ key, val string }{{"host", r.Host}, {"path", r.Path}, {"user", r.User}, {"database", r.Database}, {"tls_ca", r.TLSCA},
		{"tls_cert", r.TLSCert}, {"tls_key", r.TLSKey}, {"tls_server_name", r.TLSServer}, {"vault_path", r.VaultPath}} {
		// These values are shown to the human in approval screens and
		// policy diffs, where terminal escapes could hide a change.
		if err := kconfig.CheckValue(product.P, f.key, f.val); err != nil {
			return Profile{}, errf("%v", err)
		}
	}
	if err := kconfig.CheckProfileName(name, r.Production); err != nil {
		return Profile{}, errf("%v", err)
	}
	var ruleSet string
	if r.PIIRules != nil {
		if ruleSet = *r.PIIRules; !ValidRuleSet(ruleSet) {
			return Profile{}, errf("pii_rules: want 1 to 64 lower-case letters, digits, '_', '-' or '.', starting with a letter or digit")
		}
	}

	p := Profile{
		Name: name, Engine: r.Engine, Host: r.Host, Path: r.Path, Port: r.Port,
		User: r.User, Database: r.Database, Credentials: r.Credentials, VaultPath: r.VaultPath,
		TLS: r.TLS, TLSCA: r.TLSCA, TLSCert: r.TLSCert, TLSKey: r.TLSKey, TLSServerName: r.TLSServer,
		Production: r.Production, Detectors: r.Detectors, PIIRules: ruleSet,
		Limits: Limits{
			ExplainRowsWarn: r.Limits.ExplainRowsWarn, ExplainRowsRefuse: r.Limits.ExplainRowsRefuse,
			MaxRows: r.Limits.MaxRows, MaxCellChars: r.Limits.MaxCellChars, MaxOutputBytes: r.Limits.MaxOutputBytes,
			ExplainCostRefuse: r.Limits.ExplainCostRefuse, KAnonymity: r.Limits.KAnonymity,
			ReferenceProbe: r.Limits.ReferenceProbe,
		},
	}

	switch p.Engine {
	case EngineMariaDB, EngineMySQL, EnginePostgres:
		if p.Host == "" {
			return Profile{}, errf("engine %s needs host", p.Engine)
		}
		if p.Path != "" {
			return Profile{}, errf("path is only used by sqlite; set host instead")
		}
	case EngineSQLite:
		if p.Path == "" {
			return Profile{}, errf("engine sqlite needs path")
		}
		if p.Host != "" || p.Port != 0 {
			return Profile{}, errf("host and port are not used by sqlite; set path instead")
		}
		p.Path = resolveSQLitePath(p.Path, baseDir)
	case "":
		return Profile{}, errf("engine is required (mariadb, mysql, postgres or sqlite)")
	default:
		return Profile{}, errf("unknown engine %q (want mariadb, mysql, postgres or sqlite)", p.Engine)
	}
	if p.Port < 0 || p.Port > 65535 {
		return Profile{}, errf("port %d out of range", p.Port)
	}
	if p.Engine == EngineSQLite && (p.TLS != "" || p.TLSCA != "" || p.TLSCert != "" || p.TLSKey != "" || p.TLSServerName != "") {
		return Profile{}, errf("tls, tls_ca, tls_cert, tls_key and tls_server_name are not used by sqlite")
	}
	if (p.TLSCert == "") != (p.TLSKey == "") {
		return Profile{}, errf("tls_cert and tls_key go together: set both, or neither")
	}
	if p.TLSServerName != "" && !kconfig.ValidServerName(p.TLSServerName) {
		return Profile{}, errf("tls_server_name: want a DNS name or an IP address")
	}
	if p.TLS != "" && TLSRank(p.TLS) < 0 {
		return Profile{}, errf("unknown tls mode %q (want disable, prefer, require, verify-ca or verify-full)", p.TLS)
	}
	socket := strings.HasPrefix(p.Host, "/")
	if socket && TLSRank(p.TLS) > TLSRank(TLSPrefer) {
		return Profile{}, errf("tls %q needs a TCP host; a Unix socket is not encrypted", p.TLS)
	}

	if r.Tier != "" {
		t, err := ParseTier(r.Tier)
		if err != nil {
			return Profile{}, errf("%v", err)
		}
		p.Tier = t
	}
	switch p.Credentials {
	case "", CredentialsAsk, CredentialsKeychain:
		if p.VaultPath != "" {
			return Profile{}, errf("vault_path is only used with credentials = \"vault\"")
		}
	case CredentialsVault:
		if p.Engine == EngineSQLite {
			return Profile{}, errf("credentials = \"vault\" is not used by sqlite")
		}
		if p.VaultPath == "" {
			return Profile{}, errf("credentials = \"vault\" needs vault_path, such as \"database/creds/<role>\"")
		}
		// The path is an argument of the vault CLI: it must not read as a
		// flag. The CLI checks it again (secrets.CheckVaultPath).
		if strings.HasPrefix(p.VaultPath, "-") || strings.HasPrefix(p.VaultPath, "/") || strings.IndexFunc(p.VaultPath, unicode.IsSpace) >= 0 {
			return Profile{}, errf("vault_path: want a path such as \"database/creds/<role>\", without spaces and not starting with '-' or '/'")
		}
	default:
		return Profile{}, errf("unknown credentials mode %q (want ask, keychain or vault)", p.Credentials)
	}
	switch r.WriteFunctions {
	case "", WriteFunctionsDenylist:
	case WriteFunctionsAllowlist:
		p.WriteFunctions = WriteFunctionsAllowlist
	default:
		return Profile{}, errf("unknown write_functions mode %q (want denylist or allowlist)", r.WriteFunctions)
	}
	for _, d := range p.Detectors {
		if !knownDetectors[d] {
			return Profile{}, errf("unknown detector %q", d)
		}
	}

	for _, f := range []struct {
		key, val string
		dst      *time.Duration
	}{
		{"statement_timeout", r.Limits.StatementTimeout, &p.Limits.StatementTimeout},
		{"idle_timeout", r.Limits.IdleTimeout, &p.Limits.IdleTimeout},
		{"max_session", r.Limits.MaxSession, &p.Limits.MaxSession},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil {
			return Profile{}, errf("limits.%s: invalid duration %q", f.key, f.val)
		}
		*f.dst = d
	}
	if r.CredentialsTTL != "" {
		d, err := time.ParseDuration(r.CredentialsTTL)
		if err != nil || d < time.Minute {
			return Profile{}, errf("credentials_ttl: want a duration of at least 1m, such as \"20m\" or \"1h\"")
		}
		p.CredentialsTTL = d
	}
	if r.Limits.ExplainCostRefuse < 0 {
		return Profile{}, errf("limits.explain_cost_refuse must not be negative")
	}
	for _, f := range []struct {
		key string
		val int64
	}{
		{"statement_timeout", int64(p.Limits.StatementTimeout)},
		{"explain_rows_warn", p.Limits.ExplainRowsWarn},
		{"explain_rows_refuse", p.Limits.ExplainRowsRefuse},
		{"max_rows", int64(p.Limits.MaxRows)},
		{"max_cell_chars", int64(p.Limits.MaxCellChars)},
		{"max_output_bytes", int64(p.Limits.MaxOutputBytes)},
		{"k_anonymity", int64(p.Limits.KAnonymity)},
		{"reference_probe", int64(p.Limits.ReferenceProbe)},
		{"idle_timeout", int64(p.Limits.IdleTimeout)},
		{"max_session", int64(p.Limits.MaxSession)},
	} {
		if f.val < 0 {
			return Profile{}, errf("limits.%s must not be negative", f.key)
		}
	}

	if r.SSH != nil {
		s, err := buildSSH(*r.SSH, p, errf)
		if err != nil {
			return Profile{}, err
		}
		p.SSH = s
	}

	applyDefaults(&p, detectorsSet)
	// After the defaults: a remote host without tls is verify-full.
	if p.TLSCA != "" && TLSRank(p.TLS) < TLSRank(TLSRequire) {
		return Profile{}, errf("tls_ca needs tls = \"require\", \"verify-ca\" or \"verify-full\"")
	}
	if p.TLSCert != "" && TLSRank(p.TLS) < TLSRank(TLSRequire) {
		return Profile{}, errf("tls_cert needs tls = \"require\", \"verify-ca\" or \"verify-full\"")
	}
	if p.TLSServerName != "" && p.TLS != TLSVerifyFull {
		return Profile{}, errf("tls_server_name needs tls = \"verify-full\", the only mode that checks the name")
	}
	if p.Production && TLSRank(p.TLS) < TLSRank(TLSRequire) && !strings.HasPrefix(p.Host, "/") && !IsLoopback(p.Host) {
		return Profile{}, errf("a production profile on a remote host needs tls = \"require\" or stronger, or an ssh tunnel to the database's own host")
	}
	if p.Limits.ExplainRowsWarn > p.Limits.ExplainRowsRefuse {
		return Profile{}, errf("limits.explain_rows_warn (%d) is above limits.explain_rows_refuse (%d)", p.Limits.ExplainRowsWarn, p.Limits.ExplainRowsRefuse)
	}
	switch l := p.Limits; {
	case l.MaxSession < MinIdleTimeout || l.MaxSession > MaxMaxSession:
		return Profile{}, errf("limits.max_session (%s) must be between %s and %s", l.MaxSession, MinIdleTimeout, MaxMaxSession)
	case l.IdleTimeout < MinIdleTimeout:
		return Profile{}, errf("limits.idle_timeout (%s) is below %s", l.IdleTimeout, MinIdleTimeout)
	case l.IdleTimeout > l.MaxSession:
		return Profile{}, errf("limits.idle_timeout (%s) is above limits.max_session (%s)", l.IdleTimeout, l.MaxSession)
	}
	return p, nil
}

func resolveSQLitePath(path, baseDir string) string {
	if path == ":memory:" || strings.HasPrefix(path, "file:") || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func buildSSH(r rawSSH, p Profile, errf func(string, ...any) error) (*SSHProfile, error) {
	if p.Engine == EngineSQLite {
		return nil, errf("ssh is not used by sqlite")
	}
	if strings.HasPrefix(p.Host, "/") {
		return nil, errf("ssh needs a TCP host; forwarding to a Unix socket is not supported")
	}
	return kconfig.ParseSSH(product.P, r, p.Credentials, errf)
}
