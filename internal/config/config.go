// Package config loads locksql profiles from the project and user config
// files, applies defaults, refuses anything that looks like a secret, and
// computes the security-relevant policy of a profile.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
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
	// on a PII column or an aggregate of one may cover.
	KAnonymity int `toml:"k_anonymity" json:"k_anonymity,omitempty"`
	// ReferenceProbe is how many distinct cells of one result the agent may
	// filter on, one statement each, before the console warns of equality
	// probing; raising it is a loosening.
	ReferenceProbe int `toml:"reference_probe" json:"reference_probe,omitempty"`
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
}

// Config is the merged set of profiles visible from a working directory.
type Config struct {
	// ProjectRoot is the directory holding .locksql/config.toml, or "" when
	// no project config was found.
	ProjectRoot string
	Profiles    map[string]Profile
}

const (
	projectDir  = ".locksql"
	configFile  = "config.toml"
	appDirName  = "locksql"
	maxNameSize = 64
)

var profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// secretWords are refused as config key names, or as a "_"/"-" separated
// part of one, at any depth.
var secretWords = map[string]bool{"password": true, "passwd": true, "pwd": true, "secret": true, "token": true}

// Load reads the project config (found by walking up from cwd) and the user
// config (<user config dir>/locksql/config.toml). On a profile name present
// in both, the project profile wins as a whole.
func Load(cwd string) (*Config, error) {
	userPath, _ := UserConfigPath()
	return LoadFrom(cwd, userPath)
}

// UserConfigPath returns <user config dir>/locksql/config.toml.
func UserConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, appDirName, configFile), nil
}

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
		profiles, err := loadFile(filepath.Join(root, projectDir, configFile), root)
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
func FindProjectRoot(cwd string) (string, bool) {
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", false
	}
	for {
		st, err := os.Stat(filepath.Join(dir, projectDir, configFile))
		if err == nil && st.Mode().IsRegular() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// ProjectKey names the project of cwd in socket paths: ProjectHash of the
// project root, or "user" when cwd is outside any project (profiles from
// the user config only). The console and its clients must agree on it.
func ProjectKey(cwd string) string {
	if root, ok := FindProjectRoot(cwd); ok {
		return ProjectHash(root)
	}
	return "user"
}

// ProjectHash returns the first 8 hex digits of sha256 of the absolute,
// cleaned project root.
func ProjectHash(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:8]
}

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
	SSH         *rawSSH   `toml:"ssh"`
	Tier        string    `toml:"tier"`
	Production  bool      `toml:"production"`
	Detectors   []string  `toml:"detectors"`
	Limits      rawLimits `toml:"limits"`
	// CredentialsTTL is a duration ("20m", "1h").
	CredentialsTTL string `toml:"credentials_ttl"`
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
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, sanitizeDecodeError(name, err)
	}
	for _, key := range md.Keys() {
		if secretKey(key) {
			return nil, fmt.Errorf("config: %s: key %q looks like a secret; locksql never reads secrets from config files (the console asks for them)", name, key.String())
		}
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("config: %s: unknown key %q", name, und[0].String())
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

func sanitizeDecodeError(path string, err error) error {
	var pe toml.ParseError
	if errors.As(err, &pe) {
		if pe.LastKey != "" && !secretKey(strings.Split(pe.LastKey, ".")) {
			return fmt.Errorf("config: %s: invalid TOML at line %d (key %q)", path, pe.Position.Line, pe.LastKey)
		}
		return fmt.Errorf("config: %s: invalid TOML at line %d", path, pe.Position.Line)
	}
	// Type errors from decoding into known keys name the key and the types,
	// never the value. Secret-looking keys are never decoded.
	return fmt.Errorf("config: %s: invalid TOML: %s", path, strings.TrimPrefix(err.Error(), "toml: "))
}

func secretKey(key toml.Key) bool {
	for _, part := range key {
		for _, word := range strings.FieldsFunc(strings.ToLower(part), func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
			if secretWords[word] {
				return true
			}
		}
	}
	return false
}

// embedsPassword reports whether s looks like a DSN carrying a password:
// user:pw@host, scheme://user:pw@host, or a keyword DSN with password=.
func embedsPassword(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "password=") || strings.Contains(lower, "pwd=") {
		return true
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return false
	}
	return strings.Contains(s[:at], ":")
}

// approvalWords are answers too common to serve as the name typed to approve
// a production statement.
var approvalWords = map[string]bool{"y": true, "yes": true, "n": true, "no": true, "ok": true}

// unsafeRune reports a character that could alter or hide text on a
// terminal: a control character (C0, DEL, C1), an invalid byte or a format
// character such as a bidi override.
func unsafeRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func buildProfile(name string, r rawProfile, detectorsSet bool, baseDir string) (Profile, error) {
	if len(name) > maxNameSize || !profileNameRe.MatchString(name) {
		return Profile{}, fmt.Errorf("invalid profile name %q: use letters, digits, '_', '-' or '.', starting with a letter or digit", name)
	}
	errf := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{name}, a...)...)
	}
	for _, f := range []struct{ key, val string }{{"host", r.Host}, {"path", r.Path}, {"user", r.User}, {"database", r.Database}, {"tls_ca", r.TLSCA}} {
		if embedsPassword(f.val) {
			return Profile{}, errf("%s looks like a DSN with an embedded password; locksql never reads secrets from config files", f.key)
		}
		// These values are shown to the human in approval screens and
		// policy diffs, where terminal escapes could hide a change.
		if strings.IndexFunc(f.val, unsafeRune) >= 0 {
			return Profile{}, errf("%s holds a control or formatting character", f.key)
		}
	}
	if r.Production && (len(name) < 2 || approvalWords[strings.ToLower(name)]) {
		// Production statements are approved by typing the profile name,
		// which must not be an everyday answer such as "y".
		return Profile{}, errf("a production profile needs a name of 2 characters or more that is not y, yes, n, no or ok")
	}

	p := Profile{
		Name: name, Engine: r.Engine, Host: r.Host, Path: r.Path, Port: r.Port,
		User: r.User, Database: r.Database, Credentials: r.Credentials,
		TLS: r.TLS, TLSCA: r.TLSCA,
		Production: r.Production, Detectors: r.Detectors,
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
	if p.Engine == EngineSQLite && (p.TLS != "" || p.TLSCA != "") {
		return Profile{}, errf("tls and tls_ca are not used by sqlite")
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
	default:
		return Profile{}, errf("unknown credentials mode %q (want ask or keychain)", p.Credentials)
	}
	for _, d := range p.Detectors {
		if !knownDetectors[d] {
			return Profile{}, errf("unknown detector %q", d)
		}
	}

	if r.Limits.StatementTimeout != "" {
		d, err := time.ParseDuration(r.Limits.StatementTimeout)
		if err != nil {
			return Profile{}, errf("limits.statement_timeout: invalid duration %q", r.Limits.StatementTimeout)
		}
		p.Limits.StatementTimeout = d
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
	if p.Production && TLSRank(p.TLS) < TLSRank(TLSRequire) && !strings.HasPrefix(p.Host, "/") && !IsLoopback(p.Host) {
		return Profile{}, errf("a production profile on a remote host needs tls = \"require\" or stronger, or an ssh tunnel to the database's own host")
	}
	if p.Limits.ExplainRowsWarn > p.Limits.ExplainRowsRefuse {
		return Profile{}, errf("limits.explain_rows_warn (%d) is above limits.explain_rows_refuse (%d)", p.Limits.ExplainRowsWarn, p.Limits.ExplainRowsRefuse)
	}
	return p, nil
}

func resolveSQLitePath(path, baseDir string) string {
	if path == ":memory:" || strings.HasPrefix(path, "file:") || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// TLS modes of a network profile, as libpq's sslmode, in increasing
// strength.
const (
	TLSDisable    = "disable"
	TLSPrefer     = "prefer"
	TLSRequire    = "require"
	TLSVerifyCA   = "verify-ca"
	TLSVerifyFull = "verify-full"
)

var tlsModes = []string{TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull}

// TLSRank orders TLS modes by strength. "" is prefer, the mode of profiles
// approved before the setting existed; an unknown mode ranks -1.
func TLSRank(mode string) int {
	if mode == "" {
		mode = TLSPrefer
	}
	return slices.Index(tlsModes, mode)
}

// TLSVerifiesChain reports a tls mode that verifies the server's certificate
// chain: verify-ca and verify-full, and require with tls_ca, as libpq.
func TLSVerifiesChain(mode, ca string) bool {
	return TLSRank(mode) >= TLSRank(TLSVerifyCA) || (mode == TLSRequire && ca != "")
}

// IsLoopback reports a host that names this machine: "localhost" or a
// loopback IP literal. Any other name, even one that resolves to loopback,
// is remote.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SSH authentication methods.
const (
	SSHAuthKey      = "key"
	SSHAuthAgent    = "agent"
	SSHAuthPassword = "password"
)

// SSHProfile is the bastion a network profile is reached through. Host and
// Port of the profile are then seen from the bastion. It never holds a
// secret: a key passphrase or an SSH password follows Credentials.
type SSHProfile struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Auth        string `json:"auth"`
	Key         string `json:"key,omitempty"`
	Credentials string `json:"credentials"`
}

type rawSSH struct {
	Host        string `toml:"host"`
	Port        int    `toml:"port"`
	User        string `toml:"user"`
	Auth        string `toml:"auth"`
	Key         string `toml:"key"`
	Credentials string `toml:"credentials"`
}

func buildSSH(r rawSSH, p Profile, errf func(string, ...any) error) (*SSHProfile, error) {
	if p.Engine == EngineSQLite {
		return nil, errf("ssh is not used by sqlite")
	}
	if strings.HasPrefix(p.Host, "/") {
		return nil, errf("ssh needs a TCP host; forwarding to a Unix socket is not supported")
	}
	for _, f := range []struct{ key, val string }{{"ssh.host", r.Host}, {"ssh.user", r.User}, {"ssh.key", r.Key}} {
		if embedsPassword(f.val) {
			return nil, errf("%s looks like a DSN with an embedded password; locksql never reads secrets from config files", f.key)
		}
		if strings.IndexFunc(f.val, unsafeRune) >= 0 {
			return nil, errf("%s holds a control or formatting character", f.key)
		}
	}
	switch {
	case r.Host == "":
		return nil, errf("ssh.host is required")
	case r.User == "":
		return nil, errf("ssh.user is required")
	case r.Port < 0 || r.Port > 65535:
		return nil, errf("ssh.port %d out of range", r.Port)
	}
	switch r.Auth {
	case SSHAuthKey:
		if r.Key == "" {
			return nil, errf("ssh.key is required with ssh.auth = \"key\"")
		}
	case SSHAuthAgent, SSHAuthPassword:
		if r.Key != "" {
			return nil, errf("ssh.key is only used with ssh.auth = \"key\"")
		}
	default:
		return nil, errf("ssh.auth must be key, agent or password")
	}
	switch r.Credentials {
	case "", CredentialsAsk, CredentialsKeychain:
	default:
		return nil, errf("unknown ssh.credentials mode %q (want ask or keychain)", r.Credentials)
	}
	s := &SSHProfile{Host: r.Host, Port: r.Port, User: r.User, Auth: r.Auth, Key: r.Key, Credentials: r.Credentials}
	if s.Port == 0 {
		s.Port = 22
	}
	if s.Credentials == "" {
		s.Credentials = p.Credentials
		if s.Credentials == "" {
			s.Credentials = CredentialsAsk
		}
	}
	return s, nil
}
