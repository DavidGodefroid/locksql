package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// profileSpec is the database profile `locksql profile add` writes. It never
// holds a secret: the console asks for the password.
type profileSpec struct {
	name, engine, host, user, database, path, credentials string
	tls, vaultPath                                        string
	port                                                  int
	production                                            bool
}

// setupEngines are the engines the wizard offers, the default first.
var setupEngines = []string{config.EngineSQLite, config.EnginePostgres, config.EngineMariaDB, config.EngineMySQL}

// setupNameRe is the wizard's profile names: a TOML bare key, so that the
// table header stays [profiles.NAME].
var setupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func configPath(root string) string { return filepath.Join(root, ".locksql", "config.toml") }

// completeSpec fills in the defaults of a profile and checks it. Its errors
// name the flag, never quote its value (a secret pasted in the wrong place).
func completeSpec(s profileSpec) (profileSpec, error) {
	if s.name == "" {
		s.name = "dev"
	}
	if !setupNameRe.MatchString(s.name) {
		return s, errors.New("--profile: letters, digits, - and _ only, starting with a letter or digit, at most 64")
	}
	if err := kconfig.CheckProfileName(s.name, s.production); err != nil {
		return s, fmt.Errorf("--profile: %v", err)
	}
	if !slices.Contains(setupEngines, s.engine) {
		return s, fmt.Errorf("--engine: want %s", strings.Join(setupEngines, ", "))
	}
	for _, f := range []struct{ flag, v string }{{"--host", s.host}, {"--user", s.user}, {"--database", s.database}, {"--path", s.path}, {"--vault-path", s.vaultPath}} {
		if strings.IndexFunc(f.v, unicode.IsControl) >= 0 || len(f.v) > 512 {
			return s, fmt.Errorf("%s: control characters or too long", f.flag)
		}
	}
	if s.engine == config.EngineSQLite {
		if s.host != "" || s.port != 0 || s.user != "" || s.database != "" || s.credentials != "" || s.tls != "" || s.vaultPath != "" {
			return s, errors.New("sqlite takes --path only (no --host, --port, --user, --database, --tls or --credentials)")
		}
		if s.path == "" {
			return s, errors.New("sqlite needs --path, the database file relative to the project")
		}
		return s, nil
	}
	if s.path != "" {
		return s, fmt.Errorf("--path is for sqlite; %s takes --host", s.engine)
	}
	if s.host == "" {
		s.host = "127.0.0.1"
	}
	if s.port == 0 {
		s.port = config.DefaultPort(s.engine)
	}
	if s.port < 1 || s.port > 65535 {
		return s, errors.New("--port: out of range (1 to 65535)")
	}
	switch s.credentials {
	case "":
		s.credentials = config.CredentialsAsk
	case config.CredentialsAsk, config.CredentialsKeychain:
	case config.CredentialsVault:
		if s.vaultPath == "" {
			return s, errors.New("--credentials vault needs --vault-path, such as database/creds/<role>")
		}
		if strings.HasPrefix(s.vaultPath, "-") || strings.HasPrefix(s.vaultPath, "/") || strings.IndexFunc(s.vaultPath, unicode.IsSpace) >= 0 {
			return s, errors.New("--vault-path: no spaces, and not starting with - or /")
		}
	default:
		return s, errors.New("--credentials: want ask, keychain or vault")
	}
	if s.vaultPath != "" && s.credentials != config.CredentialsVault {
		return s, errors.New("--vault-path needs --credentials vault")
	}
	if s.tls != "" && config.TLSRank(s.tls) < 0 {
		return s, errors.New("--tls: want disable, prefer, require, verify-ca or verify-full")
	}
	return s, nil
}

// askProfile is the profile wizard: it asks, on out, for what the flags
// did not give (given names the flags set, preset holds their values). A
// profile the flags got wrong is asked again whole. It asks for no secret.
func askProfile(e env, out io.Writer, root string, preset profileSpec, given map[string]bool) (profileSpec, error) {
	container := e.inContainer()
	var taken map[string]config.Profile
	if cfg, err := config.LoadFrom(root, ""); err == nil && cfg.ProjectRoot == root {
		taken = cfg.Profiles
	}
	br := lineReader(e)
	ask := func(label, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(out, "  %s [%s]: ", label, def)
		} else {
			fmt.Fprintf(out, "  %s: ", label)
		}
		l, err := br.ReadString('\n')
		if err != nil && l == "" {
			fmt.Fprintln(out)
			return "", errAborted
		}
		if l = strings.TrimSpace(l); l == "" {
			return def, nil
		}
		return l, nil
	}
	fmt.Fprintf(out, "The profile goes to %s, read by both accounts.\nIt never holds a password: the console asks for it, or reads it from its keychain or Vault.\n", configPath(root))
	for first := true; ; first = false {
		var s profileSpec
		if first {
			s = preset
		}
		// has reports a value the flags gave, used as is on the first round.
		has := func(flag string) bool { return first && given[flag] }
		askTo := func(dst *string, flag, label, def string) error {
			if has(flag) {
				return nil
			}
			v, err := ask(label, def)
			*dst = v
			return err
		}
		if err := askTo(&s.name, "profile", "Profile name", "dev"); err != nil {
			return s, err
		}
		if !has("production") {
			ans, err := ask("Production profile, approved by typing its name (y/N)", "n")
			if err != nil {
				return s, err
			}
			s.production = strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes")
		}
		if err := askTo(&s.engine, "engine", "Engine ("+strings.Join(setupEngines, ", ")+")", config.EngineSQLite); err != nil {
			return s, err
		}
		s.engine = strings.ToLower(s.engine)
		if s.engine == config.EngineSQLite {
			if err := askTo(&s.path, "path", "SQLite file, relative to the project", "app.db"); err != nil {
				return s, err
			}
		} else if slices.Contains(setupEngines, s.engine) {
			host := "127.0.0.1"
			if container {
				// Inside a container, 127.0.0.1 is the container itself.
				host = containerHostGateway
			}
			if err := askTo(&s.host, "host", "Host", host); err != nil {
				return s, err
			}
			if !has("port") {
				port, err := ask("Port", strconv.Itoa(config.DefaultPort(s.engine)))
				if err != nil {
					return s, err
				}
				if s.port, err = strconv.Atoi(port); err != nil {
					s.port = -1
				}
			}
			if err := askTo(&s.user, "user", "Database user (empty: asked at console start)", ""); err != nil {
				return s, err
			}
			if err := askTo(&s.database, "database", "Database (empty: every database the account sees)", ""); err != nil {
				return s, err
			}
			if !config.IsLoopback(s.host) {
				// A remote server's certificate is verified by default; a
				// server on this machine seldom has one.
				def := config.TLSVerifyFull
				if s.host == containerHostGateway {
					def = config.TLSPrefer
				}
				if err := askTo(&s.tls, "tls", "TLS (disable, prefer, require, verify-ca, verify-full)", def); err != nil {
					return s, err
				}
			}
			modes := []string{config.CredentialsAsk, config.CredentialsKeychain, config.CredentialsVault}
			if container {
				modes = []string{config.CredentialsAsk, config.CredentialsVault} // no keychain in a container
			}
			if err := askTo(&s.credentials, "credentials", "Password from ("+strings.Join(modes, ", ")+"; ask: typed at console start)", config.CredentialsAsk); err != nil {
				return s, err
			}
			s.credentials = strings.ToLower(s.credentials)
			if s.credentials == config.CredentialsVault {
				if err := askTo(&s.vaultPath, "vault-path", "Vault path of the login (username and password)", "database/creds/"+s.name); err != nil {
					return s, err
				}
			}
		}
		var err error
		if s, err = completeSpec(s); err == nil && container && s.credentials == config.CredentialsKeychain {
			err = errors.New("a container has no keychain: ask or vault")
		}
		if _, dup := taken[s.name]; err == nil && dup {
			err = fmt.Errorf("profile %s already exists", s.name)
		}
		if err == nil {
			return s, nil
		}
		fmt.Fprintf(out, "  %s %v; again:\n", e.paint.Red("invalid:"), err)
	}
}

// tomlString is s as a TOML basic string (s holds no control character).
func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// toml is the profile as a TOML table.
func (s profileSpec) toml() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[profiles.%s]\nengine = %s\n", s.name, tomlString(s.engine))
	if s.production {
		b.WriteString("production = true\n")
	}
	if s.engine == config.EngineSQLite {
		fmt.Fprintf(&b, "path = %s\n", tomlString(s.path))
		return b.String()
	}
	fmt.Fprintf(&b, "host = %s\nport = %d\n", tomlString(s.host), s.port)
	if s.user != "" {
		fmt.Fprintf(&b, "user = %s\n", tomlString(s.user))
	}
	if s.database != "" {
		fmt.Fprintf(&b, "database = %s\n", tomlString(s.database))
	}
	if s.tls != "" {
		fmt.Fprintf(&b, "tls = %s\n", tomlString(s.tls))
	}
	fmt.Fprintf(&b, "credentials = %s\n", tomlString(s.credentials))
	if s.vaultPath != "" {
		fmt.Fprintf(&b, "vault_path = %s\n", tomlString(s.vaultPath))
	}
	return b.String()
}

const setupConfigHeader = `# locksql project configuration, read by the console and by the agents.
# It never holds a secret: the console asks for the password, or reads it
# from its own keychain or Vault. See https://github.com/DavidGodefroid/locksql
`

// newConfig is the project's config with the profile appended (a new
// config when there is none); it must load, or it is an error.
func newConfig(root string, s profileSpec) ([]byte, error) {
	path := configPath(root)
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	data := setupConfigHeader
	if len(old) > 0 {
		data = string(old)
		if !strings.HasSuffix(data, "\n") {
			data += "\n"
		}
	}
	data += "\n" + s.toml()
	profiles, err := config.ParseProfiles([]byte(data), path, root)
	if err != nil {
		return nil, err
	}
	if _, ok := profiles[s.name]; !ok {
		return nil, fmt.Errorf("%s: profile %s not found after adding it", path, s.name)
	}
	return []byte(data), nil
}

// writeConfig writes data, from newConfig, as the project's config.
func writeConfig(root string, data []byte) error {
	path := configPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
