package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// profileSpec is the database profile the setup wizard writes. It never
// holds a secret: the console asks for the password.
type profileSpec struct {
	name, engine, host, user, database, path, credentials string
	tls, vaultPath                                        string
	port                                                  int
}

// setupEngines are the engines the wizard offers, the default first.
var setupEngines = []string{config.EngineSQLite, config.EnginePostgres, config.EngineMariaDB, config.EngineMySQL}

// setupNameRe is the wizard's profile names: a TOML bare key, so that the
// table header stays [profiles.NAME].
var setupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// runSetup is `locksql setup`: the separated install, the agents' wiring,
// a database profile for the project and the console account's access to
// it, then the one command that starts the console.
func runSetup(e env, args []string) int {
	const usage = "locksql setup [--project DIR] [--client USER] [--trust-binary] [--yes] [" + profileFlagsUsage + "]"
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "project directory (default: the project of the current directory)")
	client := fs.String("client", "", "the account the agents run as (default: you)")
	trust := fs.Bool("trust-binary", false, "as locksql install --trust-binary")
	yes := fs.Bool("yes", false, "run the root steps without asking (sudo may still ask for a password)")
	var s profileSpec
	s.flags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(e.stderr, "locksql setup: "+format+"\n", a...)
		return code
	}
	if code, failed := sysFail(e, " setup"); failed {
		return code
	}
	if _, service := isServiceAccount(e); service {
		return fail(exitUsage, "this is the console account; run setup from the account your agents run as")
	}
	if e.geteuid() == 0 {
		return fail(exitUsage, "run setup from your own account, not as root: it asks sudo for the steps that need root")
	}
	root := agentinit.ProjectRoot(e.cwd)
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return fail(exitUsage, "%v", err)
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return fail(exitUsage, "--project %s is not a directory", abs)
		}
		root = abs
	}
	given := s.engine != ""
	if !given && s.anySet() {
		return fail(exitUsage, "the profile flags need --engine")
	}
	if given {
		var err error
		if s, err = completeSpec(s); err != nil {
			return fail(exitUsage, "%v", err)
		}
	}
	existing, err := config.LoadFrom(root, "")
	if err != nil {
		return fail(exitUsage, "%v", err)
	}
	if existing.ProjectRoot != root {
		existing.Profiles = nil // a config further up belongs to another project
	}
	if given {
		if _, dup := existing.Profiles[s.name]; dup {
			return fail(exitUsage, "profile %q is already in %s", s.name, configPath(root))
		}
	}
	separated, _ := isServiceAccount(e)
	needProfile := given || len(existing.Profiles) == 0
	if !e.tty {
		if !*yes {
			return fail(exitUsage, "the steps that run as root ask for confirmation: run setup in a terminal, or with --yes")
		}
		if needProfile && !given {
			return fail(exitUsage, "no profile in %s: run setup in a terminal, or pass --engine and its flags", configPath(root))
		}
	}
	e.stdin = lineReader(e)
	p := e.paint

	fmt.Fprint(e.stdout, p.Banner(version))
	fmt.Fprintln(e.stdout)

	// 1. The agents of this account.
	fmt.Fprintln(e.stdout, p.Heading("1. Agents", 72))
	if found := wireAgents(e); len(found) == 0 {
		fmt.Fprintf(e.stdout, "No agent found (%s); install one, then run bare locksql to wire it.\n", strings.Join(agentinit.Agents(), ", "))
	} else {
		fmt.Fprintf(e.stdout, "Wired for your account: %s\n", strings.Join(found, ", "))
	}

	// 2. The console account.
	fmt.Fprintln(e.stdout, "\n"+p.Heading("2. Console account", 72))
	installed := false
	if separated {
		fmt.Fprintln(e.stdout, "Already set up (/etc/locksql/system.toml).")
	} else {
		fmt.Fprint(e.stdout, sameUserSteps+"\n")
		run := e.installer
		if run == nil {
			run = func(o installOpts) (int, bool) { return doInstall(e, o) }
		}
		code, ran := run(installOpts{client: *client, trustBinary: *trust, yes: *yes})
		if code != exitOK {
			return code
		}
		if !ran {
			fmt.Fprintln(e.stdout, "\nRun locksql setup again once these commands have run.")
			return exitOK
		}
		installed = true
		svc := consoleAccountName(e)
		if runtime.GOOS == "linux" && e.tty && !*yes && confirm(e, fmt.Sprintf("Set a password for %s now, to log in as it? [y/N] ", svc)) {
			if err := e.asRoot("passwd " + shellQuote(svc)); err != nil {
				fmt.Fprintf(e.stderr, "locksql setup: passwd: %v (later: sudo passwd %s)\n", err, svc)
			}
		}
	}

	// 3. The database profile.
	fmt.Fprintln(e.stdout, "\n"+p.Heading("3. Database profile", 72))
	if needProfile {
		if !given {
			if s, err = askProfile(e, root); err != nil {
				return fail(exitFail, "%v", err)
			}
		}
		if err := addProfile(root, s); err != nil {
			return fail(exitFail, "%v", err)
		}
		profileWritten(e, root, s)
	} else {
		names := profileNames(existing)
		fmt.Fprintf(e.stdout, "Kept the profiles of %s: %s\n", configPath(root), strings.Join(names, ", "))
	}

	// 4. The console account's access to the project.
	fmt.Fprintln(e.stdout, "\n"+p.Heading("4. Project access", 72))
	if code := setupAccess(e, root, *yes); code != exitOK {
		return code
	}

	a := consoleArgs{project: root}
	steps := ""
	if installed {
		steps = "  - log out and in again, so that your account's new group applies;\n"
	}
	fmt.Fprintf(e.stdout, `
%s The console runs as %s, in a session of its own:
%s  - open a session as %s (switch user on the desktop, or a text console with
    Ctrl-Alt-F3), run this there and keep it open:

      %s

Then ask your agent about the database: each query waits for your approval there.
`, p.Bold("Ready."), consoleAccountName(e), steps, consoleAccountName(e), p.Accent(a.command()))
	return exitOK
}

// consoleAccountName is the console account of the separated setup.
func consoleAccountName(e env) string {
	if sys, err := sysConfig(e); err == nil && sys != nil {
		return sys.ServiceUser
	}
	return "locksql"
}

// setupAccess gives the console account what it needs in the project:
// the checks of locksql doctor, and their repairs.
func setupAccess(e env, root string, yes bool) int {
	sys, err := sysConfig(e)
	if err != nil || sys == nil {
		return exitOK
	}
	d := realDoctorEnv()
	if e.doc != nil {
		d = *e.doc
	}
	me, err := d.current()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql setup:", err)
		return exitFail
	}
	uid, _ := strconv.Atoi(me.Uid)
	svc, _ := consoleAccount(d, sys, uid)
	if svc.uid < 0 {
		fmt.Fprintf(e.stderr, "locksql setup: the console account %s does not exist; run locksql doctor\n", sys.ServiceUser)
		return exitFail
	}
	checks := projectChecks(d, root, svc, uid)
	if _, code := applyRepairs(e, "setup", checks, yes); code != exitOK {
		return code
	}
	failed := false
	for _, c := range projectChecks(d, root, svc, uid) {
		if c.state == checkOK {
			continue
		}
		failed = true
		fmt.Fprintf(e.stdout, "%s — %s\n  → %s\n", e.paint.Fail(e.paint.Bold(c.title)), c.detail, c.fix)
	}
	if failed {
		return exitFail
	}
	fmt.Fprintf(e.stdout, "%s can read %s and write its .locksql directory.\n", svc.name, root)
	return exitOK
}

func configPath(root string) string { return filepath.Join(root, ".locksql", "config.toml") }

// completeSpec fills in the defaults of a profile given by flags and
// checks it.
func completeSpec(s profileSpec) (profileSpec, error) {
	if s.name == "" {
		s.name = "dev"
	}
	if !setupNameRe.MatchString(s.name) {
		return s, fmt.Errorf("profile name %q: letters, digits, - and _ only", s.name)
	}
	if !slices.Contains(setupEngines, s.engine) {
		return s, fmt.Errorf("engine %q: want %s", s.engine, strings.Join(setupEngines, ", "))
	}
	for what, v := range map[string]string{"host": s.host, "user": s.user, "database": s.database, "path": s.path, "vault path": s.vaultPath} {
		if strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) }) >= 0 || len(v) > 512 {
			return s, fmt.Errorf("%s: control characters or too long", what)
		}
	}
	if s.engine == config.EngineSQLite {
		if s.host != "" || s.port != 0 || s.user != "" || s.database != "" || s.credentials != "" || s.tls != "" || s.vaultPath != "" {
			return s, errors.New("sqlite takes --path only")
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
		return s, fmt.Errorf("port %d out of range", s.port)
	}
	switch s.credentials {
	case "":
		s.credentials = config.CredentialsAsk
	case config.CredentialsAsk, config.CredentialsKeychain:
	case config.CredentialsVault:
		if s.vaultPath == "" {
			return s, errors.New("credentials vault needs the vault path, such as database/creds/<role>")
		}
		if strings.HasPrefix(s.vaultPath, "-") || strings.HasPrefix(s.vaultPath, "/") || strings.IndexFunc(s.vaultPath, unicode.IsSpace) >= 0 {
			return s, fmt.Errorf("vault path %q: no spaces, and not starting with - or /", s.vaultPath)
		}
	default:
		return s, fmt.Errorf("credentials %q: want ask, keychain or vault", s.credentials)
	}
	if s.vaultPath != "" && s.credentials != config.CredentialsVault {
		return s, errors.New("a vault path needs credentials vault")
	}
	if s.tls != "" && config.TLSRank(s.tls) < 0 {
		return s, fmt.Errorf("tls %q: want disable, prefer, require, verify-ca or verify-full", s.tls)
	}
	return s, nil
}

// askProfile is the profile wizard. It asks for no secret.
func askProfile(e env, root string) (profileSpec, error) {
	container := e.inContainer()
	var taken map[string]config.Profile
	if cfg, err := config.LoadFrom(root, ""); err == nil && cfg.ProjectRoot == root {
		taken = cfg.Profiles
	}
	br := lineReader(e)
	ask := func(label, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(e.stdout, "  %s [%s]: ", label, def)
		} else {
			fmt.Fprintf(e.stdout, "  %s: ", label)
		}
		l, err := br.ReadString('\n')
		if err != nil && l == "" {
			fmt.Fprintln(e.stdout)
			return "", errAborted
		}
		if l = strings.TrimSpace(l); l == "" {
			return def, nil
		}
		return l, nil
	}
	fmt.Fprintf(e.stdout, "The profile goes to %s, read by both accounts.\nIt never holds a password: the console asks for it, or reads it from its keychain or Vault.\n", configPath(root))
	for {
		var s profileSpec
		var err error
		if s.name, err = ask("Profile name", "dev"); err != nil {
			return s, err
		}
		if s.engine, err = ask("Engine ("+strings.Join(setupEngines, ", ")+")", config.EngineSQLite); err != nil {
			return s, err
		}
		s.engine = strings.ToLower(s.engine)
		if s.engine == config.EngineSQLite {
			if s.path, err = ask("SQLite file, relative to the project", "app.db"); err != nil {
				return s, err
			}
		} else if slices.Contains(setupEngines, s.engine) {
			host := "127.0.0.1"
			if container {
				// Inside a container, 127.0.0.1 is the container itself.
				host = containerHostGateway
			}
			if s.host, err = ask("Host", host); err != nil {
				return s, err
			}
			port, err := ask("Port", strconv.Itoa(config.DefaultPort(s.engine)))
			if err != nil {
				return s, err
			}
			if s.port, err = strconv.Atoi(port); err != nil {
				s.port = -1
			}
			if s.user, err = ask("Database user (empty: asked at console start)", ""); err != nil {
				return s, err
			}
			if s.database, err = ask("Database (empty: every database the account sees)", ""); err != nil {
				return s, err
			}
			if !config.IsLoopback(s.host) {
				// A remote server's certificate is verified by default; a
				// server on this machine seldom has one.
				def := config.TLSVerifyFull
				if s.host == containerHostGateway {
					def = config.TLSPrefer
				}
				if s.tls, err = ask("TLS (disable, prefer, require, verify-ca, verify-full)", def); err != nil {
					return s, err
				}
			}
			modes := []string{config.CredentialsAsk, config.CredentialsKeychain, config.CredentialsVault}
			if container {
				modes = []string{config.CredentialsAsk, config.CredentialsVault} // no keychain in a container
			}
			cred, err := ask("Password from ("+strings.Join(modes, ", ")+"; ask: typed at console start)", config.CredentialsAsk)
			if err != nil {
				return s, err
			}
			s.credentials = strings.ToLower(cred)
			if s.credentials == config.CredentialsVault {
				if s.vaultPath, err = ask("Vault path of the login (username and password)", "database/creds/"+s.name); err != nil {
					return s, err
				}
			}
		}
		if s, err = completeSpec(s); err == nil && container && s.credentials == config.CredentialsKeychain {
			err = errors.New("a container has no keychain: ask or vault")
		}
		if _, dup := taken[s.name]; err == nil && dup {
			err = fmt.Errorf("profile %s already exists", s.name)
		}
		if err == nil {
			return s, nil
		}
		fmt.Fprintf(e.stdout, "  %s %v; again:\n", e.paint.Red("invalid:"), err)
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

// addProfile appends the profile to the project's config, creating it
// when absent; the result must load, or nothing is written.
func addProfile(root string, s profileSpec) error {
	path := configPath(root)
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
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
		return err
	}
	if _, ok := profiles[s.name]; !ok {
		return fmt.Errorf("%s: profile %s not found after writing it", path, s.name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0o644)
}
