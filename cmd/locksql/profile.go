package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidGodefroid/lockkit/verbs"
	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// containerHostGateway is the host a container reaches its own machine by
// (Docker Desktop, or --add-host=host.docker.internal:host-gateway).
const containerHostGateway = "host.docker.internal"

// profileAddUsage is the usage of `locksql profile add` (lockkit GUIDE §14).
const profileAddUsage = "locksql profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production]\n" +
	"                           [--credentials ask|vault [--vault-path P]]\n" +
	"                           --engine postgres|mysql|mariadb|sqlite (--path FILE | --host H [--port N] [--user U] [--database D] [--tls MODE])"

// flags registers the profile flags on fs.
func (s *profileSpec) flags(fs *flag.FlagSet) {
	fs.StringVar(&s.name, verbs.FlagProfile, "", "name of the profile to add (default dev)")
	fs.BoolVar(&s.production, verbs.FlagProduction, false, "a production profile (its name is typed for every approval)")
	fs.StringVar(&s.engine, "engine", "", "engine of the profile to add: "+strings.Join(setupEngines, ", "))
	fs.StringVar(&s.host, "host", "", "database host")
	fs.IntVar(&s.port, "port", 0, "database port")
	fs.StringVar(&s.user, "user", "", "database user (default: asked at console start)")
	fs.StringVar(&s.database, "database", "", "the only database served (default: chosen per query)")
	fs.StringVar(&s.path, "path", "", "SQLite file, relative to the project")
	fs.StringVar(&s.tls, "tls", "", "disable, prefer, require, verify-ca or verify-full (default verify-full for a remote host)")
	fs.StringVar(&s.credentials, verbs.FlagCredentials, "", "ask (the console asks at start) or vault")
	fs.StringVar(&s.vaultPath, verbs.FlagVaultPath, "", "Vault path of the login, with --credentials vault")
}

// profileWritten reports the profile added to the project's config on w.
func profileWritten(e env, w io.Writer, root string, s profileSpec) {
	p := e.paint
	from := "the console asks for the password"
	switch s.credentials {
	case config.CredentialsVault:
		from = "the console reads the login from Vault"
	case config.CredentialsKeychain:
		from = "the console reads the password from its keychain"
	}
	fmt.Fprintf(w, "Profile %s written to %s (no secret: %s).\n", s.name, configPath(root), from)
	switch {
	case s.engine == config.EngineSQLite:
		if _, err := os.Stat(filepath.Join(root, s.path)); err != nil {
			fmt.Fprintf(w, "%s %s does not exist yet: the console never creates it.\n", p.Yellow("note:"), filepath.Join(root, s.path))
		}
	case s.credentials == config.CredentialsVault:
		fmt.Fprintf(w, "%s the console reads the login with the vault CLI and asks for the Vault token at start (no vault login needed): set VAULT_ADDR in the console account's environment.\n", p.Yellow("note:"))
	}
}

// inContainer reports a process in a Docker or Podman container.
func (e env) inContainer() bool {
	if e.container != nil {
		return e.container()
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// verbFailure is the failure of a launcher verb: its exit code, its
// verbs.Error code and its message.
type verbFailure struct {
	exit int
	code string
	msg  string
}

// report prints f: on stderr, and as one verbs.Error on stdout with --json.
func (f verbFailure) report(e env, verb, usage string, asJSON bool) int {
	fmt.Fprintf(e.stderr, "locksql %s: %s\n", verb, f.msg)
	if f.code == verbs.CodeUsage && usage != "" {
		fmt.Fprintf(e.stderr, "usage: %s\n", usage)
	}
	if asJSON {
		_ = verbs.WriteJSON(e.stdout, verbs.Error{Lock: product.P.Name, Code: f.code, Error: f.msg})
	}
	return f.exit
}

func usageFailure(err error) *verbFailure {
	return &verbFailure{exit: exitUsage, code: verbs.ErrorCode(err, verbs.CodeUsage), msg: err.Error()}
}

// runProfile is `locksql profile add` (lockkit GUIDE §14): it adds one
// database profile to the project's .locksql/config.toml. On a terminal it
// asks for what the flags did not give; with --non-interactive it never
// reads the terminal and takes everything from the flags. No form takes,
// asks for or writes a secret: the console asks for the password at start,
// or reads it from Vault (or, from the interactive form, its keychain).
func runProfile(e env, args []string) int {
	if len(args) == 0 || args[0] != "add" {
		f := verbFailure{exit: exitUsage, code: verbs.CodeUsage, msg: "the only subcommand is add"}
		return f.report(e, "profile", profileAddUsage, verbs.WantsJSON(args))
	}
	args = args[1:]
	asJSON := verbs.WantsJSON(args)
	s, root, f := profileAdd(e, args, asJSON)
	if f != nil {
		return f.report(e, "profile add", profileAddUsage, asJSON)
	}
	if !asJSON {
		profileWritten(e, e.stdout, root, s)
		return exitOK
	}
	profileWritten(e, e.stderr, root, s)
	out := verbs.Profile{Lock: product.P.Name, Profile: s.name, Config: configPath(root), Production: s.production}
	if s.engine != config.EngineSQLite {
		out.Credentials = s.credentials
	}
	if err := verbs.WriteJSON(e.stdout, out); err != nil {
		fmt.Fprintf(e.stderr, "locksql profile add: %v\n", err)
		return exitFail
	}
	return exitOK
}

// profileAdd parses args, gets the profile (from the flags, or the wizard)
// and writes it. Human text goes to stderr with --json.
func profileAdd(e env, args []string, asJSON bool) (profileSpec, string, *verbFailure) {
	var s profileSpec
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	nonInteractive := fs.Bool(verbs.FlagNonInteractive, false, "never read the terminal; a missing value is a usage error")
	fs.Bool(verbs.FlagJSON, false, "print one line of JSON on stdout")
	project := fs.String(verbs.FlagProject, "", "project directory (default: the project of the current directory)")
	s.flags(fs)
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return s, "", usageFailure(err)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	out := e.stdout
	if asJSON {
		out = e.stderr
	}

	root := agentinit.ProjectRoot(e.cwd)
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return s, "", usageFailure(errors.New("--project: not a usable path"))
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return s, "", usageFailure(errors.New("--project: not a directory"))
		}
		root = abs
	}
	if !*nonInteractive && !e.tty {
		return s, "", usageFailure(errors.New("no terminal to ask on: run it in a terminal, or pass --non-interactive and the flags"))
	}
	existing, err := config.LoadFrom(root, "")
	if err != nil {
		return s, "", &verbFailure{exit: exitUsage, code: verbs.CodeFailed, msg: err.Error()}
	}
	if existing.ProjectRoot != root {
		existing.Profiles = nil // a config further up belongs to another project
	}
	exists := func(name string) *verbFailure {
		if _, dup := existing.Profiles[name]; !dup {
			return nil
		}
		return &verbFailure{exit: exitUsage, code: verbs.CodeExists,
			msg: fmt.Sprintf("profile %s is already in %s: nothing written", name, configPath(root))}
	}
	if given[verbs.FlagProfile] && setupNameRe.MatchString(s.name) {
		if f := exists(s.name); f != nil {
			return s, "", f
		}
	}

	if *nonInteractive {
		if s.engine == "" {
			return s, "", usageFailure(fmt.Errorf("--engine is required: %s", strings.Join(setupEngines, ", ")))
		}
		if s.engine != config.EngineSQLite {
			cred, err := verbs.Credentials(s.credentials, s.vaultPath)
			if err != nil {
				return s, "", usageFailure(err)
			}
			s.credentials = cred
		}
		if s, err = completeSpec(s); err != nil {
			return s, "", usageFailure(err)
		}
	} else {
		e.stdin = lineReader(e)
		if names := profileNames(existing); len(names) > 0 {
			fmt.Fprintf(out, "Profiles already in %s: %s\n", configPath(root), strings.Join(names, ", "))
		}
		if s, err = askProfile(e, out, root, s, given); err != nil {
			return s, "", &verbFailure{exit: exitFail, code: verbs.CodeFailed, msg: err.Error()}
		}
	}
	if f := exists(s.name); f != nil {
		return s, "", f
	}
	data, err := newConfig(root, s)
	if err != nil {
		return s, "", usageFailure(err)
	}
	if err := writeConfig(root, data); err != nil {
		return s, "", &verbFailure{exit: exitFail, code: verbs.CodeFailed, msg: err.Error()}
	}
	return s, root, nil
}
