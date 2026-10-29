package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/agentinit"
	"github.com/DavidGodefroid/locksql/internal/config"
)

// containerHostGateway is the host a container reaches its own machine by
// (Docker Desktop, or --add-host=host.docker.internal:host-gateway).
const containerHostGateway = "host.docker.internal"

// profileFlagsUsage is the profile flags of setup and profile add.
const profileFlagsUsage = "--profile NAME --engine E (--path FILE | --host H [--port N] [--user U] [--database D] [--tls MODE] [--credentials ask|keychain|vault [--vault-path P]])"

// flags registers the profile flags on fs.
func (s *profileSpec) flags(fs *flag.FlagSet) {
	fs.StringVar(&s.name, "profile", "", "name of the profile to add (default dev)")
	fs.StringVar(&s.engine, "engine", "", "engine of the profile to add: "+strings.Join(setupEngines, ", "))
	fs.StringVar(&s.host, "host", "", "database host")
	fs.IntVar(&s.port, "port", 0, "database port")
	fs.StringVar(&s.user, "user", "", "database user (default: asked at console start)")
	fs.StringVar(&s.database, "database", "", "the only database served (default: chosen per query)")
	fs.StringVar(&s.path, "path", "", "SQLite file, relative to the project")
	fs.StringVar(&s.tls, "tls", "", "disable, prefer, require, verify-ca or verify-full (default verify-full for a remote host)")
	fs.StringVar(&s.credentials, "credentials", "", "ask, keychain or vault")
	fs.StringVar(&s.vaultPath, "vault-path", "", "Vault path of the login, with --credentials vault")
}

// anySet reports a profile flag given.
func (s profileSpec) anySet() bool {
	return s != (profileSpec{})
}

// profileWritten reports the profile added to the project's config.
func profileWritten(e env, root string, s profileSpec) {
	p := e.paint
	from := "the console asks for the password"
	if s.credentials == config.CredentialsVault {
		from = "the console reads the login from Vault"
	}
	fmt.Fprintf(e.stdout, "Profile %s written to %s (no secret: %s).\n", s.name, configPath(root), from)
	switch {
	case s.engine == config.EngineSQLite:
		if _, err := os.Stat(filepath.Join(root, s.path)); err != nil {
			fmt.Fprintf(e.stdout, "%s %s does not exist yet: the console never creates it.\n", p.Yellow("note:"), filepath.Join(root, s.path))
		}
	case s.credentials == config.CredentialsVault:
		fmt.Fprintf(e.stdout, "%s the console reads the login with the vault CLI and asks for the Vault token at start (no vault login needed): set VAULT_ADDR in the console account's environment.\n", p.Yellow("note:"))
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

// runProfile is `locksql profile add`: the database profile step of setup
// alone. It suits a console that runs in a container (docs/docker.md),
// where the account and access steps of setup do not apply.
func runProfile(e env, args []string) int {
	const usage = "locksql profile add [--project DIR] [" + profileFlagsUsage + "]"
	if len(args) == 0 || args[0] != "add" {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "project directory (default: the project of the current directory)")
	var s profileSpec
	s.flags(fs)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(e.stderr, "locksql profile add: "+format+"\n", a...)
		return code
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
	if !given && !e.tty {
		return fail(exitUsage, "run it in a terminal, or pass --engine and its flags")
	}
	existing, err := config.LoadFrom(root, "")
	if err != nil {
		return fail(exitUsage, "%v", err)
	}
	if existing.ProjectRoot != root {
		existing.Profiles = nil // a config further up belongs to another project
	}
	if given {
		if s, err = completeSpec(s); err != nil {
			return fail(exitUsage, "%v", err)
		}
	} else {
		e.stdin = lineReader(e)
		if names := profileNames(existing); len(names) > 0 {
			fmt.Fprintf(e.stdout, "Profiles already in %s: %s\n", configPath(root), strings.Join(names, ", "))
		}
		if s, err = askProfile(e, root); err != nil {
			return fail(exitFail, "%v", err)
		}
	}
	if _, dup := existing.Profiles[s.name]; dup {
		return fail(exitUsage, "profile %q is already in %s", s.name, configPath(root))
	}
	if err := addProfile(root, s); err != nil {
		return fail(exitFail, "%v", err)
	}
	profileWritten(e, root, s)
	return exitOK
}
