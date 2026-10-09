package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// runInstall is `locksql install`: the one-time setup that separates the
// console from the agent. It prints the commands, which need root, and on
// Linux runs them with sudo once the human confirms.
func runInstall(e env, args []string) int {
	const usage = "locksql install [--client USER] [--user locksql] [--group locksql-clients] [--print]"
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	client := fs.String("client", "", "the account the agent runs as (default: you)")
	svc := fs.String("user", sysconf.DefaultServiceUser, "the console account to create")
	group := fs.String("group", sysconf.DefaultClientGroup, "the group allowed to reach the console")
	printOnly := fs.Bool("print", false, "print the commands, do not run them")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	if *client == "" {
		if s := os.Getenv("SUDO_USER"); s != "" {
			*client = s
		} else if u, err := user.Current(); err == nil {
			*client = u.Username
		}
	}
	for what, v := range map[string]string{"--client": *client, "--user": *svc, "--group": *group} {
		if !accountRe.MatchString(v) {
			fmt.Fprintf(e.stderr, "locksql install: invalid %s %q\n", what, v)
			return exitUsage
		}
	}
	if *client == *svc {
		fmt.Fprintln(e.stderr, "locksql install: the agent's account and the console account must differ")
		return exitUsage
	}
	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail
	}
	script := linuxInstallScript(bin, *client, *svc, *group)
	if runtime.GOOS == "darwin" {
		script = darwinInstallScript(bin, *client, *svc, *group)
	}
	fmt.Fprintf(e.stdout, `locksql install separates the console from the agent:
  - the console runs as %[1]q, in its own login session (use Wayland), and alone
    holds the database credentials (its keychain or its prompt);
  - the agent's account %[2]q joins group %[3]q, which may reach the console's
    socket; the kernel checks every connection;
  - locksql is copied to /usr/local/bin, owned by root, so that the agent cannot
    replace the binary the console runs.

These commands run as root:

%[4]s
`, *svc, *client, *group, indent(script))
	if *printOnly || runtime.GOOS != "linux" {
		if runtime.GOOS != "linux" {
			fmt.Fprintln(e.stdout, "Run them in a terminal as an administrator.")
		}
		return exitOK
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(e.stderr, "locksql install: confirm in a terminal, or run with --print")
		return exitUsage
	}
	fmt.Fprint(e.stdout, "Run them now with sudo? [y/N] ")
	ans, _ := bufio.NewReader(e.stdin).ReadString('\n')
	if strings.TrimSpace(ans) != "y" {
		fmt.Fprintln(e.stdout, "nothing done")
		return exitOK
	}
	cmd := exec.Command("sudo", "sh", "-c", script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, e.stdout, e.stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail
	}
	fmt.Fprintf(e.stdout, `
Done. Next:
  1. sudo passwd %[1]s            (a password for the console account)
  2. log out and in again as %[2]s (the new group applies at login)
  3. open a separate session as %[1]s (switch user, Wayland), then run there:
       locksql console --profile <name> --project <the agent's project dir>
  4. locksql doctor               (from both accounts)
`, *svc, *client)
	return exitOK
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n    ")
}

// shellQuote quotes s for sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func systemToml(svc, group, dir string) string {
	return fmt.Sprintf(`# locksql: the console runs as service_user; members of client_group reach it.
service_user = %q
client_group = %q
socket_dir   = %q
x11          = "refuse"
`, svc, group, dir)
}

func linuxInstallScript(bin, client, svc, group string) string {
	dir := "/run/locksql"
	return fmt.Sprintf(`set -eu
getent group %[3]s >/dev/null || groupadd --system %[3]s
id -u %[2]s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "locksql console" %[2]s
chmod 0700 "$(getent passwd %[2]s | cut -d: -f6)"
usermod -aG %[3]s %[1]s
install -m 0755 -o root -g root %[4]s /usr/local/bin/locksql
install -d -m 0755 -o root -g root /etc/locksql
cat > /etc/locksql/system.toml <<'LOCKSQL'
%[5]sLOCKSQL
chown root:root /etc/locksql/system.toml
chmod 0644 /etc/locksql/system.toml
printf 'd %[6]s 0710 %[2]s %[3]s -\n' > /etc/tmpfiles.d/locksql.conf
systemd-tmpfiles --create /etc/tmpfiles.d/locksql.conf 2>/dev/null || install -d -m 0710 -o %[2]s -g %[3]s %[6]s
`, client, svc, group, shellQuote(bin), systemToml(svc, group, dir), dir)
}

func darwinInstallScript(bin, client, svc, group string) string {
	dir := sysconf.DefaultSocketDir()
	return fmt.Sprintf(`set -eu
dseditgroup -o read %[3]s >/dev/null 2>&1 || dseditgroup -o create %[3]s
id -u %[2]s >/dev/null 2>&1 || sysadminctl -addUser %[2]s -fullName "locksql console" -password -
dseditgroup -o edit -a %[1]s -t user %[3]s
install -m 0755 -o root -g wheel %[4]s /usr/local/bin/locksql
install -d -m 0755 -o root -g wheel /etc/locksql
cat > /etc/locksql/system.toml <<'LOCKSQL'
%[5]sLOCKSQL
chown root:wheel /etc/locksql/system.toml
chmod 0644 /etc/locksql/system.toml
install -d -m 0755 -o root -g wheel /usr/local/var/run
install -d -m 0710 -o %[2]s -g %[3]s %[6]s
`, client, svc, group, shellQuote(bin), systemToml(svc, group, dir), dir)
}
