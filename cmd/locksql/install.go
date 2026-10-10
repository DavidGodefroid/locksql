package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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
	const usage = "locksql install [--client USER] [--user locksql] [--group locksql-clients] [--print] [--trust-binary]"
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	client := fs.String("client", "", "the account the agent runs as (default: you)")
	svc := fs.String("user", sysconf.DefaultServiceUser, "the console account to create")
	group := fs.String("group", sysconf.DefaultClientGroup, "the group allowed to reach the console")
	printOnly := fs.Bool("print", false, "print the commands, do not run them")
	trustBinary := fs.Bool("trust-binary", false, "copy this binary even when another account than root can change it")
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
	// pin is the sha256 the root script checks its copy against: with
	// --trust-binary, the binary could change between this check and the
	// script's copy.
	pin := ""
	if *trustBinary {
		if pin, err = fileSum(bin); err != nil {
			fmt.Fprintln(e.stderr, "locksql install:", err)
			return exitFail
		}
		fmt.Fprintf(e.stdout, "--trust-binary: copying %s (sha256 %s, checked again before it is installed)\n\n", bin, pin)
	} else if msg, err := installSourceRefusal(bin); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail
	} else if msg != "" {
		fmt.Fprint(e.stderr, msg)
		return exitFail
	}
	script := linuxInstallScript(bin, *client, *svc, *group, pin)
	if runtime.GOOS == "darwin" {
		script = darwinInstallScript(bin, *client, *svc, *group, pin)
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
	if !strings.EqualFold(strings.TrimSpace(ans), "y") {
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

// installSourceRefusal returns the refusal to print when bin, the binary
// install would copy to /usr/local/bin as root, could have been changed by an
// account other than root: run from the agent's account, a binary the agent
// replaced (a go install into ~/go/bin) would become the one the console
// trusts. It returns "" for a root-owned binary that neither group nor others
// may write.
func installSourceRefusal(bin string) (string, error) {
	fi, err := os.Stat(bin)
	if err != nil {
		return "", err
	}
	uid, _, ok := fileOwner(fi)
	if ok && uid == 0 && fi.Mode().Perm()&0o022 == 0 {
		return "", nil
	}
	owner := "an unknown account"
	if ok {
		owner = fmt.Sprintf("uid %d", uid)
		if u, err := user.LookupId(fmt.Sprint(uid)); err == nil {
			owner = u.Username
		}
	}
	if ok && uid == 0 {
		owner = "root but writable by group or others"
	}
	sum, err := fileSum(bin)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`locksql install: %s is owned by %s and could have been replaced by the agent;
install a release into a root-owned directory (scripts/install.sh with the default /usr/local/bin),
or pass --trust-binary to copy this one (sha256 %s).
`, bin, owner, sum), nil
}

// fileSum is the hex sha256 of the file at path.
func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

// pinnedSource is the start of a root script that copies bin to a root-owned
// temporary file and checks it against the sha256 pin (sumCmd checks a
// "<sha256>  <path>" line on stdin), aborting before any change on a
// mismatch; src is the file to install. Without a pin, bin itself is the
// source: install refused it unless root owns it and alone may write it.
func pinnedSource(bin, pin, sumCmd string) (prefix, src string) {
	if pin == "" {
		return "", shellQuote(bin)
	}
	return fmt.Sprintf(`tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat %s > "$tmp"
echo '%s  '"$tmp" | %s >/dev/null 2>&1 || { echo 'locksql install: the binary changed since its sha256 was printed; nothing installed' >&2; exit 1; }
`, shellQuote(bin), pin, sumCmd), `"$tmp"`
}

// linuxInstallScript sets up a separated install on Linux. The socket
// directory is setgid: the console's account is not in the client group, and
// Linux lets it give its socket only to a group it belongs to or to the one
// the socket already has, which setgid makes the client group.
func linuxInstallScript(bin, client, svc, group, pin string) string {
	dir := "/run/locksql"
	prefix, src := pinnedSource(bin, pin, "sha256sum -c -")
	return fmt.Sprintf(`set -eu
%[7]sgetent group %[3]s >/dev/null || groupadd --system %[3]s
id -u %[2]s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "locksql console" %[2]s
chmod 0700 "$(getent passwd %[2]s | cut -d: -f6)"
usermod -aG %[3]s %[1]s
install -m 0755 -o root -g root %[4]s /usr/local/bin/locksql
install -d -m 0755 -o root -g root /etc/locksql
cat > /etc/locksql/system.toml <<'LOCKSQL'
%[5]sLOCKSQL
chown root:root /etc/locksql/system.toml
chmod 0644 /etc/locksql/system.toml
install -d -m 0755 -o root -g root /etc/tmpfiles.d
printf 'd %[6]s 2710 %[2]s %[3]s -\n' > /etc/tmpfiles.d/locksql.conf
systemd-tmpfiles --create /etc/tmpfiles.d/locksql.conf 2>/dev/null || install -d -m 2710 -o %[2]s -g %[3]s %[6]s
`, client, svc, group, src, systemToml(svc, group, dir), dir, prefix)
}

func darwinInstallScript(bin, client, svc, group, pin string) string {
	dir := sysconf.DefaultSocketDir()
	prefix, src := pinnedSource(bin, pin, "shasum -a 256 -c -")
	return fmt.Sprintf(`set -eu
%[7]sdseditgroup -o read %[3]s >/dev/null 2>&1 || dseditgroup -o create %[3]s
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
`, client, svc, group, src, systemToml(svc, group, dir), dir, prefix)
}
