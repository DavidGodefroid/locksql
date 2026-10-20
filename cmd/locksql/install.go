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

	"github.com/DavidGodefroid/locksql/internal/product"
)

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// installOpts are the settings of `locksql install`.
type installOpts struct {
	client, svc, group string
	printOnly          bool
	trustBinary        bool
	// yes runs the root commands without asking (sudo may still ask for
	// a password); it works without a terminal.
	yes bool
}

// runInstall is `locksql install`: the one-time setup that separates the
// console from the agent. It prints the commands, which need root, and on
// Linux runs them with sudo once the human confirms.
func runInstall(e env, args []string) int {
	const usage = "locksql install [--client USER] [--user locksql] [--group locksql-clients] [--print] [--trust-binary] [--yes]"
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o installOpts
	fs.StringVar(&o.client, "client", "", "the account the agent runs as (default: you)")
	fs.StringVar(&o.svc, "user", product.P.Account, "the console account to create")
	fs.StringVar(&o.group, "group", product.P.ClientsGroup, "the group allowed to reach the console")
	fs.BoolVar(&o.printOnly, "print", false, "print the commands, do not run them")
	fs.BoolVar(&o.trustBinary, "trust-binary", false, "copy this binary even when another account than root can change it")
	fs.BoolVar(&o.yes, "yes", false, "run the commands without asking")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	code, ran := doInstall(e, o)
	if code != exitOK || !ran {
		return code
	}
	fmt.Fprintf(e.stdout, `
Done. Next:
  1. sudo passwd %[1]s            (a password for the console account)
  2. log out and in again as %[2]s (the new group applies at login)
  3. open a separate session as %[1]s (switch user, Wayland), then run there:
       locksql console --profile <name> --project <the agent's project dir>
  4. locksql doctor               (from both accounts)
`, o.svc, o.client)
	return exitOK
}

// installClient fills in the default agent account: the account sudo was
// run from, else this one.
func installClient(o *installOpts) {
	if o.client != "" {
		return
	}
	if s := os.Getenv("SUDO_USER"); s != "" {
		o.client = s
	} else if u, err := user.Current(); err == nil {
		o.client = u.Username
	}
}

// doInstall prints the root script of a separated install and, on Linux,
// runs it once the human confirms (or o.yes). ran reports whether it ran.
func doInstall(e env, o installOpts) (code int, ran bool) {
	if o.svc == "" {
		o.svc = product.P.Account
	}
	if o.group == "" {
		o.group = product.P.ClientsGroup
	}
	installClient(&o)
	for what, v := range map[string]string{"--client": o.client, "--user": o.svc, "--group": o.group} {
		if !accountRe.MatchString(v) {
			fmt.Fprintf(e.stderr, "locksql install: invalid %s %q\n", what, v)
			return exitUsage, false
		}
	}
	if o.client == o.svc {
		fmt.Fprintln(e.stderr, "locksql install: the agent's account and the console account must differ")
		return exitUsage, false
	}
	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail, false
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail, false
	}
	// pin is the sha256 the root script checks its copy against: with
	// --trust-binary, the binary could change between this check and the
	// script's copy.
	pin := ""
	if o.trustBinary {
		if pin, err = fileSum(bin); err != nil {
			fmt.Fprintln(e.stderr, "locksql install:", err)
			return exitFail, false
		}
		fmt.Fprintf(e.stdout, "--trust-binary: copying %s (sha256 %s, checked again before it is installed)\n\n", bin, pin)
	} else if msg, err := installSourceRefusal(bin); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail, false
	} else if msg != "" {
		fmt.Fprint(e.stderr, msg)
		return exitFail, false
	}
	script := linuxInstallScript(bin, o.client, o.svc, o.group, pin)
	if runtime.GOOS == "darwin" {
		script = darwinInstallScript(bin, o.client, o.svc, o.group, pin)
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
`, o.svc, o.client, o.group, indent(script))
	if o.printOnly || runtime.GOOS != "linux" {
		if runtime.GOOS != "linux" {
			fmt.Fprintln(e.stdout, "Run them in a terminal as an administrator.")
		}
		return exitOK, false
	}
	if !o.yes {
		if !e.tty {
			fmt.Fprintln(e.stderr, "locksql install: confirm in a terminal, or run with --print or --yes")
			return exitUsage, false
		}
		if !confirm(e, "Run them now with sudo? [y/N] ") {
			fmt.Fprintln(e.stdout, "nothing done")
			return exitOK, false
		}
	}
	if err := e.asRoot(script); err != nil {
		fmt.Fprintln(e.stderr, "locksql install:", err)
		return exitFail, false
	}
	return exitOK, true
}

// confirm asks a y/N question on e's terminal.
func confirm(e env, question string) bool {
	fmt.Fprint(e.stdout, question)
	ans, _ := lineReader(e).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(ans), "y")
}

// lineReader is e.stdin as a buffered reader; it reuses e.stdin when it is
// one already, so that successive questions lose no buffered input.
func lineReader(e env) *bufio.Reader {
	if br, ok := e.stdin.(*bufio.Reader); ok {
		return br
	}
	return bufio.NewReader(e.stdin)
}

// asRoot runs a shell script as root: through e.root when set (tests),
// else sudo sh -c on the human's terminal, or sh -c when this already is
// root (a container run with --user 0, which has no sudo). The script holds
// no secret.
func (e env) asRoot(script string) error {
	if e.root != nil {
		return e.root(script)
	}
	cmd := exec.Command("sudo", "sh", "-c", script)
	if e.geteuid() == 0 {
		cmd = exec.Command("sh", "-c", script)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, e.stdout, e.stderr
	return cmd.Run()
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
// mismatch with a message prefixed by cmd ("locksql install"); src is the
// file to install. Without a pin, bin itself is the source: install refused
// it unless root owns it and alone may write it.
func pinnedSource(cmd, bin, pin, sumCmd string) (prefix, src string) {
	if pin == "" {
		return "", shellQuote(bin)
	}
	return fmt.Sprintf(`tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat %s > "$tmp"
echo '%s  '"$tmp" | %s >/dev/null 2>&1 || { echo '%s: the binary changed since its sha256 was printed; nothing installed' >&2; exit 1; }
`, shellQuote(bin), pin, sumCmd, cmd), `"$tmp"`
}

// linuxInstallScript sets up a separated install on Linux. The socket
// directory is setgid: the console's account is not in the client group, and
// Linux lets it give its socket only to a group it belongs to or to the one
// the socket already has, which setgid makes the client group.
func linuxInstallScript(bin, client, svc, group, pin string) string {
	dir := "/run/locksql"
	prefix, src := pinnedSource("locksql install", bin, pin, "sha256sum -c -")
	return fmt.Sprintf(`set -eu
%[7]sgetent group %[3]s >/dev/null || groupadd --system %[3]s
id -u %[2]s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "locksql console" %[2]s
chmod 0700 "$(getent passwd %[2]s | cut -d: -f6)"
usermod -aG %[3]s %[1]s
%[4]sinstall -d -m 0755 -o root -g root /etc/locksql
cat > /etc/locksql/system.toml <<'LOCKSQL'
%[5]sLOCKSQL
chown root:root /etc/locksql/system.toml
chmod 0644 /etc/locksql/system.toml
install -d -m 0755 -o root -g root /etc/tmpfiles.d
printf 'd %[6]s 2710 %[2]s %[3]s -\n' > /etc/tmpfiles.d/locksql.conf
systemd-tmpfiles --create /etc/tmpfiles.d/locksql.conf 2>/dev/null || install -d -m 2710 -o %[2]s -g %[3]s %[6]s
`, client, svc, group, copyBinary(bin, pin, src, "root"), systemToml(svc, group, dir), dir, prefix)
}

// installedBinary is where install puts the binary the console runs.
const installedBinary = "/usr/local/bin/locksql"

// copyBinary is the script line that installs src as installedBinary, or
// nothing when the running binary is that file already (a release
// installed by scripts/install.sh, or a second install): install(1)
// refuses to copy a file onto itself, and installSourceRefusal has checked
// that root alone may change it.
func copyBinary(bin, pin, src, group string) string {
	if pin == "" && bin == installedBinary {
		return ""
	}
	return fmt.Sprintf("install -m 0755 -o root -g %s %s %s\n", group, src, installedBinary)
}

func darwinInstallScript(bin, client, svc, group, pin string) string {
	dir := product.P.SharedSocketDir()
	prefix, src := pinnedSource("locksql install", bin, pin, "shasum -a 256 -c -")
	return fmt.Sprintf(`set -eu
%[7]sdseditgroup -o read %[3]s >/dev/null 2>&1 || dseditgroup -o create %[3]s
id -u %[2]s >/dev/null 2>&1 || sysadminctl -addUser %[2]s -fullName "locksql console" -password -
dseditgroup -o edit -a %[1]s -t user %[3]s
%[4]sinstall -d -m 0755 -o root -g wheel /etc/locksql
cat > /etc/locksql/system.toml <<'LOCKSQL'
%[5]sLOCKSQL
chown root:wheel /etc/locksql/system.toml
chmod 0644 /etc/locksql/system.toml
install -d -m 0755 -o root -g wheel /usr/local/var/run
install -d -m 0710 -o %[2]s -g %[3]s %[6]s
`, client, svc, group, copyBinary(bin, pin, src, "wheel"), systemToml(svc, group, dir), dir, prefix)
}
