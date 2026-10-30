package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

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
// the console account would run, could have been changed by an account
// other than root: run from the agent's account, a binary the agent
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
	return fmt.Sprintf("%s is owned by %s and could have been replaced by the agent (sha256 %s)\n", bin, owner, sum), nil
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

// installedBinary is where the binary the console runs is installed.
const installedBinary = "/usr/local/bin/locksql"
