package proxycmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain turns the test binary into the proxied command when it is run
// with "proxycmd-helper <mode>": the environment is scrubbed, so the mode
// travels in argv.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "proxycmd-helper" {
		helper(os.Args[2])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string) {
	switch mode {
	case "echo":
		io.Copy(os.Stdout, os.Stdin)
	case "env":
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
	case "fail":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 4096)+"\nconnect: \x1b[2Jrefused\n")
		os.Exit(1)
	case "pwd":
		wd, _ := os.Getwd()
		fmt.Println(wd)
	case "pid":
		fmt.Println(os.Getpid())
		time.Sleep(time.Hour)
	case "tree":
		// A child that outlives nothing: closing the connection must end it
		// with the command.
		child := exec.Command(os.Args[0], "proxycmd-helper", "pid")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			fmt.Println(err)
			return
		}
		time.Sleep(time.Hour)
	case "orphan":
		// A child that leaves the command's process group with its stderr:
		// ending the command must not wait for it.
		child := exec.Command(os.Args[0], "proxycmd-helper", "pid")
		child.Stderr = os.Stderr
		if _, err := start(child); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(child.Process.Pid)
		fmt.Fprintln(os.Stderr, "orphaned")
		time.Sleep(time.Hour)
	case "tty":
		// A command run by the console must not reach its terminal.
		if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			f.Close()
			fmt.Println("tty")
		} else {
			fmt.Println("no tty")
		}
	}
}

func helperArgv(mode string) []string { return []string{os.Args[0], "proxycmd-helper", mode} }

func dial(t *testing.T, p *Proxy) net.Conn {
	t.Helper()
	c, err := p.Dial(context.Background(), "tcp", "db:3306")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestDialEcho(t *testing.T) {
	c := dial(t, New(helperArgv("echo")))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	if c.RemoteAddr() == nil || c.LocalAddr() == nil {
		t.Error("nil address")
	}
}

func TestDialDeadline(t *testing.T) {
	c := dial(t, New(helperArgv("echo")))
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestEnvScrubbed(t *testing.T) {
	t.Setenv("PGPASSWORD", "hunter2")
	t.Setenv("MYSQL_PWD", "hunter2")
	t.Setenv("VAULT_TOKEN", "s.abc")
	t.Setenv("LOCKSQL_SECRET", "x")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "x")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("DOCKER_HOST", "unix:///run/docker.sock")
	c := dial(t, New(helperArgv("env")))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	out, _ := io.ReadAll(c)
	env := string(out)
	for _, bad := range []string{"PGPASSWORD", "MYSQL_PWD", "VAULT_TOKEN", "LOCKSQL_SECRET", "AWS_SECRET_ACCESS_KEY", "hunter2"} {
		if strings.Contains(env, bad) {
			t.Errorf("%s reached the command", bad)
		}
	}
	for _, good := range []string{"PATH=", "SSH_AUTH_SOCK=/tmp/agent.sock", "DOCKER_HOST=unix:///run/docker.sock"} {
		if !strings.Contains(env, good) {
			t.Errorf("%s missing from %q", good, env)
		}
	}
}

func TestScrubEnv(t *testing.T) {
	got := scrubEnv([]string{"PATH=/bin", "HOME=/h", "PGPASSWORD=x", "KUBECONFIG=/k", "path=lower", "NOEQUALS"})
	if strings.Join(got, ",") != "PATH=/bin,HOME=/h,KUBECONFIG=/k" {
		t.Errorf("scrubEnv = %q", got)
	}
}

func TestStderrKeptSanitized(t *testing.T) {
	p := New(helperArgv("fail"))
	c := dial(t, p)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read from a failed command succeeded")
	}
	msg := p.Stderr()
	if !strings.Contains(msg, "refused") {
		t.Errorf("stderr = %q", msg)
	}
	if strings.ContainsRune(msg, '\x1b') || strings.ContainsRune(msg, '\n') {
		t.Errorf("stderr not sanitized: %q", msg)
	}
	if len(msg) > maxStderr+8 {
		t.Errorf("stderr is %d bytes", len(msg))
	}
}

func TestDialMissingProgram(t *testing.T) {
	_, err := New([]string{"locksql-no-such-program"}).Dial(context.Background(), "tcp", "db:1")
	if err == nil || !strings.Contains(err.Error(), "proxy_command") {
		t.Errorf("err = %v", err)
	}
}

func TestDialCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(helperArgv("echo")).Dial(ctx, "tcp", "db:1"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

// The command does not run in the console's working directory, the project,
// nor in its home, which may hold the project: a relative argument names a
// file in an empty directory of its own, removed when the command ends.
func TestRunsInEmptyDir(t *testing.T) {
	c := dial(t, New(helperArgv("pwd")))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	dir := strings.TrimSpace(line)
	for _, d := range []string{"", "."} {
		if p, _ := filepath.Abs(d); p == dir {
			t.Errorf("working directory = %q, the console's", dir)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && dir == home {
		t.Errorf("working directory = %q, the home", dir)
	}
	// Windows reports no Unix permission bits; MkdirTemp's directory there
	// inherits the user's temporary directory's ACL.
	if fi, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0) {
		t.Errorf("working directory %q: %v, %v", dir, fi, err)
	}
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q is still there after Close", dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// readPid reads the pid a helper prints on its first line.
func readPid(t *testing.T, c net.Conn) int {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("pid line %q: %v", line, err)
	}
	return pid
}

// waitGone fails t unless the process pid ends within 5 seconds.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d still runs", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Closing the connection ends the command and every process it started.
func TestCloseKillsTree(t *testing.T) {
	c := dial(t, New(helperArgv("tree")))
	pid := readPid(t, c)
	c.Close()
	waitGone(t, pid)
}
