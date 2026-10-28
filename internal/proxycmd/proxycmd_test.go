package proxycmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	case "pid":
		fmt.Println(os.Getpid())
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
