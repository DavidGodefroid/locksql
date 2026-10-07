//go:build integration && linux

package integration

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// buildLocksql builds the binary once per test binary.
var buildLocksql = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "ls-bin-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "locksql")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/DavidGodefroid/locksql/cmd/locksql")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %v: %s", err, out)
	}
	return bin, nil
})

// consoleProc is a `locksql console` running in a pseudo-terminal.
type consoleProc struct {
	t    *testing.T
	cmd  *exec.Cmd
	tty  *os.File
	mu   sync.Mutex
	out  strings.Builder
	done chan error
	mark int
}

func startConsole(t *testing.T, project string, env []string, args ...string) *consoleProc {
	t.Helper()
	bin, err := buildLocksql()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"console"}, args...)...)
	cmd.Dir = project
	cmd.Env = env
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 200})
	if err != nil {
		t.Fatal(err)
	}
	c := &consoleProc{t: t, cmd: cmd, tty: tty, done: make(chan error, 1)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tty.Read(buf)
			c.mu.Lock()
			c.out.Write(buf[:n])
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() { c.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		tty.Close()
		if t.Failed() {
			t.Logf("console output:\n%s", c.output())
		}
	})
	return c
}

func (c *consoleProc) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

// expect waits for s in the output written since the last expect.
func (c *consoleProc) expect(s string) string {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out := c.output()
		if i := strings.Index(out[c.mark:], s); i >= 0 {
			seen := out[c.mark : c.mark+i+len(s)]
			c.mark += i + len(s)
			return seen
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("console never printed %q", s)
	return ""
}

func (c *consoleProc) send(s string) {
	c.t.Helper()
	if _, err := c.tty.WriteString(s); err != nil {
		c.t.Fatal(err)
	}
}

func (c *consoleProc) wait() error {
	c.t.Helper()
	select {
	case err := <-c.done:
		return err
	case <-time.After(30 * time.Second):
		c.t.Fatal("console did not exit")
		return nil
	}
}

// rpc is a raw socket client (the client commands are a later task).
type rpc struct {
	t  *testing.T
	c  net.Conn
	r  *bufio.Reader
	id int64
}

func dialConsole(t *testing.T, path string) *rpc {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &rpc{t: t, c: c, r: bufio.NewReader(c)}
}

func (r *rpc) send(method string, params any) {
	r.t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		r.t.Fatal(err)
	}
	r.id++
	if err := ipc.WriteMsg(r.c, ipc.Request{JSONRPC: "2.0", ID: r.id, Method: method, Params: raw}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rpc) recv(timeout time.Duration) (ipc.Response, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(timeout))
	var resp ipc.Response
	err := ipc.ReadMsg(r.r, &resp)
	return resp, err
}

func (r *rpc) call(method string, params, out any) *ipc.RPCError {
	r.t.Helper()
	r.send(method, params)
	resp, err := r.recv(30 * time.Second)
	if err != nil {
		r.t.Fatalf("%s: %v", method, err)
	}
	if resp.Error == nil && out != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			r.t.Fatal(err)
		}
	}
	return resp.Error
}

var socketLine = regexp.MustCompile(`socket (\S+\.sock)`)

func TestConsoleInPTY(t *testing.T) {
	srv := startMySQL(t, mysqlTarget{engine.FlavorMariaDB, "11.4"})
	if _, err := buildLocksql(); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`[profiles.uat]
engine = "mariadb"
host = "127.0.0.1"
port = %d
user = "ro"
database = "app"

[profiles.prod]
engine = "mariadb"
host = "127.0.0.1"
port = %d
user = "rw"
production = true
`, srv.Port, srv.Port)
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_RUNTIME_DIR=" + runDir,
	}

	t.Run("uat", func(t *testing.T) {
		c := startConsole(t, project, env, "--profile", "uat")
		c.expect("Apply these changes? [y/N]")
		c.send("y\n")
		c.expect("Password for ro@127.0.0.1: ")
		c.send(ROPassword + "\n")
		c.expect("Accept all [a], review [r], skip [s]: ")
		c.send("a\n")
		seen := c.expect("Listening…")
		if strings.Contains(c.output(), ROPassword) {
			t.Fatal("the password was echoed")
		}
		m := socketLine.FindStringSubmatch(seen)
		if m == nil {
			t.Fatalf("no socket path in %q", seen)
		}
		sock := m[1]

		cl := dialConsole(t, sock)
		var hr ipc.HelloResult
		if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
			t.Fatal(e)
		}
		plan := func() string {
			var pr ipc.PlanResult
			if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id, email FROM big WHERE id = 1 LIMIT 1"}, &pr); e != nil {
				t.Fatalf("plan: %v", e)
			}
			return pr.PlanID
		}

		// Type-ahead: a "y" typed before the prompt must not approve.
		id := plan()
		c.send("y")
		time.Sleep(300 * time.Millisecond)
		cl.send(ipc.MethodQueryRun, ipc.RunParams{PlanID: id})
		c.expect("Approve? [y/N] ")
		if resp, err := cl.recv(700 * time.Millisecond); err == nil {
			t.Fatalf("type-ahead answered the prompt: %+v", resp)
		}
		c.send("\n")
		resp, err := cl.recv(30 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Error == nil || resp.Error.Code != ipc.CodeDenied {
			t.Fatalf("type-ahead run: want denied, got %+v", resp)
		}

		// A typed answer approves; the email column comes back masked.
		id = plan()
		cl.send(ipc.MethodQueryRun, ipc.RunParams{PlanID: id})
		c.expect("Approve? [y/N] ")
		c.send("y\n")
		resp, err = cl.recv(30 * time.Second)
		if err != nil || resp.Error != nil {
			t.Fatalf("approved run: %+v %v", resp, err)
		}
		var rr ipc.RunResult
		if err := json.Unmarshal(resp.Result, &rr); err != nil {
			t.Fatal(err)
		}
		if len(rr.Rows) != 1 || rr.Rows[0][1] != "u***(17)" {
			t.Fatalf("rows: %+v", rr.Rows)
		}

		// Ctrl-C ends the session and removes the socket.
		c.send("\x03")
		if err := c.wait(); err != nil {
			t.Fatalf("console exit: %v", err)
		}
		if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket left behind: %v", err)
		}

		// Second start: policy approved, rules present; the password prompt
		// comes first and is masked too.
		c = startConsole(t, project, env, "--profile", "uat")
		c.expect("Password for ro@127.0.0.1: ")
		c.send(ROPassword + "\n")
		c.expect("Listening…")
		if strings.Contains(c.output(), ROPassword) {
			t.Fatal("the password was echoed on the second start")
		}
		c.send("\x03")
		if err := c.wait(); err != nil {
			t.Fatalf("console exit: %v", err)
		}
	})

	t.Run("production refuses an over-privileged account", func(t *testing.T) {
		c := startConsole(t, project, env, "--profile", "prod")
		c.expect("Apply these changes? [y/N]")
		c.send("y\n")
		c.expect(`Type the profile name "prod" to continue: `)
		c.send("prod\n")
		c.expect("Password for rw@127.0.0.1: ")
		c.send(RWPassword + "\n")
		c.expect("privileges beyond tier read on a production profile")
		err := c.wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("exit: %v", err)
		}
		if strings.Contains(c.output(), RWPassword) {
			t.Fatal("the password was echoed")
		}
	})
}
