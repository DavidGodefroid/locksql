package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// runtimeDir points the socket paths at a short private temp dir.
func runtimeDir(t *testing.T) string {
	t.Helper()
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	d, err := os.MkdirTemp(base, "lscl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	t.Setenv("LOCKSQL_RUNTIME_DIR", d)
	return d
}

// fakeConsole answers requests on the profile's socket with handler.
type fakeConsole struct {
	mu      sync.Mutex
	methods []string
}

func (f *fakeConsole) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func startFake(t *testing.T, cwd, profile string, handler func(req ipc.Request) ipc.Response) *fakeConsole {
	t.Helper()
	path, err := ipc.SocketPath(config.ProjectKey(cwd), profile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeConsole{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					var req ipc.Request
					if err := ipc.ReadMsg(r, &req); err != nil {
						return
					}
					f.mu.Lock()
					f.methods = append(f.methods, req.Method)
					f.mu.Unlock()
					var resp ipc.Response
					if req.Method == ipc.MethodHello {
						resp = result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: profile})
					} else {
						resp = handler(req)
					}
					if err := ipc.WriteMsg(c, resp); err != nil {
						return
					}
				}
			}()
		}
	}()
	return f
}

func result(id int64, v any) ipc.Response {
	b, _ := json.Marshal(v)
	return ipc.Response{JSONRPC: "2.0", ID: id, Result: b}
}

func rpcErr(id int64, code int, msg string) ipc.Response {
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

func TestDialWithoutConsoleIsErrNoConsole(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	_, err := Dial(cwd, "uat")
	if !errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want ErrNoConsole", err)
	}
	var nc *NoConsoleError
	if !errors.As(err, &nc) || nc.Profile != "uat" {
		t.Fatalf("err = %#v, want a *NoConsoleError for uat", err)
	}
	if !strings.Contains(err.Error(), "locksql console --profile uat") {
		t.Fatalf("message lacks the start command: %q", err.Error())
	}
	if StartCommand("uat") != "locksql console --profile uat" {
		t.Fatalf("StartCommand = %q", StartCommand("uat"))
	}
}

func TestDialStaleSocketIsErrNoConsole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket files are not left behind the same way on windows")
	}
	runtimeDir(t)
	cwd := t.TempDir()
	path, err := ipc.SocketPath(config.ProjectKey(cwd), "uat")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket missing: %v", err)
	}
	if _, err := Dial(cwd, "uat"); !errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want ErrNoConsole", err)
	}
}

func TestDialRefusesBadProfile(t *testing.T) {
	runtimeDir(t)
	if _, err := Dial(t.TempDir(), "../x"); err == nil || errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want a plain error", err)
	}
}

func TestCallSendsHelloFirstAndDecodes(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	fake := startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		return result(req.ID, ipc.TablesResult{DB: "app", Tables: []string{"users"}})
	})
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := c.Tables(context.Background(), "app")
	if err != nil {
		t.Fatal(err)
	}
	if got.DB != "app" || len(got.Tables) != 1 || got.Tables[0] != "users" {
		t.Fatalf("Tables = %+v", got)
	}
	if _, err := c.Tables(context.Background(), "app"); err != nil {
		t.Fatal(err)
	}
	want := []string{ipc.MethodHello, ipc.MethodCatalogList, ipc.MethodCatalogList}
	if s := fake.seen(); strings.Join(s, ",") != strings.Join(want, ",") {
		t.Fatalf("methods = %v, want %v", s, want)
	}
}

func TestCallReturnsRPCError(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		return rpcErr(req.ID, ipc.CodeDenied, "denied by the human")
	})
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Run(context.Background(), "abc")
	var re *ipc.RPCError
	if !errors.As(err, &re) || re.Code != ipc.CodeDenied {
		t.Fatalf("err = %v, want RPCError %d", err, ipc.CodeDenied)
	}
}

func TestHelloProtocolMismatch(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	path, _ := ipc.SocketPath(config.ProjectKey(cwd), "uat")
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req ipc.Request
		if ipc.ReadMsg(bufio.NewReader(c), &req) == nil {
			_ = ipc.WriteMsg(c, result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor + 1, Profile: "uat"}))
		}
	}()
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("err = %v, want a protocol mismatch", err)
	}
}

func TestHelloProfileMismatch(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	path, _ := ipc.SocketPath(config.ProjectKey(cwd), "uat")
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req ipc.Request
		if ipc.ReadMsg(bufio.NewReader(c), &req) == nil {
			_ = ipc.WriteMsg(c, result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: "prod"}))
		}
	}()
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("err = %v, want a profile mismatch", err)
	}
}

// spyConn records every deadline set on the connection.
type spyConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (s *spyConn) record(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadlines = append(s.deadlines, t)
}
func (s *spyConn) SetDeadline(t time.Time) error      { s.record(t); return s.Conn.SetDeadline(t) }
func (s *spyConn) SetReadDeadline(t time.Time) error  { s.record(t); return s.Conn.SetReadDeadline(t) }
func (s *spyConn) SetWriteDeadline(t time.Time) error { s.record(t); return s.Conn.SetWriteDeadline(t) }

// TestRunWaitsWithoutClientTimeout checks that query.run carries no
// client-side timeout: neither the call context nor the connection gets a
// deadline, so an approval may take as long as the console allows (5 min).
func TestRunWaitsWithoutClientTimeout(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	release := make(chan struct{})
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		<-release // the human takes their time
		return result(req.ID, ipc.RunResult{Columns: []string{"n"}, Rows: [][]any{{1}}})
	})

	var spy *spyConn
	old := dialUnix
	dialUnix = func(path string) (net.Conn, error) {
		c, err := old(path)
		if err != nil {
			return nil, err
		}
		spy = &spyConn{Conn: c}
		return spy, nil
	}
	t.Cleanup(func() { dialUnix = old })

	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	done := make(chan error, 1)
	var got ipc.RunResult
	go func() {
		var err error
		got, err = c.Run(context.Background(), "abc")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("Run returned before the human answered: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the answer")
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows = %v", got.Rows)
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	for _, d := range spy.deadlines {
		if !d.IsZero() {
			t.Fatalf("a deadline was set on the call: %v", d)
		}
	}
	if c.lastDeadline != nil {
		t.Fatalf("the call context carried a deadline: %v", *c.lastDeadline)
	}
}

func TestCallHonoursContextCancel(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		<-block
		return result(req.ID, map[string]bool{"ok": true})
	})
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := c.Logout(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestConsoleClosingMidCallIsAnError(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	path, _ := ipc.SocketPath(config.ProjectKey(cwd), "uat")
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		var req ipc.Request
		if ipc.ReadMsg(r, &req) == nil {
			_ = ipc.WriteMsg(c, result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: "uat"}))
		}
		_ = ipc.ReadMsg(r, &req)
		c.Close()
	}()
	c, err := Dial(cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err == nil || !errors.Is(err, ErrConsoleClosed) {
		t.Fatalf("err = %v, want ErrConsoleClosed", err)
	}
}

func TestSocketPathUsesProjectKey(t *testing.T) {
	d := runtimeDir(t)
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".locksql", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := SocketPath(filepath.Join(cwd), "uat")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d, "locksql", config.ProjectHash(cwd)+"-uat.sock")
	if p != want {
		t.Fatalf("SocketPath = %q, want %q", p, want)
	}
}

func TestErrorTextAndKinds(t *testing.T) {
	cases := []struct {
		err  error
		kind string
		text string
	}{
		{&ipc.RPCError{Code: ipc.CodeRefused, Message: "statement class WRITE is above the profile tier read"}, "refused",
			"refused: statement class WRITE is above the profile tier read"},
		{&ipc.RPCError{Code: ipc.CodeNoSuchPlan, Message: "no such plan: it is unknown"}, "no_such_plan", "no such plan: it is unknown"},
		{&ipc.RPCError{Code: ipc.CodePolicyPending, Message: "a policy change awaits"}, "policy_pending", "policy pending: a policy change awaits"},
		{&ipc.RPCError{Code: -1, Message: "odd"}, "error", "odd"},
		{&NoConsoleError{Profile: "uat"}, "no_console", (&NoConsoleError{Profile: "uat"}).Error()},
		{ErrConsoleClosed, "console_closed", ErrConsoleClosed.Error()},
		{context.Canceled, "cancelled", "cancelled"},
	}
	for _, c := range cases {
		if k := DescribeError(c.err).Kind; k != c.kind {
			t.Errorf("%v: kind %q, want %q", c.err, k, c.kind)
		}
		if s := ErrorText(c.err); s != c.text {
			t.Errorf("%v: text %q, want %q", c.err, s, c.text)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1 000", 65536: "65 536", 1000000: "1 000 000", -1234: "-1 234"} {
		if got := Group(n); got != want {
			t.Errorf("Group(%d) = %q, want %q", n, got, want)
		}
	}
	if got := clean("a\tb\nc\x1b[31m\u202ed"); got != `a\tb\nc\x1b[31m`+"\\u202ed" {
		t.Errorf("clean = %q", got)
	}
	if got := clean("plain é"); got != "plain é" {
		t.Errorf("clean = %q", got)
	}
}
