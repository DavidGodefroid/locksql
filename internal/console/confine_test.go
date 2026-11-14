package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// serveSocket serves h on a Unix socket and returns a function that sends
// one request on a new connection after the hello hp, and answers the
// hello's and the request's responses.
func serveSocket(t *testing.T, h *harness) func(hp ipc.HelloParams, method string) (hello, resp ipc.Response) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a Unix socket")
	}
	dir, err := os.MkdirTemp("", "lsc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.s.Serve(ctx, ln, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return func(hp ipc.HelloParams, method string) (hello, resp ipc.Response) {
		t.Helper()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)
		call := func(id int64, method string, params any) ipc.Response {
			raw, _ := json.Marshal(params)
			if err := ipc.WriteMsg(c, ipc.Request{JSONRPC: "2.0", ID: id, Method: method, Params: raw}); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			var out ipc.Response
			if err := ipc.ReadMsg(r, &out); err != nil {
				t.Fatalf("%s: %v", method, err)
			}
			return out
		}
		hello = call(1, ipc.MethodHello, hp)
		resp = call(2, method, ipc.TablesParams{DB: "app"})
		return hello, resp
	}
}

// An agent that does not run confined (lockkit#133) is refused with
// CodeUnconfined, and so is one that sends no report (an older client),
// unless the profile sets unconfined = true: then it is served, with the
// banner, and its records carry unconfined. A confined agent is served
// either way.
func TestUnconfinedAgent(t *testing.T) {
	confined := ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Confinement: &ipc.Confinement{Confined: true}}
	onHost := ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Confinement: &ipc.Confinement{Reasons: []string{"in_container"}}}
	old := ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}

	t.Run("refused by default", func(t *testing.T) {
		h := newHarness(t, uatProfile())
		dial := serveSocket(t, h)
		for _, hp := range []ipc.HelloParams{onHost, old} {
			hello, _ := dial(hp, ipc.MethodCatalogList)
			if hello.Error == nil || hello.Error.Code != ipc.CodeUnconfined || !strings.Contains(hello.Error.Message, "unconfined = true") {
				t.Errorf("hello %+v: %+v", hp.Confinement, hello.Error)
			}
		}
		if hello, resp := dial(confined, ipc.MethodCatalogList); hello.Error != nil || resp.Error != nil {
			t.Errorf("confined agent: hello %+v, request %+v", hello.Error, resp.Error)
		}
		if !strings.Contains(h.auditLog(t), `"refused-unconfined"`) {
			t.Errorf("no refused-unconfined record:\n%s", h.auditLog(t))
		}
	})

	t.Run("served with unconfined = true", func(t *testing.T) {
		p := uatProfile()
		p.Unconfined = true
		h := newHarness(t, p)
		dial := serveSocket(t, h)
		hello, resp := dial(onHost, ipc.MethodCatalogList)
		if hello.Error != nil || resp.Error != nil {
			t.Fatalf("hello %+v, request %+v", hello.Error, resp.Error)
		}
		if !strings.Contains(h.io.output(), "unconfined: this lock protects against mistakes") {
			t.Errorf("no unconfined banner:\n%s", h.io.output())
		}
	})

	t.Run("never on production", func(t *testing.T) {
		p := prodProfile()
		p.Unconfined = true
		h := newHarness(t, p)
		dial := serveSocket(t, h)
		hello, _ := dial(onHost, ipc.MethodCatalogList)
		if hello.Error == nil || hello.Error.Code != ipc.CodeUnconfined || !strings.Contains(hello.Error.Message, "production") {
			t.Errorf("hello: %+v", hello.Error)
		}
	})
}

// A production profile with unconfined = true does not start.
func TestRefuseUnconfinedProduction(t *testing.T) {
	p := prodProfile()
	if err := refuseUnconfinedProduction(p); err != nil {
		t.Errorf("production alone: %v", err)
	}
	p.Unconfined = true
	if err := refuseUnconfinedProduction(p); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "production") {
		t.Errorf("production with unconfined: %v", err)
	}
	u := uatProfile()
	u.Unconfined = true
	if err := refuseUnconfinedProduction(u); err != nil {
		t.Errorf("uat with unconfined: %v", err)
	}
}

// The server takes the gids of --runtime-gids and those of this machine.
func TestRuntimeGIDs(t *testing.T) {
	saved := hostRuntimeGIDs
	t.Cleanup(func() { hostRuntimeGIDs = saved })
	hostRuntimeGIDs = func() []int { return []int{998, 42} }
	if got := runtimeGIDs([]int{42, 7}); !slices.Equal(got, []int{42, 7, 998}) {
		t.Errorf("runtimeGIDs = %v", got)
	}
}
