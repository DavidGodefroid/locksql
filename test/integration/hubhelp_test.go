//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// fakeInstance is the instance name of the consoles fakeHub decides.
const fakeInstance = "sql-it"

// fakeHub is a fake lockhub for a console whose home is home: the
// instance key in home (where the console reads it), the hub's pinned key
// in a directory of its own, and the hub flags lox up passes.
func fakeHub(t *testing.T, home string) (*hubtest.Hub, []string) {
	t.Helper()
	key, err := hubclient.InstanceKey(home, fakeInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, fakeInstance, key.Public().(ed25519.PublicKey))
	dir := t.TempDir()
	// The pinned key's directory is writable by its owner only.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "hub.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return hub, []string{"--hub", hub.URL(), "--hub-key-file", keyFile, "--instance", fakeInstance}
}

// inProcessHub is the hub of an in-process console server, against a
// fake lockhub, watched until the test ends.
func inProcessHub(t *testing.T, io kconsole.IO) (*kconsole.Hub, *hubtest.Hub) {
	t.Helper()
	home := t.TempDir()
	fake, args := fakeHub(t, home)
	h, err := kconsole.OpenHub(product.P, kconsole.HubOptions{URL: args[1], KeyFile: args[3], Instance: fakeInstance, Home: home}, t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.Watch(ctx, io) }()
	t.Cleanup(func() { cancel(); <-done; _ = h.Close() })
	return h, fake
}

// approving wraps call, a console server's request handler, so that the
// run of a plan is the run of its ticket once the hub approved it: the
// answer is that of an approved request. Any other answer to the run of
// the plan (a refusal) is returned as is.
func approving(t *testing.T, hub *hubtest.Hub, call func(method string, params any) ipc.Response) func(method string, params any) ipc.Response {
	return func(method string, params any) ipc.Response {
		rp, ok := params.(ipc.RunParams)
		if method != ipc.MethodQueryRun || !ok || rp.PlanID == "" {
			return call(method, params)
		}
		r := call(method, params)
		if r.Error != nil {
			return r
		}
		var p ipc.RunResult
		if err := json.Unmarshal(r.Result, &p); err != nil || p.Status != "pending" || p.Ticket == "" {
			t.Fatalf("query.run: %s, want pending", r.Result)
		}
		hub.Decide(p.Ticket, ticket.Approved, "")
		deadline := time.Now().Add(30 * time.Second)
		for {
			r = call(method, ipc.RunParams{Ticket: p.Ticket, Requester: rp.Requester})
			if r.Error == nil || !strings.Contains(r.Error.Message, "no decision") || time.Now().After(deadline) {
				return r
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
