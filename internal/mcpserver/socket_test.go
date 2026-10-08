package mcpserver

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// TestRunOverRealSocket drives locksql_run through DialClient and a real
// console socket, so that the client's json.Number values go through the
// SDK's output schema validation.
func TestRunOverRealSocket(t *testing.T) {
	rt, err := os.MkdirTemp("/tmp", "lsmcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rt) })
	t.Setenv(ipc.RuntimeDirEnv, rt)
	cwd := t.TempDir()

	path, err := ipc.SocketPath(config.ProjectKey(cwd), "uat")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	clients := make(chan string, 4)
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
					var v any
					switch req.Method {
					case ipc.MethodHello:
						var hp ipc.HelloParams
						_ = json.Unmarshal(req.Params, &hp)
						clients <- hp.Client
						v = ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: "uat"}
					case ipc.MethodQueryRun:
						v = ipc.RunResult{Columns: []string{"id", "price", "note"},
							Rows: [][]any{{int64(9007199254740993), 1.5, nil}}, Text: "id\tprice\tnote\n9007199254740993\t1.5\tNULL\n"}
					}
					b, _ := json.Marshal(v)
					if err := ipc.WriteMsg(c, ipc.Response{JSONRPC: "2.0", ID: req.ID, Result: b}); err != nil {
						return
					}
				}
			}()
		}
	}()

	cs := connect(t, Options{Profile: "uat", Dial: DialClient(cwd, "1.2.3")}, nil)
	r := call(t, cs, "locksql_run", map[string]any{"plan_id": "p1"})
	if r.IsError {
		t.Fatalf("error: %s", text(r))
	}
	if got := <-clients; got != "locksql-mcp 1.2.3" {
		t.Fatalf("hello client = %q", got)
	}
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), `[["9007199254740993",1.5,null]]`) {
		t.Fatalf("structured rows = %s", b)
	}
	if !strings.HasPrefix(text(r), UntrustedPreamble+"\nid\tprice") {
		t.Fatalf("text = %q", text(r))
	}

	// Another profile has no console: the error names the start command.
	other := connect(t, Options{Dial: DialClient(cwd, "1.2.3")}, nil)
	r = call(t, other, "locksql_plan", map[string]any{"profile": "prod", "sql": "SELECT 1 LIMIT 1"})
	if !r.IsError || !strings.Contains(text(r), "locksql console --profile prod") {
		t.Fatalf("no console: %s", text(r))
	}
}
