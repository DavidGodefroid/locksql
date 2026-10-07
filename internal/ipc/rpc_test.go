package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteReadMsg(t *testing.T) {
	var buf bytes.Buffer
	in := Request{JSONRPC: "2.0", ID: 3, Method: MethodQueryPlan, Params: json.RawMessage(`{"db":"app","sql":"SELECT 1\nLIMIT 1"}`)}
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 1 || !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("framing: %q", buf.String())
	}
	var out Request
	r := bufio.NewReader(&buf)
	if err := ReadMsg(r, &out); err != nil {
		t.Fatal(err)
	}
	var p PlanParams
	if err := json.Unmarshal(out.Params, &p); err != nil || p.SQL != "SELECT 1\nLIMIT 1" || p.DB != "app" {
		t.Fatalf("params = %+v, %v", p, err)
	}
	if err := ReadMsg(r, &out); !errors.Is(err, io.EOF) {
		t.Fatalf("at end: %v", err)
	}
}

func TestReadMsgOversized(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":"` + strings.Repeat("a", MaxMessage) + `"}` + "\n"
	var req Request
	err := ReadMsg(bufio.NewReader(strings.NewReader(big)), &req)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	// Also without a newline at all.
	err = ReadMsg(bufio.NewReader(strings.NewReader(strings.Repeat("a", MaxMessage+10))), &req)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("no newline: err = %v", err)
	}
}

func TestReadMsgExactlyAtCap(t *testing.T) {
	prefix, suffix := `{"jsonrpc":"2.0","id":1,"method":"`, `"}`
	line := prefix + strings.Repeat("m", MaxMessage-len(prefix)-len(suffix)) + suffix
	var req Request
	if err := ReadMsg(bufio.NewReader(strings.NewReader(line+"\n")), &req); err != nil {
		t.Fatalf("message at the cap refused: %v", err)
	}
}

func TestWriteMsgOversized(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMsg(&buf, RunResult{Text: strings.Repeat("x", MaxMessage)})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("partial message written")
	}
}

func TestReadMsgBadInput(t *testing.T) {
	for _, in := range []string{"\n", "not json\n", "[1,2]\n", `{"id":1} {"id":2}` + "\n", "{\"id\":1"} {
		var req Request
		if err := ReadMsg(bufio.NewReader(strings.NewReader(in)), &req); err == nil {
			t.Errorf("ReadMsg(%q) accepted", in)
		}
	}
}

func TestReadMsgCRLF(t *testing.T) {
	var req Request
	if err := ReadMsg(bufio.NewReader(strings.NewReader("{\"id\":4}\r\n")), &req); err != nil || req.ID != 4 {
		t.Fatalf("req = %+v, %v", req, err)
	}
}

func TestRPCErrorJSON(t *testing.T) {
	resp := Response{JSONRPC: "2.0", ID: 1, Error: &RPCError{Code: CodeRefused, Message: "refused: no LIMIT"}}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"result"`) || !strings.Contains(string(b), `"code":-32001`) {
		t.Fatalf("json = %s", b)
	}
	var e error = resp.Error
	if e.Error() != "refused: no LIMIT" {
		t.Fatalf("Error() = %q", e.Error())
	}
}

func TestErrorCodes(t *testing.T) {
	want := map[int]int{CodeRefused: -32001, CodeDenied: -32002, CodeTimeout: -32003, CodeNoSuchPlan: -32004, CodeConnLost: -32005, CodePolicyPending: -32006}
	for got, w := range want {
		if got != w {
			t.Errorf("code %d, want %d", got, w)
		}
	}
}

func TestMethodNames(t *testing.T) {
	want := []string{"hello", "status", "catalog.list", "catalog.describe", "query.plan", "query.run", "pii.list", "pii.add", "change.request", "logout"}
	got := []string{MethodHello, MethodStatus, MethodCatalogList, MethodCatalogDescribe, MethodQueryPlan, MethodQueryRun, MethodPIIList, MethodPIIAdd, MethodChangeRequest, MethodLogout}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("method %d = %q, want %q", i, got[i], want[i])
		}
	}
	if len(Methods()) != len(want) {
		t.Errorf("Methods() = %v", Methods())
	}
}

func TestCompatible(t *testing.T) {
	if !Compatible(ProtocolMajor) || Compatible(ProtocolMajor+1) || Compatible(0) {
		t.Fatal("Compatible must accept only the same major")
	}
}

func FuzzReadMsgNoPanic(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}` + "\n"))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var req Request
		_ = ReadMsg(bufio.NewReader(bytes.NewReader(b)), &req)
	})
}
