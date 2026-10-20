// Package compat pins the wire format a locksql 0.8 client and console
// exchange, so that a console built on lockkit and an older client (or the
// reverse) still talk.
package compat

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The bytes of locksql 0.8's hello request and response (captured before
// lockkit): protocol major 1, newline-delimited JSON-RPC 2.0.
const (
	helloRequest  = `{"jsonrpc":"2.0","id":1,"method":"hello","params":{"protocol_major":1,"client":"locksql"}}` + "\n"
	helloResponse = `{"jsonrpc":"2.0","id":1,"result":{"protocol_major":1,"console_version":"0.8.0","profile":"uat"}}` + "\n"
	refusedError  = `{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"no limit","data":{"code":"E_NO_LIMIT","retry":"rewrite","hint":"end it","span":{"line":1,"col":8,"token":"FROM"}}}}` + "\n"
)

func TestHelloWire(t *testing.T) {
	if ipc.ProtocolMajor != 1 {
		t.Fatalf("protocol major %d: an 0.8 peer refuses it", ipc.ProtocolMajor)
	}
	params, err := json.Marshal(ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: "locksql"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, ConsoleVersion: "0.8.0", Profile: "uat"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ipc.WriteMsg(&buf, ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodHello, Params: params}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != helloRequest {
		t.Errorf("hello request:\n got %s\nwant %s", buf.String(), helloRequest)
	}
	buf.Reset()
	if err := ipc.WriteMsg(&buf, ipc.Response{JSONRPC: "2.0", ID: 1, Result: result}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != helloResponse {
		t.Errorf("hello response:\n got %s\nwant %s", buf.String(), helloResponse)
	}

	// An 0.8 peer's bytes decode into today's types.
	var req ipc.Request
	if err := ipc.ReadMsg(bufio.NewReader(bytes.NewBufferString(helloRequest)), &req); err != nil {
		t.Fatal(err)
	}
	var hp ipc.HelloParams
	if err := json.Unmarshal(req.Params, &hp); err != nil || req.Method != ipc.MethodHello || hp.ProtocolMajor != 1 || hp.Client != "locksql" {
		t.Fatalf("decoded %+v %+v %v", req, hp, err)
	}
	var resp ipc.Response
	if err := ipc.ReadMsg(bufio.NewReader(bytes.NewBufferString(refusedError)), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != ipc.CodeRefused || resp.Error.Data == nil || resp.Error.Data.Code != "E_NO_LIMIT" ||
		resp.Error.Data.Span == nil || resp.Error.Data.Span.Token != "FROM" {
		t.Fatalf("refused error decoded as %+v", resp.Error)
	}
	buf.Reset()
	if err := ipc.WriteMsg(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if buf.String() != refusedError {
		t.Errorf("refused error:\n got %s\nwant %s", buf.String(), refusedError)
	}
}
