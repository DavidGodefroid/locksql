package main

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// mcpSession runs `locksql mcp args...` in dir over pipes and returns a
// function that sends one request and returns its response.
func mcpSession(t *testing.T, dir string, args ...string) (call func(method string, params any) map[string]any, closeIn func(), done <-chan int) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errb strings.Builder
	exit := make(chan int, 1)
	go func() {
		code := runEnv(env{stdin: inR, stdout: outW, stderr: &errb, cwd: dir}, append([]string{"mcp"}, args...))
		outW.Close()
		exit <- code
	}()
	t.Cleanup(func() { inW.Close() })
	r := bufio.NewReader(outR)
	id := 0
	send := func(v any) {
		b, _ := json.Marshal(v)
		if _, err := inW.Write(append(b, '\n')); err != nil {
			t.Fatalf("write: %v (stderr %s)", err, errb.String())
		}
	}
	call = func(method string, params any) map[string]any {
		t.Helper()
		id++
		send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				t.Fatalf("read: %v (stderr %s)", err, errb.String())
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("stdout is not JSON-RPC: %q", line)
			}
			if got, ok := m["id"].(float64); ok && int(got) == id {
				return m
			}
		}
	}
	call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "1"},
	})
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return call, func() { inW.Close() }, exit
}

func toolText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	var b strings.Builder
	for _, c := range res["content"].([]any) {
		b.WriteString(c.(map[string]any)["text"].(string))
	}
	isErr, _ := res["isError"].(bool)
	return b.String(), isErr
}

func TestMCPOverStdio(t *testing.T) {
	dir := project(t, twoProfiles)
	startConsole(t, dir, "uat")
	call, _, _ := mcpSession(t, dir)

	list := call("tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("%d tools", len(tools))
	}

	txt, isErr := toolText(t, call("tools/call", map[string]any{"name": "locksql_list_tables", "arguments": map[string]any{"profile": "uat"}}))
	if isErr || txt != "orders\nusers\n" {
		t.Fatalf("tables: %q (error %v)", txt, isErr)
	}
	txt, isErr = toolText(t, call("tools/call", map[string]any{"name": "locksql_plan",
		"arguments": map[string]any{"profile": "prod", "sql": "SELECT 1 LIMIT 1"}}))
	if !isErr || !strings.Contains(txt, "locksql console --profile prod") {
		t.Fatalf("no console: %q (error %v)", txt, isErr)
	}
	txt, _ = toolText(t, call("tools/call", map[string]any{"name": "locksql_status", "arguments": map[string]any{}}))
	if !strings.Contains(txt, "uat: console running") || !strings.Contains(txt, "locksql console --profile prod") {
		t.Fatalf("status: %q", txt)
	}
}

func TestMCPEndsOnEOF(t *testing.T) {
	dir := project(t, uatConfig)
	_, closeIn, done := mcpSession(t, dir, "--profile", "uat")
	closeIn()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("exit %d after EOF", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("locksql mcp did not end on EOF")
	}
}

func TestMCPUsageErrors(t *testing.T) {
	dir := project(t, uatConfig)
	cli(t, dir, "", "mcp", "--profile", "nope").want(t, exitUsage, "unknown profile")
	cli(t, dir, "", "mcp", "extra").want(t, exitUsage, "wrong number of arguments")
	bad := project(t, "[profiles.x]\nengine = \"mariadb\"\nhost = \"h\"\npassword = \"p\"\n")
	o := cli(t, bad, "", "mcp")
	o.want(t, exitUsage)
	if strings.Contains(o.stdout+o.stderr, `"p"`) {
		t.Fatalf("secret quoted: %s", o.stderr)
	}
}
