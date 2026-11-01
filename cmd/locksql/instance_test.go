//go:build unix

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/locksql/internal/client"
	"github.com/DavidGodefroid/locksql/internal/mcpserver"
)

// separatedSockets switches the process to the separated setup with a
// short socket directory, and clears the instance variables.
func separatedSockets(t *testing.T) string {
	t.Helper()
	sockets, err := os.MkdirTemp("/tmp", "lsinst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	conf := filepath.Join(t.TempDir(), "system.toml")
	body := "service_user = \"root\"\nsocket_dir = \"" + sockets + "\"\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath, oldSkip := sysconf.Path, sysconf.SkipOwnerCheck
	sysconf.Path, sysconf.SkipOwnerCheck = conf, true
	t.Cleanup(func() { sysconf.Path, sysconf.SkipOwnerCheck = oldPath, oldSkip })
	t.Setenv("LOCKSQL_INSTANCE", "")
	t.Setenv("LEA_LOCKSQL_INSTANCES", "")
	return sockets
}

// listenAt listens on the socket of profile uat for the project of dir in
// the instance directory of sockets, and reports each connection it gets.
func listenAt(t *testing.T, dir, instance string) <-chan struct{} {
	t.Helper()
	path, err := client.SocketPathInstance(dir, "uat", instance)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			got <- struct{}{}
			_ = c.Close()
		}
	}()
	return got
}

func waitConn(t *testing.T, got <-chan struct{}) {
	t.Helper()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the instance socket")
	}
}

func TestInstanceFlagDialsItsDirectory(t *testing.T) {
	dir := project(t, uatConfig)
	sockets := separatedSockets(t)
	got := listenAt(t, dir, "orders")
	cli(t, dir, "", "status", "--profile", "uat", "--instance", "orders")
	waitConn(t, got)
	if _, err := os.Stat(filepath.Join(sockets, "orders")); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceFlagOnEveryClientCommand(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	got := listenAt(t, dir, "orders")
	for _, args := range [][]string{
		{"tables", "--profile", "uat", "--instance", "orders", "--db", "app"},
		{"describe", "--profile", "uat", "--instance", "orders", "--db", "app", "orders"},
		{"run", "--profile", "uat", "--instance", "orders", "p1"},
		{"pii", "list", "--profile", "uat", "--instance", "orders"},
		{"logout", "--profile", "uat", "--instance", "orders"},
		{"request", "--profile", "uat", "--instance", "orders", "tier=write"},
		{"plan", "--profile", "uat", "--instance", "orders", "--db", "app", "SELECT 1"},
	} {
		cli(t, dir, "", args...)
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatalf("%v: no connection reached the instance socket", args)
		}
	}
}

func TestInstanceFromLeaListWhenSingle(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "orders")
	got := listenAt(t, dir, "orders")
	cli(t, dir, "", "status", "--profile", "uat")
	waitConn(t, got)
}

func TestSeveralInstancesAndNoneChosenIsUsage(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "audit orders")
	for _, args := range [][]string{
		{"status", "--profile", "uat"},
		{"tables", "--profile", "uat", "--db", "app"},
		{"mcp", "--profile", "uat"},
		{"doctor"},
	} {
		o := cli(t, dir, "", args...)
		o.want(t, exitUsage, "--instance", "audit orders")
	}
}

func TestBadInstanceIsRefusedBeforeAnyPath(t *testing.T) {
	dir := project(t, uatConfig)
	sockets := separatedSockets(t)
	for _, args := range [][]string{
		{"status", "--profile", "uat", "--instance", "../x"},
		{"plan", "--profile", "uat", "--db", "app", "--instance", "../x", "SELECT 1"},
		{"mcp", "--instance", "../x"},
		{"doctor", "--instance", "../x"},
	} {
		o := cli(t, dir, "", args...)
		o.want(t, exitUsage, "--instance")
		if strings.Contains(o.stdout+o.stderr, "../x") {
			t.Fatalf("%v echoed the name: %s", args, o.stderr)
		}
	}
	entries, err := os.ReadDir(sockets)
	if err != nil || len(entries) != 0 {
		t.Fatalf("socket dir touched: %v %v", entries, err)
	}
}

func TestMCPDialsTheInstance(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	got := listenAt(t, dir, "orders")
	dial := mcpserver.DialClient(dir, "1.2.3", "orders")
	c, err := dial("uat")
	if err == nil {
		defer c.Close()
	}
	waitConn(t, got)
}

func TestMCPCommandPassesTheInstance(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	got := listenAt(t, dir, "orders")
	call, _, _ := mcpSession(t, dir, "--profile", "uat", "--instance", "orders")
	call("tools/call", map[string]any{"name": "locksql_list_tables", "arguments": map[string]any{"profile": "uat"}})
	waitConn(t, got)
}

func TestStatusAllReachesTheInstance(t *testing.T) {
	dir := project(t, twoProfiles)
	separatedSockets(t)
	got := listenAt(t, dir, "orders")
	cli(t, dir, "", "status", "--instance", "orders")
	// Both profiles are dialled; the listener serves the uat socket.
	waitConn(t, got)
}

func TestDoctorStatusReachesTheInstance(t *testing.T) {
	dir := project(t, uatConfig)
	separatedSockets(t)
	got := listenAt(t, dir, "orders")
	cli(t, dir, "", "doctor", "--profile", "uat", "--instance", "orders")
	waitConn(t, got)
}
