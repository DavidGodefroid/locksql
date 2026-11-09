//go:build unix

package main

import (
	"errors"
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
	return listenFor(t, dir, instance, "uat")
}

// listenFor is listenAt for the socket of profile.
func listenFor(t *testing.T, dir, instance, profile string) <-chan struct{} {
	t.Helper()
	path, err := client.SocketPathInstance(dir, profile, instance)
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

// Several locks and none chosen route each profile to the lock whose
// directory holds its console socket; with none, there is no console.
func TestSeveralInstancesAndNoneChosenRouteByProfile(t *testing.T) {
	dir := project(t, twoProfiles)
	separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "audit orders")
	for _, args := range [][]string{
		{"status", "--profile", "uat"},
		{"tables", "--profile", "uat", "--db", "app"},
	} {
		o := cli(t, dir, "", args...)
		o.want(t, exitNoConsole, "lox run")
	}
	uat, prod := listenFor(t, dir, "orders", "uat"), listenFor(t, dir, "audit", "prod")
	cli(t, dir, "", "tables", "--profile", "uat", "--db", "app")
	waitConn(t, uat)
	cli(t, dir, "", "tables", "--profile", "prod", "--db", "app")
	waitConn(t, prod)
	cli(t, dir, "", "status")
	waitConn(t, uat)
	waitConn(t, prod)
}

// TestResolveLocksByProfile is the instance resolution with no lock, one
// and two, by profile.
func TestResolveLocksByProfile(t *testing.T) {
	dir := project(t, twoProfiles)
	separatedSockets(t)
	instanceOf := func(profile string) (string, error) {
		t.Helper()
		l, err := client.ResolveLocks(dir, "")
		if err != nil {
			t.Fatal(err)
		}
		return l.Instance(profile)
	}

	// No lock listed: the socket directory itself, for every profile.
	if got, err := instanceOf("uat"); got != "" || err != nil {
		t.Fatalf("0 locks: %q %v", got, err)
	}
	// One lock: that one, socket or not.
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg")
	if got, err := instanceOf("prod"); got != "pg" || err != nil {
		t.Fatalf("1 lock: %q %v", got, err)
	}
	// Two locks: the one that holds the profile's socket.
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg my")
	listenFor(t, dir, "pg", "uat")
	listenFor(t, dir, "my", "prod")
	if got, err := instanceOf("uat"); got != "pg" || err != nil {
		t.Fatalf("2 locks, uat: %q %v", got, err)
	}
	if got, err := instanceOf("prod"); got != "my" || err != nil {
		t.Fatalf("2 locks, prod: %q %v", got, err)
	}
	if _, err := instanceOf("dev"); !errors.Is(err, client.ErrNoConsole) {
		t.Fatalf("2 locks, no socket: %v", err)
	}
	listenFor(t, dir, "my", "uat")
	if _, err := instanceOf("uat"); err == nil || !strings.Contains(err.Error(), "--instance") || !strings.Contains(err.Error(), "pg my") {
		t.Fatalf("2 locks, both hold uat: %v", err)
	}
	// A chosen lock wins over routing.
	l, err := client.ResolveLocks(dir, "my")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := l.Instance("prod"); got != "my" || err != nil {
		t.Fatalf("--instance my: %q %v", got, err)
	}
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg ../x")
	if _, err := client.ResolveLocks(dir, ""); err == nil || strings.Contains(err.Error(), "../x") {
		t.Fatalf("bad listed name: %v", err)
	}
}

// One `locksql mcp`, as `locksql init claude` writes it, reaches every
// locksql lock of the workspace by profile (#206).
func TestMCPServesEveryLock(t *testing.T) {
	dir := project(t, twoProfiles)
	separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg my")
	uat, prod := listenFor(t, dir, "pg", "uat"), listenFor(t, dir, "my", "prod")
	call, _, _ := mcpSession(t, dir)
	call("tools/call", map[string]any{"name": "locksql_list_tables", "arguments": map[string]any{"profile": "uat"}})
	waitConn(t, uat)
	call("tools/call", map[string]any{"name": "locksql_list_tables", "arguments": map[string]any{"profile": "prod"}})
	waitConn(t, prod)
	txt, _ := toolText(t, call("tools/call", map[string]any{"name": "locksql_status", "arguments": map[string]any{}}))
	waitConn(t, uat)
	waitConn(t, prod)
	if strings.Contains(txt, "no console") {
		t.Fatalf("status: %s", txt)
	}
}

// A server bound to one lock with --instance neither reports nor counts the
// profiles another mounted lock serves.
func TestMCPBoundInstanceKeepsItsProfiles(t *testing.T) {
	dir := project(t, twoProfiles)
	separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg my")
	uat := listenFor(t, dir, "pg", "uat")
	listenFor(t, dir, "my", "prod")
	call, _, _ := mcpSession(t, dir, "--instance", "pg")
	txt, _ := toolText(t, call("tools/call", map[string]any{"name": "locksql_status", "arguments": map[string]any{}}))
	waitConn(t, uat)
	if !strings.Contains(txt, "uat:") || strings.Contains(txt, "prod") {
		t.Fatalf("status of pg: %s", txt)
	}
	txt, _ = toolText(t, call("tools/call", map[string]any{"name": "locksql_list_tables", "arguments": map[string]any{}}))
	if strings.Contains(txt, "several profiles") {
		t.Fatalf("list_tables without profile: %s", txt)
	}
	waitConn(t, uat)
}

// An instance the server cannot resolve does not stop it (no exit 3):
// locksql_status reports the problem, and the name is never echoed.
func TestMCPBadOrAmbiguousInstanceStarts(t *testing.T) {
	dir := project(t, uatConfig)
	sockets := separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "pg my")
	t.Setenv("LOCKSQL_INSTANCE", "../x")
	call, closeIn, done := mcpSession(t, dir)
	txt, _ := toolText(t, call("tools/call", map[string]any{"name": "locksql_status", "arguments": map[string]any{}}))
	if !strings.Contains(txt, "LOCKSQL_INSTANCE") || strings.Contains(txt, "../x") || strings.Contains(txt, "lox run") {
		t.Fatalf("status: %s", txt)
	}
	entries, err := os.ReadDir(sockets)
	if err != nil || len(entries) != 0 {
		t.Fatalf("socket dir touched: %v %v", entries, err)
	}
	closeIn()
	if code := <-done; code != exitOK {
		t.Fatalf("exit %d", code)
	}

	// Ambiguous: the profile's console socket is in both locks.
	t.Setenv("LOCKSQL_INSTANCE", "")
	listenFor(t, dir, "pg", "uat")
	listenFor(t, dir, "my", "uat")
	call, _, _ = mcpSession(t, dir)
	txt, _ = toolText(t, call("tools/call", map[string]any{"name": "locksql_status", "arguments": map[string]any{}}))
	if !strings.Contains(txt, "several locks") || !strings.Contains(txt, "--instance") {
		t.Fatalf("ambiguous status: %s", txt)
	}
}

func TestBadInstanceIsRefusedBeforeAnyPath(t *testing.T) {
	dir := project(t, uatConfig)
	sockets := separatedSockets(t)
	for _, args := range [][]string{
		{"status", "--profile", "uat", "--instance", "../x"},
		{"plan", "--profile", "uat", "--db", "app", "--instance", "../x", "SELECT 1"},
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

// doctor resolves the instance where it dials a console: a stray or
// ambiguous value fails the console check only, the other checks and
// --fix still run, and the name is never echoed.
func TestDoctorResolvesTheInstanceLazily(t *testing.T) {
	dir := project(t, uatConfig)
	sockets := separatedSockets(t)
	t.Setenv("LEA_LOCKSQL_INSTANCES", "audit orders")
	// Several locks route by profile: none holds uat's socket, so no
	// console runs for it.
	o := cli(t, dir, "", "doctor", "--profile", "uat")
	if o.code == exitUsage || !strings.Contains(o.stdout+o.stderr, "lox run") || !strings.Contains(o.stdout, "console") {
		t.Fatalf("several locks: exit %d\nstdout: %s\nstderr: %s", o.code, o.stdout, o.stderr)
	}
	o = cli(t, dir, "", "doctor", "--profile", "uat", "--instance", "../x")
	if o.code == exitUsage || !strings.Contains(o.stdout+o.stderr, "--instance") || strings.Contains(o.stdout+o.stderr, "../x") {
		t.Fatalf("bad name: exit %d\nstdout: %s\nstderr: %s", o.code, o.stdout, o.stderr)
	}
	entries, err := os.ReadDir(sockets)
	if err != nil || len(entries) != 0 {
		t.Fatalf("socket dir touched: %v %v", entries, err)
	}
}
