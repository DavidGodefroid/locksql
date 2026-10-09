package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shortDir returns a private temp dir with a short path: unix socket paths
// are limited to about 104 bytes and t.TempDir() can be long on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lsipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func sockPath(t *testing.T) string {
	return filepath.Join(shortDir(t), "run", "abcd1234-uat.sock")
}

func TestListenDialRoundTrip(t *testing.T) {
	path := sockPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		ok, err := PeerAllowed(c)
		if err != nil || !ok {
			done <- errors.Join(errors.New("peer refused"), err)
			return
		}
		var req Request
		if err := ReadMsg(bufio.NewReader(c), &req); err != nil {
			done <- err
			return
		}
		res, _ := json.Marshal(HelloResult{ProtocolMajor: ProtocolMajor, Profile: "uat"})
		done <- WriteMsg(c, Response{JSONRPC: "2.0", ID: req.ID, Result: res})
	}()

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	params, _ := json.Marshal(HelloParams{ProtocolMajor: ProtocolMajor})
	if err := WriteMsg(c, Request{JSONRPC: "2.0", ID: 7, Method: MethodHello, Params: params}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := ReadMsg(bufio.NewReader(c), &resp); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if resp.ID != 7 || resp.Error != nil {
		t.Fatalf("resp = %+v", resp)
	}
	var hr HelloResult
	if err := json.Unmarshal(resp.Result, &hr); err != nil || hr.Profile != "uat" || hr.ProtocolMajor != ProtocolMajor {
		t.Fatalf("hello result = %+v, %v", hr, err)
	}
}

func TestListenModes(t *testing.T) {
	path := sockPath(t)
	// A pre-existing, too open directory is tightened.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want socket 0600", fi.Mode())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
}

func TestListenRefusesSymlinkDir(t *testing.T) {
	d := shortDir(t)
	target := filepath.Join(d, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d, "run")); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(filepath.Join(d, "run", "x.sock")); err == nil {
		ln.Close()
		t.Fatal("listening through a symlinked directory was accepted")
	}
}

func TestSecondListenAlreadyRunning(t *testing.T) {
	path := sockPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ln2, err := Listen(path)
	if err == nil {
		ln2.Close()
		t.Fatal("second Listen succeeded")
	}
	if !errors.Is(err, ErrAlreadyRunning) || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err = %v", err)
	}
	// The live console's socket is still there and still serves.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("live socket broken: %v", err)
	}
	c.Close()
}

func TestStaleSocketReplaced(t *testing.T) {
	path := sockPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crashed console: the socket file stays, nobody listens.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket not left behind: %v", err)
	}
	ln2, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	defer ln2.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestListenRefusesNonSocket(t *testing.T) {
	path := sockPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(path); err == nil {
		ln.Close()
		t.Fatal("a regular file was replaced")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "not a socket" {
		t.Fatal("the regular file was touched")
	}
}

func TestCloseRemovesSocket(t *testing.T) {
	path := sockPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left after Close: %v", err)
	}
}

func TestPeerAllowedSelf(t *testing.T) {
	path := sockPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		ok  bool
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		defer c.Close()
		ok, err := PeerAllowed(c)
		ch <- res{ok, err}
	}()
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := <-ch
	if r.err != nil || !r.ok {
		t.Fatalf("PeerAllowed(self) = %v, %v", r.ok, r.err)
	}
}

func TestPeerAllowedRejectsNonUnix(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if ok, err := PeerAllowed(a); ok || err == nil {
		t.Fatalf("PeerAllowed(pipe) = %v, %v", ok, err)
	}
}

func TestListenShared(t *testing.T) {
	base, err := os.MkdirTemp("", "lsh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "run")
	if err := os.Mkdir(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	// macOS gives a new directory its parent's group, not the process's.
	if err := os.Chown(dir, -1, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.sock")
	ln, err := ListenShared(path, gid)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %04o, want 0660", fi.Mode().Perm())
	}
	ln.Close()

	for _, mode := range []os.FileMode{0o777, 0o711, 0o700} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if ln, err := ListenShared(path, gid); err == nil {
			ln.Close()
			t.Errorf("dir mode %04o accepted", mode)
		}
	}
	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	if ln, err := ListenShared(path, gid+1); err == nil {
		ln.Close()
		t.Error("a dir of another group accepted")
	}
}

// A setgid directory gives the socket its group at birth, so the console
// never needs to change it (Linux refuses a group the owner is not in).
func TestListenSharedSetgidDir(t *testing.T) {
	gid := -1
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != os.Getgid() {
			gid = g
			break
		}
	}
	if gid < 0 {
		t.Skip("needs a supplementary group")
	}
	base, err := os.MkdirTemp("", "lsg") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "run")
	if err := os.Mkdir(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o710|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode()&os.ModeSetgid == 0 {
		t.Skipf("cannot set setgid here: %v", err)
	}
	path := filepath.Join(dir, "x.sock")
	ln, err := ListenShared(path, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Gid) != gid || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket gid %d mode %04o, want %d 0660", st.Gid, fi.Mode().Perm(), gid)
	}
}

func TestSharedChownErrorNamesTheFix(t *testing.T) {
	err := sharedChownError("/run/locksql", 990, &os.PathError{Op: "chown", Path: "/run/locksql/x.sock", Err: syscall.EPERM})
	for _, want := range []string{"/run/locksql", "setgid", "2710", "sudo locksql install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Error("EPERM not wrapped")
	}
	if err := sharedChownError("/run/locksql", 990, syscall.EIO); strings.Contains(err.Error(), "setgid") {
		t.Errorf("non-EPERM error blames setgid: %v", err)
	}
}
