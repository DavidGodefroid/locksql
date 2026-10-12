package fingerprint

import (
	"bufio"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

const (
	fprintName    = "net.reactivated.Fprint"
	fprintManager = "/net/reactivated/Fprint/Manager"
	fprintDevice  = "/net/reactivated/Fprint/Device/0"
	ifaceManager  = "net.reactivated.Fprint.Manager"
	ifaceDevice   = "net.reactivated.Fprint.Device"
)

type fakeFprintd struct {
	mu        sync.Mutex
	conn      *dbus.Conn
	claimedBy string
	enrolled  map[string][]string
	statuses  [][2]any
	// emitBeforeVerifyStartReply are VerifyStatus signals emitted
	// synchronously inside VerifyStart, before its reply: stale signals a
	// client must drop.
	emitBeforeVerifyStartReply [][2]any
	// beforeVerifyStartReply runs inside VerifyStart after those signals and
	// before the reply, without f.mu held.
	beforeVerifyStartReply func()
	busy                   bool
	calls                  []string
}

func (f *fakeFprintd) record(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

// Manager
func (f *fakeFprintd) GetDefaultDevice() (dbus.ObjectPath, *dbus.Error) {
	f.record("GetDefaultDevice")
	return dbus.ObjectPath(fprintDevice), nil
}

// Device
func (f *fakeFprintd) Claim(user string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Claim:"+user)
	if f.busy || f.claimedBy != "" {
		return dbus.NewError("net.reactivated.Fprint.Error.AlreadyInUse", nil)
	}
	f.claimedBy = user
	return nil
}

func (f *fakeFprintd) Release() *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Release")
	f.claimedBy = ""
	return nil
}

func (f *fakeFprintd) ListEnrolledFingers(user string) ([]string, *dbus.Error) {
	f.record("ListEnrolledFingers:" + user)
	f.mu.Lock()
	fingers := f.enrolled[user]
	f.mu.Unlock()
	if len(fingers) == 0 {
		return nil, dbus.NewError("net.reactivated.Fprint.Error.NoEnrolledPrints", nil)
	}
	return fingers, nil
}

func (f *fakeFprintd) VerifyStart(finger string) *dbus.Error {
	f.mu.Lock()
	f.calls = append(f.calls, "VerifyStart:"+finger)
	if f.claimedBy == "" {
		f.mu.Unlock()
		return dbus.NewError("net.reactivated.Fprint.Error.ClaimDevice", nil)
	}
	statuses := f.statuses
	stale := f.emitBeforeVerifyStartReply
	hook := f.beforeVerifyStartReply
	conn := f.conn
	f.mu.Unlock()
	for _, st := range stale {
		_ = conn.Emit(dbus.ObjectPath(fprintDevice), ifaceDevice+".VerifyStatus", st[0], st[1])
	}
	if hook != nil {
		hook()
	}
	go func() {
		for _, st := range statuses {
			time.Sleep(5 * time.Millisecond)
			_ = conn.Emit(dbus.ObjectPath(fprintDevice), ifaceDevice+".VerifyStatus", st[0], st[1])
		}
	}()
	return nil
}

func (f *fakeFprintd) VerifyStop() *dbus.Error { f.record("VerifyStop"); return nil }

// configure changes the fake's behaviour under its mutex, so the change is
// ordered against the bus handlers (the race detector cannot see ordering
// through the socket).
func (f *fakeFprintd) configure(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func startFakeFprintd(t *testing.T) (string, *fakeFprintd) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not on PATH")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address", "--address=unix:path="+sock)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	addr = strings.TrimSpace(addr)

	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f := &fakeFprintd{conn: conn, enrolled: map[string][]string{"locksql": {"right-index-finger"}},
		statuses: [][2]any{{"verify-match", true}}}
	f.serve(t, conn)
	return addr, f
}

// serve exports the fake on conn and takes the fprintd name.
func (f *fakeFprintd) serve(t *testing.T, conn *dbus.Conn) {
	t.Helper()
	if err := conn.Export(f, dbus.ObjectPath(fprintManager), ifaceManager); err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(f, dbus.ObjectPath(fprintDevice), ifaceDevice); err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(introspect.Introspectable(""), dbus.ObjectPath(fprintDevice), "org.freedesktop.DBus.Introspectable"); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(fprintName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", reply, err)
	}
}

// restart simulates an idle fprintd exiting and coming back: the name moves
// to a new connection, hence a new unique name.
func (f *fakeFprintd) restart(t *testing.T, addr string) {
	t.Helper()
	f.mu.Lock()
	old := f.conn
	f.mu.Unlock()
	_ = old.Close()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f.mu.Lock()
	f.conn = conn
	f.mu.Unlock()
	f.serve(t, conn)
}

func TestFakeFprintdAnswersClaimAndVerify(t *testing.T) {
	addr, _ := startFakeFprintd(t)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var path dbus.ObjectPath
	if err := conn.Object(fprintName, dbus.ObjectPath(fprintManager)).Call(ifaceManager+".GetDefaultDevice", 0).Store(&path); err != nil {
		t.Fatal(err)
	}
	dev := conn.Object(fprintName, path)
	if err := dev.Call(ifaceDevice+".Claim", 0, "locksql").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(ifaceDevice+".Claim", 0, "locksql").Err; err == nil {
		t.Fatal("second Claim should fail with AlreadyInUse")
	}
	if err := dev.Call(ifaceDevice+".Release", 0).Err; err != nil {
		t.Fatal(err)
	}
}
