//go:build linux

package fingerprint

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func newTestVerifier(t *testing.T, addr string) *Fprintd {
	t.Helper()
	v, err := NewFprintd(Options{Address: addr, User: "locksql", OwnerUID: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func TestVerifierMatch(t *testing.T) {
	addr, f := startFakeFprintd(t)
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := v.Verify(ctx, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := []string{"GetDefaultDevice", "ListEnrolledFingers:locksql", "Claim:locksql", "VerifyStart:any", "VerifyStop", "Release"}
	f.mu.Lock()
	got := append([]string(nil), f.calls...)
	f.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

func TestVerifierNoMatch(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.statuses = [][2]any{{"verify-no-match", true}} })
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := v.Verify(ctx, nil); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("got %v, want ErrNoMatch", err)
	}
}

func TestVerifierIntermediateStatusIsNotDone(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.statuses = [][2]any{{"verify-retry-scan", false}, {"verify-match", true}} })
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := v.Verify(ctx, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifierTimeoutStopsAndReleases(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.statuses = nil }) // never done
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := v.Verify(ctx, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimedBy != "" {
		t.Fatal("device not released after timeout")
	}
	last2 := f.calls[len(f.calls)-2:]
	if last2[0] != "VerifyStop" || last2[1] != "Release" {
		t.Fatalf("tail = %v", last2)
	}
}

// onReady runs after the reader is claimed and listening, before any
// result; a busy reader never calls it.
func TestVerifierOnReadyAfterClaim(t *testing.T) {
	addr, f := startFakeFprintd(t)
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var atReady []string
	err := v.Verify(ctx, func() {
		f.mu.Lock()
		atReady = append([]string(nil), f.calls...)
		f.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(atReady) == 0 {
		t.Fatal("onReady was never called")
	}
	last := atReady[len(atReady)-1]
	if last != "VerifyStart:any" {
		t.Fatalf("onReady ran with calls %v, want VerifyStart last", atReady)
	}
	addr2, f2 := startFakeFprintd(t)
	f2.configure(func() { f2.busy = true })
	v2 := newTestVerifier(t, addr2)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel2()
	if err := v2.Verify(ctx2, func() { t.Error("onReady on a busy reader") }); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
}

func TestVerifierBusyRetriesThenTimesOut(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.busy = true })
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	err := v.Verify(ctx, nil)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
	f.mu.Lock()
	claims := 0
	for _, c := range f.calls {
		if c == "Claim:locksql" {
			claims++
		}
	}
	f.mu.Unlock()
	if claims < 2 {
		t.Fatalf("claims = %d, want a retry", claims)
	}
}

func TestVerifierNotEnrolled(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.enrolled = map[string][]string{} })
	v := newTestVerifier(t, addr)
	if n, err := v.Enrolled(context.Background()); n != 0 || !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Enrolled = %d, %v", n, err)
	}
	if err := v.Verify(context.Background(), nil); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Verify = %v", err)
	}
}

func TestVerifierIgnoresForeignSignals(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.statuses = nil })
	// Another connection on the bus emits a matching VerifyStatus after the
	// verification started: it is not the name owner and must be ignored.
	other, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = v.Verify(ctx, func() {
		_ = other.Emit(dbus.ObjectPath(fprintDevice), ifaceDevice+".VerifyStatus", "verify-match", true)
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout (foreign signal ignored)", err)
	}
}

// A match emitted before the VerifyStart reply (a late finger from the
// previous, stopped verification) must not approve this one.
func TestVerifierDropsSignalsQueuedBeforeVerifyStart(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() {
		f.statuses = nil
		f.emitBeforeVerifyStartReply = [][2]any{{"verify-match", true}}
	})
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := v.Verify(ctx, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout (stale match ignored)", err)
	}
}

// A flood of foreign signals must not push the owner's stale match past the
// drain: ordering is by sequence number, not by channel timing.
func TestVerifierStaleMatchSurvivesForeignFlood(t *testing.T) {
	addr, f := startFakeFprintd(t)
	other, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.configure(func() {
		f.statuses = nil
		f.emitBeforeVerifyStartReply = [][2]any{{"verify-match", true}}
		f.beforeVerifyStartReply = func() {
			for i := 0; i < 8; i++ {
				_ = other.Emit(dbus.ObjectPath(fprintDevice), ifaceDevice+".VerifyStatus", "verify-retry-scan", false)
			}
		}
	})
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := v.Verify(ctx, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout (stale match ignored)", err)
	}
}

// fprintd is bus-activated and exits when idle: a later Verify must follow
// the name to its new owner.
func TestVerifierFollowsOwnerRestart(t *testing.T) {
	addr, f := startFakeFprintd(t)
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := v.Verify(ctx, nil); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	f.restart(t, addr)
	if err := v.Verify(ctx, nil); err != nil {
		t.Fatalf("Verify after restart: %v", err)
	}
}

func TestVerifierDisconnectedIsUnavailable(t *testing.T) {
	addr, f := startFakeFprintd(t)
	f.configure(func() { f.statuses = [][2]any{{"verify-disconnected", true}} })
	v := newTestVerifier(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := v.Verify(ctx, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestNewFprintdChecksOwnerUID(t *testing.T) {
	addr, _ := startFakeFprintd(t)
	v, err := NewFprintd(Options{Address: addr, User: "locksql", OwnerUID: os.Getuid()})
	if err != nil {
		t.Fatalf("matching uid: %v", err)
	}
	_ = v.Close()
	if _, err := NewFprintd(Options{Address: addr, User: "locksql", OwnerUID: os.Getuid() + 1}); !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("wrong uid: got %v, want ErrUnavailable and ErrWrongOwner", err)
	}
}

func TestNewFprintdUnavailableWithoutService(t *testing.T) {
	_, err := NewFprintd(Options{Address: "unix:path=/nonexistent/bus", User: "locksql", OwnerUID: -1})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

// DeliverSignal keeps only VerifyStatus signals from the armed owner on the
// armed path, numbered in arrival order.
func TestStatusQueueDeliverSignal(t *testing.T) {
	q := newStatusQueue()
	path := dbus.ObjectPath(fprintDevice)
	sig := func(sender string, p dbus.ObjectPath, result string) *dbus.Signal {
		return &dbus.Signal{Sender: sender, Path: p, Name: ifaceDevice + ".VerifyStatus", Body: []any{result, true}}
	}
	q.DeliverSignal(ifaceDevice, "VerifyStatus", sig(":1.5", path, "verify-match")) // not armed yet
	q.arm(":1.5", path)
	q.DeliverSignal(ifaceDevice, "VerifyStatus", sig(":1.9", path, "verify-match"))                        // foreign sender
	q.DeliverSignal(ifaceDevice, "VerifyStatus", sig(":1.5", "/net/reactivated/Fprint/Device/1", "x"))     // wrong path
	q.DeliverSignal("other.Interface", "VerifyStatus", sig(":1.5", path, "verify-match"))                  // wrong interface
	q.DeliverSignal(ifaceDevice, "VerifyStatus", &dbus.Signal{Sender: ":1.5", Path: path, Body: []any{1}}) // malformed
	if _, _, ok := q.pop(0); ok {
		t.Fatal("a dropped signal was queued")
	}
	q.DeliverSignal(ifaceDevice, "VerifyStatus", sig(":1.5", path, "verify-no-match"))
	q.DeliverSignal(ifaceDevice, "VerifyStatus", sig(":1.5", path, "verify-match"))
	a, _, ok1 := q.pop(0)
	b, _, ok2 := q.pop(0)
	if !ok1 || !ok2 || a.result != "verify-no-match" || b.result != "verify-match" || b.seq <= a.seq {
		t.Fatalf("got %+v (%v), %+v (%v)", a, ok1, b, ok2)
	}
}
