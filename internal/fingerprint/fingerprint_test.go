package fingerprint

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFakeReturnsResultsInOrderThenNil(t *testing.T) {
	f := &Fake{Results: []error{ErrNoMatch, nil}}
	if err := f.Verify(context.Background(), nil); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("first: %v", err)
	}
	if err := f.Verify(context.Background(), nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	if err := f.Verify(context.Background(), nil); err != nil {
		t.Fatalf("past the end: %v", err)
	}
	if f.Calls != 3 {
		t.Fatalf("calls = %d", f.Calls)
	}
}

func TestFakeCallsOnReadyBeforeTheResult(t *testing.T) {
	f := &Fake{Results: []error{ErrNoMatch}}
	ready := false
	if err := f.Verify(context.Background(), func() { ready = true }); !errors.Is(err, ErrNoMatch) || !ready || f.Ready != 1 {
		t.Fatalf("err %v ready %v count %d", err, ready, f.Ready)
	}
	g := &Fake{Results: []error{ErrBusy}, NeverReady: true}
	if err := g.Verify(context.Background(), func() { t.Fatal("onReady on a busy reader") }); !errors.Is(err, ErrBusy) {
		t.Fatalf("err %v", err)
	}
}

func TestFakeBlockHonoursDeadline(t *testing.T) {
	f := &Fake{Block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.Verify(ctx, nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := f.Verify(ctx2, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestFakeEnrolled(t *testing.T) {
	f := &Fake{EnrolledN: 2}
	n, err := f.Enrolled(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("got %d, %v", n, err)
	}
}
