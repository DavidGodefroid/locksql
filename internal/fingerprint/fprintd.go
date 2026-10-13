//go:build linux

package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName       = "net.reactivated.Fprint"
	managerPath   = dbus.ObjectPath("/net/reactivated/Fprint/Manager")
	managerIface  = "net.reactivated.Fprint.Manager"
	deviceIface   = "net.reactivated.Fprint.Device"
	errInUse      = "net.reactivated.Fprint.Error.AlreadyInUse"
	errNoPrints   = "net.reactivated.Fprint.Error.NoEnrolledPrints"
	claimInterval = 500 * time.Millisecond
	// cleanupTimeout bounds VerifyStop and Release, which must run even
	// after the caller's context has ended.
	cleanupTimeout = 3 * time.Second
	// activationTimeout bounds the first call, which may start fprintd.
	activationTimeout = 15 * time.Second
	// maxPending is the most unread VerifyStatus signals tolerated before
	// the verification fails closed.
	maxPending = 64
)

// Options configures NewFprintd. Zero values: the system bus, the name
// owner must run as uid 0. User is required: an empty User is an error.
type Options struct {
	// Address overrides the system bus (tests). Empty: dbus.SystemBus.
	Address string
	// User is the account whose prints must match. Required.
	User string
	// OwnerUID is the uid the name owner must run as; -1 disables the check.
	OwnerUID int
}

// Fprintd verifies through the fprintd service on the system bus.
type Fprintd struct {
	conn     *dbus.Conn
	user     string
	ownerUID int
	device   dbus.ObjectPath
	queue    *statusQueue
	verifyMu sync.Mutex // one verification at a time on this connection
}

// NewFprintd connects, activates fprintd if needed and resolves the default
// device. ErrUnavailable wraps every failure: no bus, no fprintd, no reader,
// wrong owner.
func NewFprintd(o Options) (*Fprintd, error) {
	if o.User == "" {
		return nil, errors.New("fingerprint: Options.User is required")
	}
	q := newStatusQueue()
	var conn *dbus.Conn
	var err error
	if o.Address != "" {
		conn, err = dbus.Connect(o.Address, dbus.WithSignalHandler(q))
	} else {
		conn, err = dbus.ConnectSystemBus(dbus.WithSignalHandler(q))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	f := &Fprintd{conn: conn, user: o.User, ownerUID: o.OwnerUID, queue: q}
	ctx, cancel := context.WithTimeout(context.Background(), activationTimeout)
	defer cancel()
	// fprintd is bus-activated and exits when idle: this first call starts
	// it, so the name has an owner to resolve.
	if err := conn.Object(busName, managerPath).CallWithContext(ctx, managerIface+".GetDefaultDevice", 0).Store(&f.device); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: no fingerprint reader: %v", ErrUnavailable, err)
	}
	if _, err := f.resolveOwner(ctx); err != nil {
		conn.Close()
		if !errors.Is(err, ErrUnavailable) {
			// An activation deadline: the reader did not answer.
			err = fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return nil, err
	}
	return f, nil
}

// resolveOwner returns the unique name that currently owns the fprintd name
// and checks its uid (unless disabled). It is re-run on every Verify since
// an idle fprintd exits and comes back under a new unique name.
func (f *Fprintd) resolveOwner(ctx context.Context) (string, error) {
	bus := f.conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	var owner string
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, busName).Store(&owner); err != nil {
		return "", f.unavailable(ctx, "fprintd is not on the bus", err)
	}
	if f.ownerUID >= 0 {
		var uid uint32
		if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid); err != nil {
			return "", f.unavailable(ctx, "cannot read fprintd's uid", err)
		}
		if int(uid) != f.ownerUID {
			return "", fmt.Errorf("%w: %w: fprintd runs as uid %d, expected %d", ErrUnavailable, ErrWrongOwner, uid, f.ownerUID)
		}
	}
	return owner, nil
}

// unavailable maps a failed bus call: a finished context is a timeout or a
// cancellation, anything else is ErrUnavailable.
func (f *Fprintd) unavailable(ctx context.Context, what string, err error) error {
	if ctx.Err() != nil {
		return deadlineErr(ctx)
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, what, err)
}

// Close releases the bus connection.
func (f *Fprintd) Close() error { return f.conn.Close() }

// Enrolled is the number of prints enrolled for the console account.
func (f *Fprintd) Enrolled(ctx context.Context) (int, error) {
	var fingers []string
	err := f.conn.Object(busName, f.device).CallWithContext(ctx, deviceIface+".ListEnrolledFingers", 0, f.user).Store(&fingers)
	if err != nil {
		if isDBusError(err, errNoPrints) {
			return 0, ErrNotEnrolled
		}
		return 0, f.unavailable(ctx, "ListEnrolledFingers", err)
	}
	if len(fingers) == 0 {
		return 0, ErrNotEnrolled
	}
	return len(fingers), nil
}

// Verify claims the reader, starts a verification, calls onReady, and
// waits for the result. The reader is always released.
func (f *Fprintd) Verify(ctx context.Context, onReady func()) error {
	f.verifyMu.Lock()
	defer f.verifyMu.Unlock()
	if _, err := f.Enrolled(ctx); err != nil {
		return err
	}
	if err := f.claim(ctx); err != nil {
		return err
	}
	// The owner may have restarted since NewFprintd: pin the one holding the
	// claim now, address this verification to it and trust only its signals.
	owner, err := f.resolveOwner(ctx)
	if err != nil {
		f.release(busName)
		return err
	}
	defer f.stopAndRelease(owner)
	dev := f.conn.Object(owner, f.device)

	f.queue.arm(owner, f.device)
	defer f.queue.disarm()
	match := []dbus.MatchOption{dbus.WithMatchSender(owner), dbus.WithMatchObjectPath(f.device), dbus.WithMatchInterface(deviceIface), dbus.WithMatchMember("VerifyStatus")}
	if err := f.conn.AddMatchSignalContext(ctx, match...); err != nil {
		return f.unavailable(ctx, "AddMatch", err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = f.conn.RemoveMatchSignalContext(cctx, match...)
	}()

	if err := dev.CallWithContext(ctx, deviceIface+".VerifyStart", 0, "any").Err; err != nil {
		return f.unavailable(ctx, "VerifyStart", err)
	}
	// The statusQueue runs in the connection's reader goroutine, which sees
	// messages in bus order: every signal queued before this point was
	// emitted before the VerifyStart reply (a late finger from a stopped
	// verification). Only signals numbered after the mark can approve.
	seen := f.queue.mark()
	// The reader is ours and listening: now, and only now, the human may
	// be asked to touch it.
	if onReady != nil {
		onReady()
	}

	for {
		st, overflow, ok := f.queue.pop(seen)
		if overflow {
			return fmt.Errorf("%w: too many VerifyStatus signals", ErrUnavailable)
		}
		if !ok {
			select {
			case <-ctx.Done():
				return deadlineErr(ctx)
			case <-f.queue.notify:
			}
			continue
		}
		if !st.done {
			continue
		}
		switch st.result {
		case "verify-match":
			return nil
		case "verify-no-match":
			return ErrNoMatch
		default:
			return fmt.Errorf("%w: verification ended with %q", ErrUnavailable, st.result)
		}
	}
}

// stopAndRelease ends the verification and frees the reader, whatever the
// state of the caller's context. fprintd tolerates a stop without a start.
func (f *Fprintd) stopAndRelease(owner string) {
	dev := f.conn.Object(owner, f.device)
	// Each call gets its own budget: a VerifyStop that runs out its time
	// must not leave Release with none, or the reader stays claimed.
	for _, method := range []string{".VerifyStop", ".Release"} {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		_ = dev.CallWithContext(ctx, deviceIface+method, 0).Err
		cancel()
	}
}

// release is a best-effort Release addressed to dest.
func (f *Fprintd) release(dest string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_ = f.conn.Object(dest, f.device).CallWithContext(ctx, deviceIface+".Release", 0).Err
}

// claim takes the reader, retrying while another client holds it.
func (f *Fprintd) claim(ctx context.Context) error {
	busy := false
	for {
		err := f.conn.Object(busName, f.device).CallWithContext(ctx, deviceIface+".Claim", 0, f.user).Err
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			// The grant may have happened with the reply lost.
			f.release(busName)
			if busy {
				return fmt.Errorf("%w: %v", ErrBusy, deadlineErr(ctx))
			}
			return deadlineErr(ctx)
		}
		if !isDBusError(err, errInUse) {
			return fmt.Errorf("%w: Claim: %v", ErrUnavailable, err)
		}
		busy = true
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrBusy, deadlineErr(ctx))
		case <-time.After(claimInterval):
		}
	}
}

func isDBusError(err error, name string) bool {
	var de dbus.Error
	return errors.As(err, &de) && de.Name == name
}

type status struct {
	seq    uint64
	result string
	done   bool
}

// statusQueue is the connection's dbus.SignalHandler. DeliverSignal runs
// synchronously in the reader goroutine, so sequence numbers follow the
// order messages arrived on the connection, independent of scheduling. Only
// well-formed VerifyStatus signals from the armed owner on the device path
// are kept.
type statusQueue struct {
	notify chan struct{}

	mu       sync.Mutex
	owner    string
	path     dbus.ObjectPath
	seq      uint64
	pending  []status
	overflow bool
}

func newStatusQueue() *statusQueue { return &statusQueue{notify: make(chan struct{}, 1)} }

func (q *statusQueue) DeliverSignal(iface, name string, sig *dbus.Signal) {
	if iface != deviceIface || name != "VerifyStatus" || len(sig.Body) != 2 {
		return
	}
	result, ok1 := sig.Body[0].(string)
	done, ok2 := sig.Body[1].(bool)
	if !ok1 || !ok2 {
		return
	}
	q.mu.Lock()
	if q.owner == "" || sig.Sender != q.owner || sig.Path != q.path {
		q.mu.Unlock()
		return
	}
	q.seq++
	if len(q.pending) >= maxPending {
		q.overflow = true
	} else {
		q.pending = append(q.pending, status{seq: q.seq, result: result, done: done})
	}
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// arm starts a verification: only signals from owner on path are kept.
func (q *statusQueue) arm(owner string, path dbus.ObjectPath) {
	q.mu.Lock()
	q.owner, q.path, q.pending, q.overflow = owner, path, nil, false
	q.mu.Unlock()
}

func (q *statusQueue) disarm() {
	q.mu.Lock()
	q.owner, q.pending = "", nil
	q.mu.Unlock()
}

// mark discards everything queued so far and returns the current sequence
// number; only signals numbered above it count.
func (q *statusQueue) mark() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = nil
	return q.seq
}

// pop returns the oldest pending status newer than seen.
func (q *statusQueue) pop(seen uint64) (st status, overflow, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.overflow {
		return status{}, true, false
	}
	for len(q.pending) > 0 {
		st, q.pending = q.pending[0], q.pending[1:]
		if st.seq > seen {
			return st, false, true
		}
	}
	return status{}, false, false
}
