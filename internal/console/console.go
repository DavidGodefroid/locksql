// Package console is the human side of locksql: it holds the credentials
// and the only database connection, enforces the approved policy, shows
// every query to the human for approval, masks the results and writes the
// audit trail. Clients (the CLI and the MCP server) reach it over the
// per-profile socket and never see a secret.
package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Session timeouts, spec §6.
const (
	// The idle timeout and the maximum session length are the profile's
	// limits.idle_timeout and limits.max_session.
	ApprovalTimeout = 5 * time.Minute
	PlanTTL         = 10 * time.Minute
	// PolicyPoll is how often the config files are checked for changes.
	PolicyPoll = 2 * time.Second
)

// IO is the console's terminal. Ask and AskSecret discard pending input
// before prompting, so type-ahead never answers a prompt.
type IO interface {
	Println(s string)
	// Ask prints prompt and reads one line. It returns false when no answer
	// came within timeout, when ctx ended (Ctrl-C, client gone) or when the
	// terminal is closed.
	Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool)
	// AskSecret reads a line with echo off.
	AskSecret(ctx context.Context, prompt string) ([]byte, error)
}

// Beller is implemented by an IO that can ring the terminal bell, so that
// a human away from the console notices a prompt waiting for them.
type Beller interface {
	Bell()
}

// bell rings io's bell when it has one.
func bell(io IO) {
	if b, ok := io.(Beller); ok {
		b.Bell()
	}
}

// LineSource is implemented by an IO that also delivers the lines the human
// types between requests (console commands such as :review).
type LineSource interface {
	Lines() <-chan string
}

// KeySource is implemented by an IO that reports the control keys pressed
// in the console: on Keys between prompts, to the handler during one.
type KeySource interface {
	Keys() <-chan Key
	SetKeyHandler(func(Key))
}

// StatusLine is implemented by an IO that keeps a status row on screen.
type StatusLine interface {
	SetStatus(string)
}

// Sized is implemented by an IO that knows its width in columns.
type Sized interface {
	Width() int
}

// Options configure Run.
type Options struct {
	Profile string
	// Auto starts the console in auto mode (--auto); Shift+Tab switches
	// the mode while it runs.
	Auto bool
	// AllowUnmask lets clients ask for unmasked output (--allow-unmask).
	AllowUnmask bool
	// ShowResults starts with the clear results on (--show-results);
	// Ctrl-O switches them while the console runs.
	ShowResults bool
	Cwd         string
	IO          IO
	// Now defaults to time.Now.
	Now func() time.Time
	// StateDir defaults to config.StateDir().
	StateDir string
	// Version is the console version reported to clients.
	Version string
	// TTY is the console's terminal device (nil when unknown): its owner
	// must be the console's account in a separated setup.
	TTY *os.File
}

// ServerConfig holds what a Server needs once the start-up sequence is
// done. Run builds it; tests build it directly.
type ServerConfig struct {
	// Policy is the approved policy the server enforces.
	Policy config.Policy
	// RulesPath is the PII rules file: <project>/.locksql/pii.toml, or
	// pii.toml in the user config directory outside a project.
	RulesPath string
	// StateDir and ApprovedKey locate the approved policy file.
	StateDir    string
	ApprovedKey string
	Session     engine.Session
	// DBUser is the database account in use (it may have been asked for).
	DBUser    string
	Databases []string
	Audit     *audit.Log
	IO        IO
	// Approver takes every human decision; nil means typed approvals.
	Approver Approver
	// Fingerprint is true when Approver is the fingerprint approver
	// (level 2): a typed answer alone then never widens anything.
	Fingerprint bool
	// Boundary names the desktop boundary for the status screen ("" in
	// the session shape).
	Boundary string
	Now      func() time.Time
	// Auto starts in auto mode: on non-production profiles, statements
	// allowed by the tier and the weight check run without a prompt (never
	// unmask, never REFUSE). Shift+Tab switches the mode while the console
	// runs.
	Auto bool
	// AllowUnmask starts with unmasked output allowed: clients may ask for
	// it, and each such query is approved in the console. Without it an
	// unmask plan is refused before anything else. :unmask switches it
	// while the console runs.
	AllowUnmask bool
	// ShowResults starts with the clear results on: the result of each
	// masked run printed in the console, in clear; the client still gets
	// it masked. Ctrl-O switches them while the console runs.
	ShowResults bool
	Version     string
	// LoadPolicy re-reads the current policy from the config files. Nil
	// disables CheckPolicy.
	LoadPolicy func() (config.Policy, error)
	// Reconnect opens a new session after a lost connection, under p, the
	// profile in force at that time. Nil means a lost connection ends the
	// console.
	Reconnect func(ctx context.Context, p config.Profile) (engine.Session, error)
	// Quantum levels the response time of query.run (ResponseQuantum in
	// the real console, 0 to disable).
	Quantum time.Duration
	// PeerAllowed decides which clients are served, from the kernel's
	// credentials of the peer. Nil serves the console's own account only.
	PeerAllowed func(ipc.Cred) bool
	// Health is reported in status for locksql doctor.
	Health *ipc.Health
}

// plan is a one-shot plan awaiting query.run.
type plan struct {
	id       string
	db       string
	st       sqlclass.Statement
	level    string
	summary  string
	reasons  []string
	unmask   bool
	created  time.Time
	warnings []string
	intent   string       // the agent's one-line reason, shown and audited
	explain  *engine.Plan // the EXPLAIN result, assessed again when the plan runs
	// kExplains are the EXPLAIN results of the k-anonymity counts, assessed
	// again when the plan runs.
	kExplains []engine.Plan
	// an is the analysis of a read statement, or of a write whose rows
	// come back or that stores a query's rows (nil otherwise);
	// runSQL is the statement that runs; isExplain marks an EXPLAIN
	// SELECT, answered with the plan.
	an        *sqlast.Analysis
	runSQL    string
	isExplain bool
	// src is the statement as the agent sent it, and base the offset in
	// it of the statement the checks read: refusals point into src.
	src  string
	base int
}

// Server serves client requests one at a time against one session. It is
// not safe for concurrent use: Serve runs every request on one goroutine.
type Server struct {
	cfg       ServerConfig
	approver  Approver
	approved  config.Policy
	profile   config.Profile
	rules     pii.Rules
	detectors []pii.Detector
	dialect   sqlclass.Dialect
	sess      engine.Session
	now       func() time.Time

	// refs keeps the values behind the references of redacted cells.
	refs refStore
	// typed keeps the values the human typed for placeholder names.
	typed map[string]typedValue
	// probes are, per result number, the reference uses seen as filters
	// (a single reference, or one IN list of references).
	probes map[int]map[string]bool
	// keys caches whether "db.table.column" is a one-column unique key.
	keys map[string]bool

	plans    map[string]*plan
	started  time.Time
	lastSeen time.Time

	// catalogCache holds the column catalog per database for the analyser.
	catalogCache map[string][]engine.ColumnInfo
	// quantum levels response times (ResponseQuantum; 0 in tests).
	quantum time.Duration
	// auto, showResults and allowUnmask are the live switches (modes.go),
	// started from the config and changed from the console's keyboard only.
	auto        bool
	showResults bool
	allowUnmask bool
	// connected is when the current connection was opened (credentials_ttl).
	connected time.Time

	// pending is a loosening policy read from the files that awaits :review.
	pending *config.Policy
	// refused is the fingerprint of the last loosening the human refused, so
	// that it is not announced again until the files change.
	refused string
	// requests are change.request proposals from clients.
	requests []string
	// lastLoadErr avoids repeating the same config error every poll.
	lastLoadErr string

	ended  bool
	reason string
}

// NewServer checks cfg and returns a server enforcing cfg.Policy.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Session == nil || cfg.IO == nil || cfg.Audit == nil {
		return nil, errors.New("console: server needs a session, an IO and an audit log")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Approver == nil {
		cfg.Approver = newTypedApprover(cfg.IO)
	}
	cfg.Databases = servedDatabases(cfg.Policy.Profile.Database, cfg.Databases)
	s := &Server{cfg: cfg, approver: cfg.Approver, sess: cfg.Session, now: cfg.Now, plans: map[string]*plan{}, typed: map[string]typedValue{}, probes: map[int]map[string]bool{}, keys: map[string]bool{}, quantum: cfg.Quantum,
		auto: cfg.Auto, showResults: cfg.ShowResults, allowUnmask: cfg.AllowUnmask}
	if err := s.apply(cfg.Policy); err != nil {
		return nil, err
	}
	s.started = s.now()
	s.lastSeen = s.started
	s.connected = s.started
	if s.autoApprove() {
		s.println(paint.Yellow("auto mode: statements allowed by the tier and the weight check run without a prompt (Shift+Tab: manual)"))
	}
	s.refreshStatus()
	return s, nil
}

// apply makes p the enforced policy.
func (s *Server) apply(p config.Policy) error {
	d, err := sqlclass.DialectFor(p.Profile.Engine)
	if err != nil {
		return err
	}
	ds, err := pii.Detectors(p.Profile.Detectors)
	if err != nil {
		return err
	}
	s.approved = p
	s.profile = p.Profile
	s.rules = pii.Rules{Mask: append([]string(nil), p.PIIMask...), Allow: append([]string(nil), p.PIIAllow...), Modes: p.PIIModes}
	s.detectors = ds
	s.dialect = d
	return nil
}

// println writes one console line.
func (s *Server) println(line string) { s.cfg.IO.Println(line) }

func (s *Server) audit(rec audit.Record) {
	rec.Profile = s.profile.Name
	rec.Engine = s.profile.Engine
	rec.Host = s.host()
	rec.DBUser = s.cfg.DBUser
	// A login read from Vault names its own user, new at every connection.
	if u, ok := s.sess.(interface{ DBUser() string }); ok && u.DBUser() != "" {
		rec.DBUser = u.DBUser()
	}
	if err := s.cfg.Audit.Append(rec); err != nil {
		s.cfg.IO.Println("audit log write failed: " + err.Error())
	}
}

func (s *Server) host() string {
	if s.profile.Engine == config.EngineSQLite {
		return s.profile.Path
	}
	return s.profile.Host
}

// explainNoFinger tells the human why a finger did not approve.
func explainNoFinger(println func(string), r Result) {
	println(paint.Fail("denied: " + safeText(r.Err.Error(), false)))
}

// noFingerFields is the audit text of a refusal for want of a finger; it
// is empty for any other outcome.
func noFingerFields(r Result) (reason, errText string) {
	if r.Outcome != NoFinger {
		return "", ""
	}
	return "no fingerprint", r.Err.Error()
}

// decide asks the approver and explains a missing finger. Too many
// non-matching fingers end the console.
func (s *Server) decide(ctx context.Context, d Decision) Result {
	r := s.approver.Approve(ctx, d)
	if r.Outcome == NoFinger {
		explainNoFinger(s.println, r)
		if errors.Is(r.Err, ErrTooManyNoMatch) {
			s.End("fingerprint: three non-matching fingers")
		}
	}
	return r
}

// End stops the session after the current request.
func (s *Server) End(reason string) {
	if !s.ended {
		s.ended, s.reason = true, reason
	}
}

// Ended reports whether the session is over, and why.
func (s *Server) Ended() (string, bool) { return s.reason, s.ended }

// Tick ends the session on idle or maximum session timeout, as set by the
// policy in force: a policy change applies from the next tick.
func (s *Server) Tick() {
	now := s.now()
	l := s.profile.Limits
	switch {
	case now.Sub(s.started) >= l.MaxSession:
		s.End("maximum session length")
	case now.Sub(s.lastSeen) >= l.IdleTimeout:
		s.End("idle timeout")
	}
}

// job is one request handed from a connection to the console goroutine.
type job struct {
	ctx  context.Context
	req  ipc.Request
	resp chan ipc.Response
}

// flushWait bounds how long an ending session waits for the last responses
// (such as the answer to logout) to reach their clients.
const flushWait = 2 * time.Second

// Serve accepts clients on ln and serves their requests one at a time until
// ctx ends or the session ends (logout, timeouts, :quit). lines are the
// console commands typed by the human (nil for none); the control keys
// come from the IO when it is a KeySource. ln is closed on return, which
// removes the socket.
func (s *Server) Serve(ctx context.Context, ln net.Listener, lines <-chan string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var keys <-chan Key
	if ks, ok := s.cfg.IO.(KeySource); ok {
		keys = ks.Keys()
		ks.SetKeyHandler(s.Key)
	}
	s.refreshStatus()
	defer s.clearStatus()
	jobs := make(chan job)
	// inflight counts responses handed to connections but not yet written.
	var wg, inflight sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.accept(ctx, ln, jobs, &wg, &inflight)
	}()
	defer func() {
		ln.Close()
		waitFor(&inflight, flushWait)
		cancel()
		wg.Wait()
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastPoll := time.Now()
	for {
		if _, ended := s.Ended(); ended {
			return nil
		}
		select {
		case <-ctx.Done():
			s.End("interrupted")
			return nil
		case j := <-jobs:
			inflight.Add(1)
			if j.ctx.Err() != nil {
				j.resp <- errResp(j.req.ID, ipc.CodeDenied, "client gone")
				continue
			}
			j.resp <- s.Handle(j.ctx, j.req)
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			s.Command(ctx, line)
		case k := <-keys:
			s.Key(k)
		case <-tick.C:
			if time.Since(lastPoll) >= PolicyPoll {
				lastPoll = time.Now()
				s.CheckPolicy()
			}
			s.Tick()
		}
		s.refreshStatus()
	}
}

// waitFor waits for wg, at most d.
func waitFor(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func (s *Server) accept(ctx context.Context, ln net.Listener, jobs chan<- job, wg, inflight *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept errors: back off briefly.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		cred, err := ipc.PeerCred(c)
		if err != nil || !s.peerAllowed(cred) {
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(withPeer(ctx, cred), c, jobs, inflight)
		}()
	}
}

// peerAllowed applies the peer check: the configured one, or the console's
// own account.
func (s *Server) peerAllowed(c ipc.Cred) bool {
	if s.cfg.PeerAllowed != nil {
		return s.cfg.PeerAllowed(c)
	}
	return c.UID == os.Getuid()
}

// maxQueued bounds the requests a client may pipeline behind the one being
// served.
const maxQueued = 32

type readResult struct {
	req ipc.Request
	err error
}

// serveConn reads requests from c and hands them to the console goroutine
// one by one. While a request is being served, the next read doubles as a
// probe: a closed connection cancels the request's context, which cancels
// a pending approval prompt. Every response received from the console
// goroutine is marked done on inflight once written (or dropped).
func serveConn(ctx context.Context, c net.Conn, jobs chan<- job, inflight *sync.WaitGroup) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	msgs := make(chan readResult, 1)
	done := make(chan struct{}) // ends the reader when serveConn returns
	defer close(done)
	go func() {
		r := bufio.NewReader(c)
		for {
			var req ipc.Request
			err := ipc.ReadMsg(r, &req)
			select {
			case msgs <- readResult{req, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	var queue []readResult
	next := func() (readResult, bool) {
		if len(queue) > 0 {
			m := queue[0]
			queue = queue[1:]
			return m, true
		}
		select {
		case m := <-msgs:
			return m, true
		case <-ctx.Done():
			return readResult{}, false
		}
	}
	gone := false
	for !gone {
		m, ok := next()
		if !ok {
			return
		}
		if m.err != nil {
			if !errors.Is(m.err, io.EOF) && !errors.Is(m.err, net.ErrClosed) {
				_ = ipc.WriteMsg(c, errResp(0, ipc.CodeParseError, "invalid message"))
			}
			return
		}
		jctx, jcancel := context.WithCancel(ctx)
		j := job{ctx: jctx, req: m.req, resp: make(chan ipc.Response, 1)}
		// While the job waits for the console (another client's approval
		// may be pending), keep reading: a client that leaves meanwhile
		// never gets its statement run.
	handoff:
		for {
			select {
			case jobs <- j:
				break handoff
			case m2 := <-msgs:
				if m2.err != nil {
					jcancel()
					return
				}
				if len(queue) >= maxQueued {
					jcancel()
					_ = ipc.WriteMsg(c, errResp(m2.req.ID, ipc.CodeInvalidRequest, "too many pipelined requests"))
					return
				}
				queue = append(queue, m2)
			case <-ctx.Done():
				jcancel()
				return
			}
		}
		var resp ipc.Response
	wait:
		for {
			select {
			case resp = <-j.resp:
				break wait
			case m2 := <-msgs:
				if m2.err != nil {
					// The client is gone: cancel the request, then still
					// wait for the console to finish with it.
					gone = true
					jcancel()
					continue
				}
				if len(queue) >= maxQueued {
					// Too many pipelined requests: drop the client once
					// the console is done with the current one.
					gone = true
					jcancel()
					continue
				}
				queue = append(queue, m2)
			}
		}
		jcancel()
		if gone {
			inflight.Done()
			return
		}
		err := ipc.WriteMsg(c, resp)
		if errors.Is(err, ipc.ErrTooLarge) {
			err = ipc.WriteMsg(c, errResp(resp.ID, ipc.CodeInternal,
				"result larger than 1 MiB: lower limits.max_output_bytes or select fewer columns"))
		}
		inflight.Done()
		if err != nil {
			return
		}
	}
}

func errResp(id int64, code int, msg string) ipc.Response {
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

func okResp(id int64, v any) ipc.Response {
	b, err := json.Marshal(v)
	if err != nil {
		return errResp(id, ipc.CodeInternal, fmt.Sprintf("encode result: %v", err))
	}
	return ipc.Response{JSONRPC: "2.0", ID: id, Result: b}
}
