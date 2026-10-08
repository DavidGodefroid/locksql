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

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Session timeouts, spec §6.
const (
	ApprovalTimeout = 5 * time.Minute
	IdleTimeout     = 20 * time.Minute
	MaxSession      = 4 * time.Hour
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

// LineSource is implemented by an IO that also delivers the lines the human
// types between requests (console commands such as :review).
type LineSource interface {
	Lines() <-chan string
}

// Options configure Run.
type Options struct {
	Profile         string
	SkipPermissions bool
	Cwd             string
	IO              IO
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
	// Root is the directory holding .locksql/pii.toml.
	Root string
	// StateDir and ApprovedKey locate the approved policy file.
	StateDir    string
	ApprovedKey string
	Session     engine.Session
	// DBUser is the database account in use (it may have been asked for).
	DBUser    string
	Databases []string
	Audit     *audit.Log
	IO        IO
	Now       func() time.Time
	// SkipPermissions auto-approves on non-production profiles (never
	// unmask, never REFUSE).
	SkipPermissions bool
	Version         string
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
	id      string
	db      string
	st      sqlclass.Statement
	level   string
	summary string
	reasons []string
	unmask  bool
	created time.Time
	explain *engine.Plan // the EXPLAIN result, assessed again when the plan runs
	// an is the analysis of a read statement (nil for other classes);
	// runSQL is the statement that runs (token values substituted) and
	// isExplain marks an EXPLAIN SELECT, answered with the plan.
	an        *sqlast.Analysis
	runSQL    string
	isExplain bool
}

// Server serves client requests one at a time against one session. It is
// not safe for concurrent use: Serve runs every request on one goroutine.
type Server struct {
	cfg       ServerConfig
	approved  config.Policy
	profile   config.Profile
	rules     pii.Rules
	detectors []pii.Detector
	dialect   sqlclass.Dialect
	sess      engine.Session
	now       func() time.Time

	plans    map[string]*plan
	started  time.Time
	lastSeen time.Time

	// tokens is the session's token table (mask mode hash); its key dies
	// with the console.
	tokens *pii.Tokens
	// catalogCache holds the column catalog per database for the analyser.
	catalogCache map[string][]engine.ColumnInfo
	// quantum levels response times (ResponseQuantum; 0 in tests).
	quantum time.Duration
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
	s := &Server{cfg: cfg, sess: cfg.Session, now: cfg.Now, plans: map[string]*plan{}, tokens: pii.NewTokens(), quantum: cfg.Quantum}
	if err := s.apply(cfg.Policy); err != nil {
		return nil, err
	}
	s.started = s.now()
	s.lastSeen = s.started
	s.connected = s.started
	if s.autoApprove() {
		s.println("--skip-permissions: statements allowed by the tier and the weight check run without a prompt")
	}
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

// autoApprove reports whether --skip-permissions is in effect: never on a
// production profile.
func (s *Server) autoApprove() bool { return s.cfg.SkipPermissions && !s.profile.Production }

// println writes one console line, with the AUTO-APPROVE marker while
// --skip-permissions is in effect.
func (s *Server) println(line string) {
	if s.autoApprove() {
		line = "AUTO-APPROVE " + line
	}
	s.cfg.IO.Println(line)
}

func (s *Server) audit(rec audit.Record) {
	rec.Profile = s.profile.Name
	rec.Engine = s.profile.Engine
	rec.Host = s.host()
	rec.DBUser = s.cfg.DBUser
	if err := s.cfg.Audit.Write(rec); err != nil {
		s.cfg.IO.Println("audit log write failed: " + err.Error())
	}
}

func (s *Server) host() string {
	if s.profile.Engine == config.EngineSQLite {
		return s.profile.Path
	}
	return s.profile.Host
}

// End stops the session after the current request.
func (s *Server) End(reason string) {
	if !s.ended {
		s.ended, s.reason = true, reason
	}
}

// Ended reports whether the session is over, and why.
func (s *Server) Ended() (string, bool) { return s.reason, s.ended }

// Tick ends the session on idle or maximum session timeout.
func (s *Server) Tick() {
	now := s.now()
	switch {
	case now.Sub(s.started) >= MaxSession:
		s.End("maximum session length")
	case now.Sub(s.lastSeen) >= IdleTimeout:
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
// console commands typed by the human (nil for none). ln is closed on
// return, which removes the socket.
func (s *Server) Serve(ctx context.Context, ln net.Listener, lines <-chan string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
		case <-tick.C:
			if time.Since(lastPoll) >= PolicyPoll {
				lastPoll = time.Now()
				s.CheckPolicy()
			}
			s.Tick()
		}
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
