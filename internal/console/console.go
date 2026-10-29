// Package console is the human side of locksql: it holds the credentials
// and the only database connection, enforces the approved policy, shows
// every query to the human for approval, masks the results and writes the
// audit trail. Clients (the CLI and the MCP server) reach it over the
// per-profile socket and never see a secret.
package console

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"

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
	ApprovalTimeout = kconsole.ApprovalTimeout
	PlanTTL         = 10 * time.Minute
	// PolicyPoll is how often the config files are checked for changes.
	PolicyPoll = kconsole.PolicyPoll
)

// The console's terminal and its optional abilities (lockkit's console).
type (
	IO         = kconsole.IO
	Beller     = kconsole.Beller
	LineSource = kconsole.LineSource
	KeySource  = kconsole.KeySource
	StatusLine = kconsole.StatusLine
	Sized      = kconsole.Sized
)

// bell rings io's bell when it has one.
func bell(io IO) { kconsole.Bell(io) }

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
	// RulesPath is the file of the profile's PII rule set:
	// <project>/.locksql/pii/<set>.toml, or pii/<set>.toml in the user
	// config directory outside a project.
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
	// it masked. Ctrl-O switches them while the console runs. Ignored on
	// the desktop (Boundary set): levels 1 and 2 keep the results masked.
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
	// shadow are the functions and operators checkShadows looks up again
	// just before the run (nil: none to check).
	shadow *shadowNames
	// refs are the objects the statement names, and hash the plan hash:
	// the run checks it again in its own transaction (planhash.go).
	refs engine.ObjectRefs
	hash string
	// guarded: the engine read the definitions, and the run checks them.
	guarded bool
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
	// prompting counts the prompts waiting for the human (waiting).
	prompting int

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
		auto: cfg.Auto, showResults: cfg.ShowResults && cfg.Boundary == "", allowUnmask: cfg.AllowUnmask}
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

// noFingerFields is the audit text of a refusal for want of a finger; it
// is empty for any other outcome.
func noFingerFields(r Result) (reason, errText string) {
	if r.Outcome != NoFinger {
		return "", ""
	}
	return "no fingerprint", r.Err.Error()
}

// asker takes the human decisions of s (lockkit's console).
func (s *Server) asker() kconsole.Asker {
	return kconsole.Asker{IO: s.cfg.IO, Approver: s.approver, Profile: s.profile.Name, End: s.End, Waiting: s.waiting}
}

// waiting counts the prompts that wait for the human: a control key or a
// command meanwhile never widens a switch (widenRefused).
func (s *Server) waiting(on bool) {
	if on {
		s.prompting++
	} else {
		s.prompting--
	}
}

// decide asks the approver and explains a missing finger. Too many
// non-matching fingers end the console.
func (s *Server) decide(ctx context.Context, d Decision) Result { return s.asker().Decide(ctx, d) }

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

// Serve accepts clients on ln and serves their requests one at a time until
// ctx ends or the session ends (logout, timeouts, :quit). lines are the
// console commands typed by the human (nil for none); the control keys
// come from the IO when it is a KeySource. ln is closed on return, which
// removes the socket. It is lockkit's request loop.
func (s *Server) Serve(ctx context.Context, ln net.Listener, lines <-chan string) error {
	l := kconsole.Loop{
		IO: s.cfg.IO, Handle: s.Handle, Command: s.Command, Key: s.Key, Tick: s.Tick, Poll: s.CheckPolicy,
		Ended: func() bool { _, ended := s.Ended(); return ended }, End: s.End,
		Refresh: s.refreshStatus, Clear: s.clearStatus, PeerAllowed: s.cfg.PeerAllowed,
	}
	return l.Serve(ctx, ln, lines)
}

func errResp(id int64, code int, msg string) ipc.Response { return kconsole.ErrResp(id, code, msg) }

func okResp(id int64, v any) ipc.Response { return kconsole.OKResp(id, v) }
