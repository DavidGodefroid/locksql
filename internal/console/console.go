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
	"sync"
	"sync/atomic"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/secrets"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/product"
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
	// PIIDir, when set (PIIDirEnv), is the directory of the PII rule sets
	// (pii/<set>.toml) instead of the profile's: lock up's copy of the
	// profile is read-only, and the console writes its first rule set and
	// every rule it adds. A set it lacks is first copied from the
	// profile's directory.
	PIIDir string
	// Version is the console version reported to clients.
	Version string
	// TTY is the console's terminal device (nil when unknown): its owner
	// must be the console's account in a separated setup.
	TTY *os.File
	// Hub is the hub mode (--hub, --hub-key-file, --instance): the human
	// decides in lockhub, query.run answers pending with a ticket.
	Hub kconsole.HubOptions
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
	// RefuseProduction re-applies the start-up refusals of a production
	// profile (an X11 session, core dumps that could not be disabled) when
	// the policy in force becomes production: an error ends the session.
	// nil: none.
	RefuseProduction func() error
	// Quantum levels the response time of query.run (ResponseQuantum in
	// the real console, 0 to disable).
	Quantum time.Duration
	// PeerAllowed decides which clients are served, from the kernel's
	// credentials of the peer. Nil serves the console's own account only.
	PeerAllowed func(ipc.Cred) bool
	// Health is reported in status for locksql doctor.
	Health *ipc.Health
	// Refused is the fingerprint of a loosening the human refused at start,
	// not announced again until the files change.
	Refused string
	// Hub is the hub mode (nil: the human decides on this terminal); the
	// Approver is then its asynchronous approver.
	Hub *kconsole.Hub
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
	// inputs are the digests of the plan hash's inputs by name
	// (ticket.InputDigests): a renewal names those that moved.
	inputs map[string]string
	// guarded: the engine read the definitions, and the run checks them.
	guarded bool
	// requester is the agent that planned it: its lea name and token (as
	// its client sent it; compared, never shown or written).
	requester ipc.Requester
	// maxAffected bounds the rows a hub-mode write may change (0: no
	// bound): more rolls it back in its own transaction, as stale.
	// affected is what such a rolled-back run would have changed, and
	// staleTicket its ticket (hubmode.go).
	maxAffected int64
	affected    int64
	staleTicket string
	// sideEffects are what changes rows beside the statement itself and
	// so beside its rowcount: triggers, rules, foreign-key cascades (from
	// the definitions read on PostgreSQL).
	sideEffects []string
}

// Server serves client requests one at a time against one session. It is
// not safe for concurrent use: Serve runs every request on one goroutine.
//
// The request loop, the live switches, :status, :review and the policy
// polling, the session limits and the reconnection are lockkit's console
// (k); Server is its backend (kserver.go): the SQL methods, the approval
// screen, the masking and what locksql shows in its own words.
type Server struct {
	cfg ServerConfig
	k   *kconsole.Server
	// approved and profile are the policy in force (kept by ApplyPolicy),
	// rules, detectors and dialect compiled from it.
	approved  config.Policy
	profile   config.Profile
	rules     pii.Rules
	detectors []pii.Detector
	dialect   sqlclass.Dialect
	// sess is the last session the console handed out, for the database
	// user of the audit records.
	sess engine.Session
	now  func() time.Time

	// refs keeps the values behind the references of redacted cells.
	refs refStore
	// typed keeps the values the human typed for placeholder names.
	typed map[string]typedValue
	// probes are, per result number, the reference uses seen as filters
	// (a single reference, or one IN list of references).
	probes map[int]map[string]bool
	// keys caches whether "db.table.column" is a one-column unique key.
	keys map[string]bool

	plans map[string]*plan

	// catalogCache holds the column catalog per database for the analyser.
	catalogCache map[string][]engine.ColumnInfo
	// quantum levels response times (ResponseQuantum; 0 in tests).
	quantum time.Duration

	// auditFails counts consecutive failures of the hub goroutine's own
	// records (auditHubRequest); Tick ends the session on maxAuditFails.
	// lockkit's console counts those of the request goroutine.
	auditFails atomic.Int32
	// live is the policy in force as the hub's goroutine reads it, and
	// recomputed the full recomputes of expired plans being renewed
	// (hubrenew.go).
	live        atomic.Pointer[hubLive]
	recomputeMu sync.Mutex
	recomputed  map[string]recomputed
}

// maxAuditFails consecutive failures of the hub goroutine's records end
// the session, as lockkit's console does for its own.
const maxAuditFails = 3

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
	s := &Server{cfg: cfg, sess: cfg.Session, now: cfg.Now, plans: map[string]*plan{}, typed: map[string]typedValue{}, probes: map[int]map[string]bool{}, keys: map[string]bool{}, quantum: cfg.Quantum}
	// The security level: 2 with the fingerprint approver, 1 on the
	// desktop with typed approvals, 0 in a session of the console account.
	level := 0
	switch {
	case cfg.Fingerprint:
		level = 2
	case cfg.Boundary != "":
		level = 1
	}
	p := product.P
	p.Version = cfg.Version
	kc := kconsole.ServerConfig{
		Product: p, Backend: s, Policy: kpolicy{cfg.Policy}, StateDir: cfg.StateDir, ApprovedKey: cfg.ApprovedKey,
		Session: cfg.Session, Audit: cfg.Audit, IO: cfg.IO, Approver: cfg.Approver, Level: level, Boundary: cfg.Boundary,
		Now: cfg.Now, Auto: cfg.Auto, AllowUnmask: cfg.AllowUnmask, ShowResults: cfg.ShowResults && level == 0,
		Quantum: cfg.Quantum, PeerAllowed: cfg.PeerAllowed, Refused: cfg.Refused, Hub: cfg.Hub,
	}
	if refuseProd := cfg.RefuseProduction; refuseProd != nil {
		// What a production profile is refused at start-up is refused when
		// the policy in force becomes production too, and audited.
		kc.RefuseProduction = func() error {
			err := refuseProd()
			if err != nil {
				s.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: "became production: " + secrets.Sanitize(err)})
			}
			return err
		}
	}
	if cfg.Reconnect != nil {
		kc.ReconnectPolicy = s.reconnect
	}
	k, err := kconsole.NewServer(kc)
	if err != nil {
		return nil, err
	}
	s.k = k
	if cfg.Hub != nil {
		s.hubWire()
	}
	return s, nil
}

// reconnect opens a new session under the policy in force (lockkit's
// Env.Session calls it after a lost connection or an expired login). The
// reconnection may prompt (a password, a host key, the privilege audit):
// it counts as a prompt, so a switch pressed meanwhile never widens.
func (s *Server) reconnect(ctx context.Context, p kconsole.Policy) (kconsole.Session, error) {
	if w := s.k.Asker().Waiting; w != nil {
		w(true)
		defer w(false)
	}
	sess, err := s.cfg.Reconnect(ctx, p.(kpolicy).p.Profile)
	switch {
	case err == nil:
		s.sess = sess
		return sess, nil
	case errors.Is(err, errPrivilegeAudit):
		return nil, &kconsole.EndError{Reason: "privilege audit failed after reconnect", Err: err}
	case errors.Is(err, errLockedOut):
		return nil, &kconsole.EndError{Reason: "fingerprint: three non-matching fingers", Err: err}
	}
	return nil, err
}

// println writes one console line.
func (s *Server) println(line string) { s.cfg.IO.Println(line) }

// audit writes rec; a failure is told to the human and counted (see
// writeAudit).
func (s *Server) audit(rec audit.Record) { _ = s.writeAudit(rec) }

// writeAudit writes rec and returns the failure, which the caller of an
// approval turns into a refusal (fail closed). Consecutive failures end
// the session (lockkit's console counts them).
func (s *Server) writeAudit(rec audit.Record) error { return s.k.WriteAudit(s.stamp(rec)) }

// stamp fills the profile, the database and its user of rec.
func (s *Server) stamp(rec audit.Record) audit.Record {
	rec.Profile = s.profile.Name
	rec.Engine = s.profile.Engine
	rec.Host = s.host()
	rec.DBUser = s.dbUser()
	s.liveDBUser(rec.DBUser)
	return rec
}

// dbUser is the database user of the records: a login read from Vault
// names its own user, new at every connection.
func (s *Server) dbUser() string {
	if u, ok := s.sess.(interface{ DBUser() string }); ok && u.DBUser() != "" {
		return u.DBUser()
	}
	return s.cfg.DBUser
}

func (s *Server) host() string {
	if s.profile.Engine == config.EngineSQLite {
		return s.profile.Path
	}
	return s.profile.Host
}

// asker takes the human decisions of s (lockkit's console).
func (s *Server) asker() kconsole.Asker { return s.k.Asker() }

// waiting counts a prompt that waits for the human: a control key or a
// command meanwhile never widens a switch.
func (s *Server) waiting(on bool) {
	if w := s.k.Asker().Waiting; w != nil {
		w(on)
	}
}

// End stops the session after the current request.
func (s *Server) End(reason string) { s.k.End(reason) }

// Ended reports whether the session is over, and why.
func (s *Server) Ended() (string, bool) { return s.k.Ended() }

// Tick ends the session on idle or maximum session timeout, as set by the
// policy in force: a policy change applies from the next tick.
func (s *Server) Tick() {
	s.k.Tick()
	if s.auditFails.Load() >= maxAuditFails {
		// Failures of the hub's own records end the session here, on the
		// request goroutine.
		s.End("the audit log cannot be written")
	}
}

// Handle serves one request. It is the whole client surface of the console:
// none of the methods loosens the policy.
func (s *Server) Handle(ctx context.Context, req ipc.Request) ipc.Response {
	return s.k.Handle(ctx, req)
}

// Command runs a console command typed by the human between requests.
func (s *Server) Command(ctx context.Context, line string) { s.k.Command(ctx, line) }

// Key handles a control key pressed in the console.
func (s *Server) Key(k Key) { s.k.Key(k) }

// CheckPolicy re-reads the policy from the config files. Changes that only
// tighten are applied at once; a loosening waits for :review, and plans are
// refused with CodePolicyPending meanwhile.
// Without LoadPolicy (tests) there is nothing to poll.
func (s *Server) CheckPolicy() {
	if s.cfg.LoadPolicy != nil {
		s.k.CheckPolicy()
	}
}

// The live switches and the policy review, as lockkit's console holds them.
func (s *Server) autoApprove() bool   { return s.k.Auto() }
func (s *Server) showResults() bool   { return s.k.ShowResults() }
func (s *Server) allowUnmask() bool   { return s.k.UnmaskAllowed() }
func (s *Server) pendingPolicy() bool { return s.k.PolicyPending() }

// Close closes the session.
func (s *Server) Close() { s.k.Close() }

// Serve accepts clients on ln and serves their requests one at a time until
// ctx ends or the session ends (logout, timeouts, :quit). lines are the
// console commands typed by the human (nil for none); the control keys
// come from the IO when it is a KeySource. ln is closed on return, which
// removes the socket. It is lockkit's request loop.
func (s *Server) Serve(ctx context.Context, ln net.Listener, lines <-chan string) error {
	return s.loop().Serve(ctx, ln, lines)
}

// loop is lockkit's request loop with locksql's policy poll and tick.
func (s *Server) loop() *kconsole.Loop {
	l := s.k.Loop()
	l.Poll = s.CheckPolicy
	l.Tick = s.Tick // the hub goroutine's audit failures too
	return l
}

func errResp(id int64, code int, msg string) ipc.Response { return kconsole.ErrResp(id, code, msg) }

func okResp(id int64, v any) ipc.Response { return kconsole.OKResp(id, v) }
