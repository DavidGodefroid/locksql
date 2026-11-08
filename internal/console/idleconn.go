package console

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/lazyconn"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// The idle end of a session (locksql#198). Once limits.idle_timeout
// passes without a request or a key of the human, the console closes its
// database connection and its SSH tunnel, but keeps running and keeps its
// socket: the start questions (policy review, production name) are not
// asked again. The next agent request that needs the database asks a
// connect ticket (ticket.KindConnect), decided in `lox run` like a plan's,
// and the console connects again once it is approved. A secret the
// profile asks for (credentials = "ask", ssh.credentials = "ask") comes
// sealed in the decision, to a one-use key of this console
// (ticket.Subject.SecretTo): the hub relays a box it cannot open, and the
// secret goes nowhere but the connection. Two secrets take two tickets:
// the SSH leg's (the bastion) and the database leg's.
//
// lockkit's console still ends the session at max_session; its own idle
// end is not used (kpolicy.Profile hands it noIdleEnd).

// noIdleEnd is the idle timeout lockkit's console gets: never reached,
// locksql closes the connection on idle instead of ending the session.
const noIdleEnd = time.Duration(1<<63 - 1)

// defaultIdleTimeout is lockkit's console default when the profile sets
// none.
const defaultIdleTimeout = 20 * time.Minute

// connectSecrets are the secrets of a reconnection, opened from the
// decisions of its connect tickets (nil: not asked for). wipe clears them.
type connectSecrets struct {
	db, ssh []byte
}

func (c *connectSecrets) wipe() {
	secrets.Wipe(c.db)
	secrets.Wipe(c.ssh)
	c.db, c.ssh = nil, nil
}

// idleConnector opens a session again after an idle end, with the secrets
// of the approved connect tickets (Run's starter).
type idleConnector interface {
	// connectNeeds reports which secrets a connection of p asks for: the
	// database's (credentials = "ask") and the bastion's (ssh.credentials
	// = "ask", and the key or password took one when it last connected).
	connectNeeds(p config.Profile) (db, ssh bool)
	// reconnectSealed connects p with sec in place of the human's typed
	// answers, and runs the privilege audit again.
	reconnectSealed(ctx context.Context, p config.Profile, sec *connectSecrets) (engine.Session, error)
}

// idleTimeout is the profile's limits.idle_timeout in force.
func (s *Server) idleTimeout() time.Duration {
	if t := s.profile.Limits.IdleTimeout; t > 0 {
		return t
	}
	return defaultIdleTimeout
}

// seen records activity for the idle timeout, as lockkit's console counts
// it: a request that reaches the database (its start and its end), a
// line or a key of the human. A client polling status or hello keeps
// nothing open.
func (s *Server) seen() { s.lastSeen = s.now() }

// idleTick closes the connection once idle_timeout passed without
// activity (Tick, on the request goroutine).
func (s *Server) idleTick() {
	if s.idleClosed || s.k == nil {
		return
	}
	if _, ended := s.k.Ended(); ended || s.now().Sub(s.lastSeen) < s.idleTimeout() {
		return
	}
	s.idleClosed = true
	s.endGrants("idle timeout: the connection is closed")
	s.k.Lost() // closes the session: the database connection and the tunnel
	s.audit(audit.Record{Event: audit.EventLogin, Decision: "idle-closed"})
	what := "the database connection"
	if s.profile.SSH != nil {
		what += " and the SSH tunnel"
	}
	s.println(paint.Step(fmt.Sprintf("idle_timeout (%s): %s closed; the console keeps running, the next request asks a connect ticket in lox run", s.idleTimeout(), what)))
}

// errConnectDeniedHub: the decider refused a connect ticket.
var errConnectDeniedHub = errors.New("the connection was refused in lox run: not connected; ask again only if the human asks you to")

// errConnectTimeout: no decision came on a connect ticket in time.
var errConnectTimeout = errors.New("the connect ticket was not decided in time; do not retry unless asked")

// errHumanConnect: an auto rule approved a connect ticket only a human may
// approve (auto.connect = "ask").
var errHumanConnect = errors.New("the profile's auto rules ask a human for this connection (auto.connect = ask), but an auto rule approved it: not connected; ask again and wait for the human's decision")

// reconnectIdle connects p again after an idle end: the connect tickets
// first, then the connection with their secrets.
func (s *Server) reconnectIdle(ctx context.Context, p config.Profile) (sess engine.Session, err error) {
	defer func() {
		if err != nil {
			s.idleErr = fmt.Errorf("the connection closed at idle_timeout was not opened again: %s; the console keeps running", secrets.Sanitize(err))
		}
	}()
	needDB, needSSH := s.cfg.IdleConnect.connectNeeds(p)
	sec := &connectSecrets{}
	defer sec.wipe()
	if sec.db, err = s.askConnect(ctx, p, s.dbLeg(p, needDB)); err != nil {
		return nil, err
	}
	if p.SSH != nil && needSSH {
		if sec.ssh, err = s.askConnect(ctx, p, sshLeg(p)); err != nil {
			return nil, err
		}
	}
	sess, err = s.cfg.IdleConnect.reconnectSealed(ctx, p, sec)
	if err != nil {
		return nil, err
	}
	s.idleClosed = false
	s.audit(audit.Record{Event: audit.EventLogin, Decision: "reconnected"})
	return sess, nil
}

// connectLeg is one connect ticket of a reconnection.
type connectLeg struct {
	name       string // "database" or "ssh", for the screen and the audit
	endpoint   string
	credential string
	secret     bool
}

// dbLeg is the database leg of p: its endpoint and credential source.
func (s *Server) dbLeg(p config.Profile, secret bool) connectLeg {
	cred := p.Credentials
	if p.Engine == config.EngineSQLite {
		cred = ticket.CredentialNone
		secret = false
	}
	return connectLeg{name: "database", endpoint: dbEndpoint(p), credential: cred, secret: secret}
}

// sshLeg is the bastion leg of p, asked for its secret.
func sshLeg(p config.Profile) connectLeg {
	return connectLeg{name: "ssh", endpoint: endpointOf(p.SSH.Host, p.SSH.Port, ""), credential: ticket.CredentialAsk, secret: true}
}

// dbEndpoint is the database of p as a connect ticket names it, without
// userinfo: host:port/database, or the file name of a SQLite database.
func dbEndpoint(p config.Profile) string {
	if p.Engine == config.EngineSQLite {
		return endpointOf("sqlite", 0, filepath.Base(p.Path))
	}
	port := p.Port
	if port == 0 {
		port = defaultPort(p.Engine)
	}
	return endpointOf(p.Host, port, p.Database)
}

// endpointOf is host[:port][/path], dropping what a ticket would refuse
// (ticket.Subject.Validate): the full name stays on the masked screen.
func endpointOf(host string, port int, path string) string {
	hp := host
	if port > 0 {
		hp = net.JoinHostPort(host, strconv.Itoa(port))
	}
	for _, e := range []string{hp + "/" + path, hp, host} {
		if path == "" && e == hp+"/" {
			continue
		}
		sub := ticket.Subject{Profile: "p", Endpoint: e, Credential: ticket.CredentialNone}
		if sub.Validate(ticket.KindConnect) == nil {
			return e
		}
	}
	return "unnamed"
}

// connectRisk is the risk class of a connect ticket of p.
func connectRisk(p config.Profile, secret bool) ticket.Risk {
	switch {
	case secret:
		return ticket.RiskUnlock
	case p.Production:
		return ticket.RiskProdWrite
	}
	return ticket.RiskRead
}

// askConnect asks the connect ticket of leg and waits for its decision,
// audited with the profile's auto rule and the decider's. It returns the
// secret the decision sealed (nil when leg asks for none); the caller
// wipes it.
func (s *Server) askConnect(ctx context.Context, p config.Profile, leg connectLeg) ([]byte, error) {
	h := s.cfg.Hub
	rule := "auto.connect = " + string(p.AutoRules().Get(config.ActionConnect))
	human := p.AutoRules().Get(config.ActionConnect) != config.AutoAuto
	subj := ticket.Subject{Profile: p.Name, Endpoint: leg.endpoint, Credential: leg.credential}
	var priv *ecdh.PrivateKey
	if leg.secret {
		var err error
		if priv, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		subj.SecretTo = ticket.EncodeX25519(priv.PublicKey())
	}
	t, err := ticket.NewConnectTicket(ticket.Source{Lock: product.P.Name}, connectRisk(p, leg.secret), subj, s.policyFP(), s.now(), lazyconn.DefaultAskTimeout)
	if err != nil {
		return nil, err
	}
	t.Flags.Production, t.Flags.NeverAuto = p.Production, human
	src := render.ScreenSource{
		Header: p.Name + " · connect · " + leg.name,
		Body: []render.Line{
			render.Structure("the connection was closed at idle_timeout; the next request needs it"),
			render.Structure("endpoint: " + leg.endpoint),
			render.Structure("credentials: " + leg.credential),
			render.Structure("rule: " + rule),
		},
		Warnings: []string{},
	}
	if leg.secret {
		src.Body = append(src.Body, render.Structure("secret: typed in lox run, sealed to this console"))
	}
	if p.Production {
		src.Warnings = append(src.Warnings, "production")
	}
	rec := audit.Record{Event: audit.EventPending, Decision: "pending", Approval: kconsole.HubApproval, Ticket: t.ID,
		AutoRule: rule, Reason: "connect: " + leg.name}
	if leg.name == "ssh" {
		rec.SSHHost = p.SSH.Host
	}
	if err := s.writeAudit(rec); err != nil {
		return nil, fmt.Errorf("connect ticket: the audit log cannot be written: %w", err)
	}
	s.println(paint.Step("connect: the " + leg.name + " leg waits for its connect ticket " + safeText(t.ID, false) + " in lox run"))
	actx, cancel := context.WithTimeout(ctx, lazyconn.DefaultAskTimeout)
	defer cancel()
	d, err := h.Client.Ask(actx, t, render.MaskScreen(src, render.Masking{}))
	if err != nil {
		rec.Event, rec.Decision, rec.Error = audit.EventRun, "failed", secrets.Sanitize(err)
		s.audit(rec)
		if actx.Err() != nil && ctx.Err() == nil {
			return nil, errConnectTimeout
		}
		return nil, fmt.Errorf("connect ticket: %s", secrets.Sanitize(err))
	}
	rec.Approver, rec.Facade, rec.HubSig, rec.DecidedBy = &d.Approver, d.Facade, d.Sig, decidedBy(d)
	fail := func(event string, err error) ([]byte, error) {
		rec.Event, rec.Decision, rec.Error = event, "failed", err.Error()
		s.audit(rec)
		return nil, err
	}
	if err := d.Match(t); err != nil {
		return fail(audit.EventRun, fmt.Errorf("connect ticket: %w", err))
	}
	if err := d.Usable(t, s.now(), lazyconn.DefaultMaxAge); err != nil {
		switch {
		case errors.Is(err, ticket.ErrDenied):
			rec.Event, rec.Decision, rec.Reason = audit.EventDenied, string(d.Decision), safeText(d.Reason, false)
			s.audit(rec)
			s.println(paint.Fail("connect: the " + leg.name + " leg was refused in lox run"))
			return nil, errConnectDeniedHub
		case errors.Is(err, ticket.ErrAuto):
			return fail(audit.EventRun, errHumanConnect)
		}
		return fail(audit.EventRun, fmt.Errorf("connect ticket: %w", err))
	}
	if human && (d.Rule == nil || d.Rule.By != ticket.RuleHuman) {
		// Usable refuses an auto rule's approval of a NeverAuto ticket;
		// this also refuses a decision that does not say who decided.
		return fail(audit.EventRun, errHumanConnect)
	}
	secret, err := d.OpenSecret(t, priv)
	if err != nil {
		return fail(audit.EventRun, fmt.Errorf("connect ticket: %w", err))
	}
	rec.Event, rec.Decision = audit.EventApproved, string(d.Decision)
	if err := s.writeAudit(rec); err != nil {
		secrets.Wipe(secret)
		return nil, fmt.Errorf("connect ticket: the audit log cannot be written: %w", err)
	}
	// The hub's bookkeeping only.
	_ = h.Client.Consumed(ctx, t.ID)
	return secret, nil
}
