package console

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// Re-approval of expired tickets (lockkit decision H1), reveals and the
// rollback of hub mode.
//
// A ticket whose plan expired (pending past its TTL, or approved but the
// approval aged before the run) is asked again: the run answers pending
// with a new ticket that names the expired one and the plan-hash inputs
// that moved since (ticket.Renewal). The renewal is checked by
// hubRecompute, the same plan hash and input digests the run's recheck
// computes, from the stored statement and the lock's state now.

// hubLive is what the hub's goroutine (hubclient.Watch: the reveals and
// renewals a human asks for in lockhub) reads of the server, which serves
// its requests on another goroutine: set whole by apply.
type hubLive struct {
	// fp is the fingerprint of the policy in force (ticket.HashOf).
	fp                    string
	profile, engine, host string
	dbUser                string
}

// setLive records the policy in force for the hub's goroutine.
func (s *Server) setLive() error {
	fp, err := ticket.HashOf(s.approved)
	if err != nil {
		return err
	}
	s.live.Store(&hubLive{fp: fp, profile: s.profile.Name, engine: s.profile.Engine, host: s.host(), dbUser: s.cfg.DBUser})
	return nil
}

// recomputed is a full recompute of an expired plan, made on the
// request goroutine for the renewal that follows (hubRenew).
type recomputed struct {
	fp, hash string
	inputs   map[string]string
}

// hubWire sets what the hub client asks of locksql: the recompute of a
// renewal and the audit of the hub's requests (reveals, renewals).
func (s *Server) hubWire() {
	h := s.cfg.Hub
	h.Client.SetRecompute(s.hubRecompute)
	h.Requests(s.cfg.IO, s.auditHubRequest)
}

// auditHubRequest audits a reveal or a renewal the hub asked for. It runs
// on the hub's goroutine: it writes the log itself (audit.Log is safe for
// concurrent use) with the fields hubLive keeps, never the server's.
func (s *Server) auditHubRequest(b kaudit.Base) {
	rec := audit.Record{Event: b.Event, Decision: b.Decision, Error: safeText(b.Error, false), Reason: b.Reason,
		Approval: b.Approval, Ticket: b.Ticket, Approver: b.Approver, Facade: b.Facade}
	if v := s.live.Load(); v != nil {
		rec.Profile, rec.Engine, rec.Host, rec.DBUser = v.profile, v.engine, v.host, v.dbUser
	}
	if err := s.cfg.Audit.Append(rec); err != nil {
		s.println(paint.Fail("audit log write failed: " + safeText(err.Error(), false)))
	}
}

// hubRenew answers the run of expired ticket tk: its statement is planned
// again now, on this goroutine (read-only: the definitions it resolves to,
// as the recheck reads them), and the ticket asked again with what moved
// (Hub.RenewResp). A statement that no longer plans answers its refusal.
func (s *Server) hubRenew(ctx context.Context, id int64, tk string, caller plans.Caller) ipc.Response {
	h := s.cfg.Hub
	if p, err := h.Store.ExpiredByTicket(tk, caller); err == nil && p.RenewedBy == "" {
		var body hubPlan
		if err := json.Unmarshal(p.Body, &body); err != nil {
			return errResp(id, ipc.CodeInternal, "plan store: "+err.Error())
		}
		pl, r := s.buildPlan(ctx, id, ipc.PlanParams{DB: body.DB, SQL: body.SQL, Unmask: body.Unmask, Intent: body.Intent})
		if r != nil {
			return *r
		}
		fp, err := ticket.HashOf(s.approved)
		if err != nil {
			return errResp(id, ipc.CodeInternal, "policy fingerprint: "+err.Error())
		}
		s.recomputeMu.Lock()
		if s.recomputed == nil {
			s.recomputed = map[string]recomputed{}
		}
		s.recomputed[p.ID] = recomputed{fp: fp, hash: pl.hash, inputs: pl.inputs}
		s.recomputeMu.Unlock()
		defer func() {
			s.recomputeMu.Lock()
			delete(s.recomputed, p.ID)
			s.recomputeMu.Unlock()
		}()
	}
	s.println(paint.Warn("ticket " + safeText(tk, false) + " expired before its run: asked again in lockhub"))
	return h.RenewResp(ctx, id, tk, caller)
}

// hubRecompute is the hub client's Recompute: the policy fingerprint, plan
// hash and plan-hash inputs of stored plan p as the lock sees them now.
//
// The run of an expired ticket (hubRenew) planned the statement again
// first: that full recompute, the recheck's own, is the answer. A renewal
// the human asks for in lockhub comes on the hub's goroutine, where the
// session (another goroutine's) cannot be read: the inputs that need no
// session (the policy, the profile, the engine, the host, the database,
// unmask) are recomputed, while the statement as planned ("sql") and the
// definitions it resolves to ("state") are ticket.UncheckedInput: the
// renewal names them "unchecked", so the hub never shows it as checked
// and unchanged, and the plan hash stays the stored one. They are checked
// at the run, which plans again and answers stale, with a new ticket, if
// they moved. Nothing here runs a statement.
func (s *Server) hubRecompute(p *plans.Plan) (string, string, map[string]string, error) {
	s.recomputeMu.Lock()
	r, ok := s.recomputed[p.ID]
	s.recomputeMu.Unlock()
	if ok {
		return r.fp, r.hash, r.inputs, nil
	}
	v := s.live.Load()
	if v == nil {
		return "", "", nil, fmt.Errorf("no policy in force")
	}
	var body hubPlan
	if err := json.Unmarshal(p.Body, &body); err != nil {
		return "", "", nil, err
	}
	now, err := ticket.InputDigests(planInputs{V: planHashVersion, Profile: v.profile, Engine: v.engine, Host: v.host,
		DB: body.DB, Unmask: body.Unmask, PolicyFP: v.fp})
	if err != nil {
		return "", "", nil, err
	}
	inputs := maps.Clone(now)
	for _, k := range []string{"sql", "state"} {
		inputs[k] = ticket.UncheckedInput
	}
	return v.fp, p.Binding.PlanHash, inputs, nil
}

// withdrawStandalone is the rollback of hub mode at a standalone start:
// the plans a run with --hub left pending are withdrawn (the hub hears of
// it at the next start with --hub), and a run of their tickets is refused
// (queryRunTicket answers kconsole.WithdrawnResp).
func withdrawStandalone(io IO, stateDir string) {
	ws, err := kconsole.WithdrawStandalone(product.P, stateDir)
	for _, w := range ws {
		io.Println(paint.Warn(fmt.Sprintf("hub mode is off: %d pending ticket(s) of %s withdrawn; the hub hears of it at the next start with --hub --instance %s",
			len(w.Tickets), safeText(w.Instance, false), safeText(w.Instance, false))))
	}
	if err != nil {
		io.Println(paint.Warn("hub mode is off, and its pending plans could not all be withdrawn (they stay pending and could run after a restart with --hub; deny them in lockhub): " + safeText(err.Error(), false)))
	}
}
