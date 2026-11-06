package console

import (
	"context"
	"errors"
	"fmt"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// The lock's side of the profile's auto rules (config/auto.go,
// locksql#185). `lox run` decides in auto mode; the lock makes its rules
// hold whatever the decider does: deny is refused here, before a ticket;
// ask marks the ticket never-auto (ticket.Flags.NeverAuto), which an
// auto rule's approval cannot use (ticket.ErrAuto); auto leaves the
// ticket to the decider's auto mode. The rule in force is that of the
// approved policy, so loosening it is a policy loosening: asked at start
// or at :review, with the typed profile name on production.

// autoRule is the profile's auto rule for a statement of class, unmasked
// or not.
func (s *Server) autoRule(class sqlclass.Class, unmask bool) (config.AutoAction, config.AutoValue) {
	return config.AutoRuleOf(s.profile.AutoRules(), config.Tier(class), unmask)
}

// autoRuleText is the rule in the audit: "auto.write = ask".
func (s *Server) autoRuleText(class sqlclass.Class, unmask bool) string {
	a, v := s.autoRule(class, unmask)
	return fmt.Sprintf("auto.%s = %s", a, v)
}

// neverAuto reports a statement whose ticket no auto rule may approve:
// its rule is not auto.
func (s *Server) neverAuto(class sqlclass.Class, unmask bool) bool {
	_, v := s.autoRule(class, unmask)
	return v != config.AutoAuto
}

// autoDenied is the refusal of a statement the auto rules deny, nil when
// they do not.
func (s *Server) autoDenied(class sqlclass.Class, unmask bool) *autoDenial {
	a, v := s.autoRule(class, unmask)
	if v != config.AutoDeny {
		return nil
	}
	return &autoDenial{rule: s.autoRuleText(class, unmask), err: refusal.Newf(refusal.AutoDeny,
		"the auto rules of profile %s deny this %s (auto.%s = deny): no ticket is asked, a human cannot approve it",
		s.profile.Name, actionNoun(a), a)}
}

// autoDenial is a refusal of the auto rules and the rule that refused.
type autoDenial struct {
	rule string
	err  *refusal.Error
}

func actionNoun(a config.AutoAction) string {
	switch a {
	case config.ActionDDL:
		return "schema change"
	case config.ActionUnmask:
		return "unmasked result"
	}
	return string(a)
}

// refuseAuto is refuse for a refusal of the auto rules: the record names
// the rule.
func (s *Server) refuseAuto(ctx context.Context, id int64, intent, db, sql, class, verdict, src string, d *autoDenial) ipc.Response {
	rec := withPeerRecord(ctx, audit.Record{Event: audit.EventRefused, DB: db, SQL: sql, Class: class, Verdict: verdict, Intent: intent, AutoRule: d.rule})
	return s.refuseRec(id, rec, src, d.err)
}

// decidedBy is what decided d, for the audit: "human", or "auto:<rule
// id>" for an auto rule of the decider; "" for a version-1 decision,
// which does not say.
func decidedBy(d *ticket.Decision) string {
	switch {
	case d == nil || d.Rule == nil:
		return ""
	case d.Rule.By == ticket.RuleAuto:
		return "auto:" + d.Rule.ID
	}
	return d.Rule.By
}

// autoLine is the auto rules in force, as the console shows them at
// start and in describePolicy.
func autoLine(p config.Profile) string {
	return "  auto mode (lox run): " + p.AutoRules().String()
}

// classOf is the statement class named name ("read", "write", ...).
func classOf(name string) (sqlclass.Class, bool) {
	for _, c := range []sqlclass.Class{sqlclass.Read, sqlclass.Write, sqlclass.DDL, sqlclass.Admin} {
		if c.String() == name {
			return c, true
		}
	}
	return 0, false
}

// connectDeniedRule is the audit text of the rule that refuses a
// connection.
const connectDeniedRule = "auto.connect = deny"

// errConnectDenied marks a connection the auto rules refuse.
var errConnectDenied = errors.New("console: the auto rules deny the connection (auto.connect = deny)")

// connectDenied is the refusal of a connection under p, nil when p's
// auto rules allow it (connect = auto or ask: the console connects with
// the human at its terminal, and lockkit refuses a plan's connect
// ticket).
func connectDenied(p config.Profile) error {
	if p.AutoRules().Get(config.ActionConnect) != config.AutoDeny {
		return nil
	}
	return fmt.Errorf("%w: profile %s", errConnectDenied, p.Name)
}

// endConnectDenied ends the session of a profile whose policy in force
// now denies its connection (a tightening applied from the files, a
// reviewed change, a reconnection): the open connection no longer
// matches the policy. The end is on record first; when stage says where
// it was found.
func (s *Server) endConnectDenied(stage string, err error) {
	s.audit(audit.Record{Event: audit.EventLogin, Decision: "refused", Error: stage + ": " + err.Error(), AutoRule: connectDeniedRule})
	s.println(paint.Fail("the auto rules of profile " + safeText(s.profile.Name, false) + " now deny its connection (auto.connect = deny): the session ends"))
	s.k.End("the auto rules deny the connection")
}
