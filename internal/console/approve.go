package console

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// ANSI colours for the approval screen.
const (
	red   = "\x1b[1;31m"
	green = "\x1b[32m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

// screen prints the approval screen of a plan (spec §6).
func (s *Server) screen(pl *plan) {
	db := pl.db
	if db == "" {
		db = "(default)"
	}
	s.println("")
	s.println(fmt.Sprintf("%s━━ %s ━━ %s / %s ━━ user %s ━━ tier %s%s",
		bold, strings.ToUpper(s.profile.Name), s.host(), safeText(db, false), safeText(s.cfg.DBUser, false), s.profile.Tier, reset))
	for _, line := range strings.Split(safeText(pl.st.SQL, true), "\n") {
		s.println(line)
	}
	class := strings.ToUpper(pl.st.Class.String())
	if pl.st.Class != sqlclass.Read {
		class = red + class + reset
	}
	verdict := pl.level
	if verdict != "OK" {
		verdict = red + verdict + reset
	}
	s.println(fmt.Sprintf("class %s · EXPLAIN: %s · verdict %s", class, safeText(pl.summary, false), verdict))
	for _, r := range pl.reasons {
		s.println("  - " + safeText(r, false))
	}
	if pl.unmask {
		s.println(red + "PII: UNMASKED" + reset)
	} else {
		s.println(fmt.Sprintf("PII: masked (%d column rules; detectors: %s)",
			len(s.rules.Mask), strings.Join(s.profile.Detectors, ", ")))
	}
}

// safeText escapes control, C1 and bidirectional formatting characters so
// that client-supplied text cannot drive or spoof the human's terminal.
// Newlines and tabs are kept when multiline is set.
func safeText(s string, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, "\\x%02x", r)
		case r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeControls is safeText for one-line client text.
func escapeControls(s string) string { return safeText(s, false) }

// Command runs a console command typed by the human between requests.
func (s *Server) Command(ctx context.Context, line string) {
	s.lastSeen = s.now()
	switch strings.TrimSpace(line) {
	case "":
	case ":review":
		s.review(ctx)
	case ":status":
		st := s.status()
		s.println(fmt.Sprintf("profile %s · %s %s · tier %s · production %t · databases %s",
			st.Profile, st.Engine, st.Host, st.Tier, st.Production, strings.Join(st.Databases, ", ")))
		l := st.Limits
		s.println(fmt.Sprintf("limits: timeout %s · warn %d · refuse %d · max_rows %d · max_cell_chars %d · max_output_bytes %d",
			l.StatementTimeout, l.ExplainRowsWarn, l.ExplainRowsRefuse, l.MaxRows, l.MaxCellChars, l.MaxOutputBytes))
		s.println(fmt.Sprintf("session ends in %d min · %d plans open · pending policy change: %t",
			st.SessionEndsInS/60, len(s.plans), s.pending != nil))
	case ":quit":
		s.End("quit")
	default:
		s.println("commands: :review (pending policy change and change requests), :status, :quit")
	}
}

// review shows the queued change requests and the pending policy change,
// and asks the human to apply the latter.
func (s *Server) review(ctx context.Context) {
	if len(s.requests) == 0 && s.pending == nil {
		s.println("nothing to review")
		return
	}
	if len(s.requests) > 0 {
		s.println("change requests from clients (edit the config files to apply one; locksql then asks you to confirm):")
		for _, r := range s.requests {
			s.println("  - " + r)
		}
		s.requests = nil
	}
	if s.pending == nil {
		return
	}
	next := *s.pending
	s.println("pending policy change for profile " + s.profile.Name + ":")
	for _, line := range formatChanges(config.Diff(s.approved, next)) {
		s.println(line)
	}
	if s.cfg.SkipPermissions && s.profile.Production && !next.Profile.Production {
		s.println(red + "--skip-permissions is set: once applied, statements run without a prompt" + reset)
	}
	ans, ok := s.cfg.IO.Ask(ctx, "Apply these changes? [y/N] ", ApprovalTimeout)
	s.pending = nil
	if !ok || strings.TrimSpace(ans) != "y" {
		s.refused = config.Fingerprint(next)
		s.audit(audit.Record{Event: audit.EventPolicy, Decision: "refused"})
		s.println("policy change refused: the last approved policy stays in force")
		return
	}
	s.refused = ""
	if err := s.adopt(next, "applied"); err != nil {
		s.println("policy change not applied: " + err.Error())
		return
	}
	s.println("policy change applied")
}

// CheckPolicy re-reads the policy from the config files. Changes that only
// tighten are applied at once; a loosening waits for :review, and plans are
// refused with CodePolicyPending meanwhile.
func (s *Server) CheckPolicy() {
	if s.cfg.LoadPolicy == nil {
		return
	}
	cur, err := s.cfg.LoadPolicy()
	if err != nil {
		msg := "config error: " + err.Error() + "; the last approved policy stays in force"
		if msg != s.lastLoadErr {
			s.lastLoadErr = msg
			s.println(msg)
		}
		return
	}
	s.lastLoadErr = ""
	fp := config.Fingerprint(cur)
	switch {
	case fp == config.Fingerprint(s.approved):
		// Back to the approved policy (a reverted edit).
		s.pending, s.refused = nil, ""
		return
	case s.pending != nil && fp == config.Fingerprint(*s.pending), fp == s.refused:
		return
	}
	changes := config.Diff(s.approved, cur)
	if !loosens(changes) {
		s.pending = nil
		if err := s.adopt(cur, "tightened"); err != nil {
			s.println("policy change not applied: " + err.Error())
			return
		}
		s.println("policy tightened:")
		for _, line := range formatChanges(changes) {
			s.println(line)
		}
		return
	}
	s.pending = &cur
	s.println(red + "pending policy change (loosening) — type :review to see it" + reset)
}

func loosens(changes []config.Change) bool {
	for _, c := range changes {
		if c.Loosens {
			return true
		}
	}
	return false
}

// adopt records p as the approved policy and enforces it. A change of the
// connection settings ends the session: the open connection no longer
// matches the policy.
func (s *Server) adopt(p config.Policy, decision string) error {
	if s.cfg.StateDir != "" && s.cfg.ApprovedKey != "" {
		if err := config.SaveApproved(s.cfg.StateDir, s.cfg.ApprovedKey, p); err != nil {
			return err
		}
	}
	old := s.profile
	if err := s.apply(p); err != nil {
		return err
	}
	s.audit(audit.Record{Event: audit.EventPolicy, Decision: decision})
	n := p.Profile
	if n.Production && !old.Production && s.sess != nil {
		// The start-up privilege audit accepted extra grants with a typed
		// "continue"; a production profile refuses them (spec §6 step 5).
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		warns, err := s.sess.ExtraPrivileges(ctx, n.Tier)
		cancel()
		if err != nil || len(warns) > 0 {
			s.println(red + "the profile is now production and the account has privileges beyond tier " + n.Tier.String() + ": the session ends" + reset)
			s.End("privilege audit failed after the profile became production")
			return nil
		}
	}
	if old.Engine != n.Engine || old.Host != n.Host || old.Port != n.Port || old.Path != n.Path ||
		old.User != n.User || old.Database != n.Database {
		s.println("connection settings changed: the session ends; start the console again")
		s.End("connection settings changed")
	}
	return nil
}

// formatChanges renders a policy diff, loosenings in red.
func formatChanges(changes []config.Change) []string {
	var out []string
	for _, c := range changes {
		var line string
		switch {
		case c.Old == "":
			line = fmt.Sprintf("  + %s: %s", c.Field, c.New)
		case c.New == "" && (strings.HasPrefix(c.Field, "pii.") || c.Field == "detectors"):
			line = fmt.Sprintf("  - %s: %s", c.Field, c.Old)
		default:
			line = fmt.Sprintf("  ~ %s: %s → %s", c.Field, c.Old, c.New)
		}
		if c.Loosens {
			line = red + line + "  (loosens)" + reset
		} else {
			line = green + line + reset
		}
		out = append(out, line)
	}
	return out
}

// describePolicy renders a whole policy for its first approval.
func describePolicy(p config.Policy) []string {
	pr := p.Profile
	where := pr.Host
	if pr.Engine == config.EngineSQLite {
		where = pr.Path
	} else if pr.Port != 0 {
		where += ":" + strconv.Itoa(pr.Port)
	}
	l := pr.Limits
	lines := []string{
		fmt.Sprintf("  engine %s · %s · database %q · user %q", pr.Engine, where, pr.Database, pr.User),
		fmt.Sprintf("  tier %s · production %t · credentials %s", pr.Tier, pr.Production, pr.Credentials),
		fmt.Sprintf("  limits: timeout %s · warn %d · refuse %d · max_rows %d · max_cell_chars %d · max_output_bytes %d",
			l.StatementTimeout, l.ExplainRowsWarn, l.ExplainRowsRefuse, l.MaxRows, l.MaxCellChars, l.MaxOutputBytes),
		"  detectors: " + strings.Join(pr.Detectors, ", "),
		fmt.Sprintf("  PII rules: %d mask, %d allow", len(p.PIIMask), len(p.PIIAllow)),
	}
	for _, a := range p.PIIAllow {
		lines = append(lines, red+"  allow "+a+reset)
	}
	return lines
}
