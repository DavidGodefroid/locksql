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
	"github.com/DavidGodefroid/locksql/internal/ui"
)

// ANSI colours of the console, which always runs in a terminal.
const (
	red   = ui.Red
	green = ui.Green
	bold  = ui.Bold
	reset = ui.Reset
)

// paint styles console lines.
var paint = ui.Painter{On: true}

// screen prints the approval screen of a plan (spec §6): a frame, red on
// a production profile, that the approval prompt closes (see frameEnd).
func (s *Server) screen(ctx context.Context, pl *plan) {
	db := pl.db
	if db == "" {
		db = "(default)"
	}
	var lines []string
	add := func(l string) { lines = append(lines, l) }
	s.screenBody(ctx, pl, add)
	if pl.an != nil {
		s.readDetails(pl, add)
	}
	if pl.unmask {
		add(red + "PII: UNMASKED" + reset)
	} else {
		add(fmt.Sprintf("PII: masked (%d column rules; detectors: %s)",
			len(s.rules.Mask), strings.Join(s.profile.Detectors, ", ")))
		if s.cfg.ShowResults {
			add(paint.Yellow("result: shown here in clear (--show-results); the agent gets it masked"))
		}
	}
	for _, w := range pl.warnings {
		add(red + "warning: " + safeText(w, false) + reset)
	}
	frame := s.frameColour()
	sep := paint.Dim(" · ")
	s.println("")
	head := paint.Paint(frame, "╭─ ") + paint.Paint(bold+frame, strings.ToUpper(s.profile.Name)) + sep +
		safeText(s.host(), false) + " / " + safeText(db, false)
	if s.cfg.DBUser != "" {
		head += sep + "user " + safeText(s.cfg.DBUser, false)
	}
	s.println(head + sep + "tier " + s.profile.Tier.String() + " " + paint.Paint(frame, "─────"))
	for _, l := range lines {
		if l == "" {
			s.println(paint.Paint(frame, "│"))
			continue
		}
		s.println(paint.Paint(frame, "│ ") + l)
	}
}

// frameColour is the colour of the approval frame.
func (s *Server) frameColour() string {
	if s.profile.Production {
		return ui.Red
	}
	return ui.Violet
}

// frameEnd closes the approval frame in front of text (the prompt).
func (s *Server) frameEnd(text string) string {
	return paint.Paint(s.frameColour(), "╰─ ") + text
}

// screenBody is the requester, the statement and the verdict.
func (s *Server) screenBody(ctx context.Context, pl *plan, add func(string)) {
	if who := peerText(ctx); who != "" {
		add(paint.Dim("requested by " + safeText(who, false)))
	}
	add("")
	for _, line := range strings.Split(s.highlight(pl), "\n") {
		add("  " + line)
	}
	add("")
	class := strings.ToUpper(pl.st.Class.String())
	if pl.st.Class != sqlclass.Read {
		class = red + class + reset
	}
	verdict := pl.level
	if verdict != "OK" {
		verdict = red + verdict + reset
	}
	add(fmt.Sprintf("class %s · EXPLAIN: %s · verdict %s", class, safeText(pl.summary, false), verdict))
	for _, r := range pl.reasons {
		add("  - " + safeText(r, false))
	}
}

// readDetails explains a read plan to the human: what it reads, which PII
// columns it touches and where, how each output is masked, the k-anonymity
// counts that run first and the token values substituted.
func (s *Server) readDetails(pl *plan, add func(string)) {
	an := pl.an
	if pl.isExplain {
		add(bold + "EXPLAIN only: the statement does not run; the plan is returned" + reset)
	}
	if len(an.Relations) > 0 {
		add("reads: " + safeText(strings.Join(an.Relations, ", "), false))
	}
	if pl.st.Limit >= 0 {
		add(fmt.Sprintf("returns at most %d rows", min(pl.st.Limit, s.profile.Limits.MaxRows)))
	}
	if len(an.Uses) > 0 {
		var order []string
		where := map[string][]string{}
		for _, u := range an.Uses {
			k := u.Source.Table + "." + u.Source.Column
			if _, ok := where[k]; !ok {
				order = append(order, k)
			}
			where[k] = append(where[k], u.Clause)
		}
		var parts []string
		for _, k := range order {
			parts = append(parts, k+" ("+strings.Join(where[k], ", ")+")")
		}
		add(red + "PII columns touched: " + safeText(strings.Join(parts, "; "), false) + reset)
	}
	if !pl.unmask {
		var masks []string
		for i, o := range an.Outputs {
			if o.Mask == "" {
				continue
			}
			name := strings.ToLower(o.Label)
			if name == "" {
				name = fmt.Sprintf("#%d", i+1)
			}
			masks = append(masks, name+" → "+o.Mask)
		}
		if len(masks) > 0 {
			add("masked outputs: " + safeText(strings.Join(masks, ", "), false))
		}
		_, reused := s.placeholders(pl)
		for _, n := range reused {
			add(fmt.Sprintf("${%s} = value typed at %s", n, s.typed[n].at.Format("15:04")))
		}
		if missing, _ := s.placeholders(pl); len(missing) > 0 {
			add("values to type: ${" + strings.Join(missing, "}, ${") + "}")
		}
		if k := s.profile.Limits.KAnonymity; k > 1 {
			for _, c := range an.KChecks {
				add(fmt.Sprintf("k-anonymity check (k=%d) runs first: %s", k, safeText(c.SQL, false)))
			}
		}
		if an.PIIFilter {
			add("row estimates are hidden from the agent: the statement filters on a PII column")
		}
	}
}

// highlight is the statement for the screen, escaped, with the names of
// the PII columns it touches in red.
func (s *Server) highlight(pl *plan) string {
	sql := pl.st.SQL
	if pl.an == nil || len(pl.an.Uses) == 0 {
		return safeText(sql, true)
	}
	names := map[string]bool{}
	for _, u := range pl.an.Uses {
		names[fold(u.Source.Column)] = true
	}
	toks, err := sqlclass.Lex(s.dialect, sql)
	if err != nil {
		return safeText(sql, true)
	}
	var b strings.Builder
	pos := 0
	for _, t := range toks {
		if (t.Kind == sqlclass.TokWord || t.Kind == sqlclass.TokQuotedIdent) && names[t.Name()] && t.Pos >= pos {
			b.WriteString(safeText(sql[pos:t.Pos], true))
			b.WriteString(red + safeText(sql[t.Pos:t.End], false) + reset)
			pos = t.End
		}
	}
	b.WriteString(safeText(sql[pos:], true))
	return b.String()
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
			st.Profile, st.Engine, safeText(st.Host, false), st.Tier, st.Production, safeText(strings.Join(st.Databases, ", "), false)))
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

// formatChanges renders a policy diff, loosenings in red. Every value is
// escaped: a pattern or a host could otherwise carry terminal escapes that
// hide a loosening from the human.
func formatChanges(changes []config.Change) []string {
	var out []string
	for _, c := range changes {
		c.Field, c.Old, c.New = safeText(c.Field, false), safeText(c.Old, false), safeText(c.New, false)
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
		fmt.Sprintf("  engine %s · %s · database %q · user %q", safeText(pr.Engine, false), safeText(where, false), pr.Database, pr.User),
		fmt.Sprintf("  tier %s · production %t · credentials %s", pr.Tier, pr.Production, safeText(pr.Credentials, false)),
		fmt.Sprintf("  limits: timeout %s · warn %d · refuse %d · max_rows %d · max_cell_chars %d · max_output_bytes %d",
			l.StatementTimeout, l.ExplainRowsWarn, l.ExplainRowsRefuse, l.MaxRows, l.MaxCellChars, l.MaxOutputBytes),
		"  detectors: " + safeText(strings.Join(pr.Detectors, ", "), false),
		fmt.Sprintf("  PII rules: %d mask, %d allow", len(p.PIIMask), len(p.PIIAllow)),
	}
	if pr.Engine != config.EngineSQLite {
		mode := pr.TLS
		if mode == "" {
			mode = config.TLSPrefer
		}
		lines = append(lines, "  tls: "+safeText(mode, false))
	}
	if pr.SSH != nil {
		lines = append(lines, "  ssh: "+safeText(config.SSHString(pr.SSH), false))
	}
	for _, a := range p.PIIAllow {
		lines = append(lines, red+"  allow "+safeText(a, false)+reset)
	}
	return lines
}
