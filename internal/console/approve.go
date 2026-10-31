package console

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ui"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
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
		if s.showResults() {
			add(paint.Yellow("result: shown here in clear (results on); the agent gets it masked"))
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

// screenBody is the requester, the agent's intent, the statement and the
// verdict.
func (s *Server) screenBody(ctx context.Context, pl *plan, add func(string)) {
	if who := peerText(ctx); who != "" {
		add(paint.Dim("requested by " + safeText(who, false)))
	}
	if pl.intent != "" {
		add(paint.Dim("agent: " + safeText(pl.intent, false)))
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

// readDetails explains a read plan (or an analysed write) to the human: what it reads, which PII
// columns it touches and where, how each output is masked, the k-anonymity
// counts that run before the approval and the token values substituted.
func (s *Server) readDetails(pl *plan, add func(string)) {
	an := pl.an
	if pl.isExplain {
		add(bold + "EXPLAIN only: the statement does not run; the plan is returned" + reset)
	}
	if len(an.Relations) > 0 {
		head := "reads: "
		if pl.st.Class != sqlclass.Read {
			head = "reads or writes: "
		}
		add(head + safeText(strings.Join(an.Relations, ", "), false))
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
				add(fmt.Sprintf("k-anonymity count (k=%d): %s", k, safeText(c.SQL, false)))
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
func safeText(s string, multiline bool) string { return sanitize.Terminal(s, multiline) }

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
		fmt.Sprintf("  session: idle_timeout %s · max_session %s", l.IdleTimeout, l.MaxSession),
		"  detectors: " + safeText(strings.Join(pr.Detectors, ", "), false),
		fmt.Sprintf("  PII rules: set %q · %d mask, %d allow", pr.PIIRules, len(p.PIIMask), len(p.PIIAllow)),
	}
	if pr.Engine != config.EngineSQLite {
		mode := pr.TLS
		if mode == "" {
			mode = config.TLSPrefer
		}
		lines = append(lines, "  tls: "+safeText(mode, false))
	}
	if pr.VaultPath != "" {
		lines = append(lines, "  vault: "+safeText(pr.VaultPath, false)+" (user and password read at every connection)")
	}
	if pr.SSH != nil {
		lines = append(lines, "  ssh: "+safeText(config.SSHString(pr.SSH), false))
	}
	if pr.WriteFunctions != "" {
		lines = append(lines, "  write_functions: "+pr.WriteFunctions)
	}
	if len(pr.ProxyCommand) > 0 {
		lines = append(lines, "  proxy_command: "+safeText(config.ProxyString(pr.ProxyCommand), false))
	}
	for _, a := range p.PIIAllow {
		lines = append(lines, red+"  allow "+safeText(a, false)+reset)
	}
	return lines
}
