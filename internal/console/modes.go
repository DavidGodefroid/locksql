package console

import (
	"fmt"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/ui"
)

// The console's live switches: the approval mode (manual, where every
// statement is prompted, or auto, where statements allowed by the tier and
// the weight check run without a prompt) and the clear results (the
// result of each masked query printed here, in clear). Both change only
// from the console's own keyboard, Shift+Tab and Ctrl-O (or :mode and
// :results), never from a client or a config file, and each change is
// audited. A production profile stays in manual mode.

// autoApprove reports whether auto mode is in effect: never on a
// production profile.
func (s *Server) autoApprove() bool { return s.auto && !s.profile.Production }

// modeName is the approval mode in effect, for the audit log and the
// status line.
func (s *Server) modeName() string {
	if s.autoApprove() {
		return "auto"
	}
	return "manual"
}

// Key handles a control key pressed in the console.
func (s *Server) Key(k Key) {
	s.lastSeen = s.now()
	switch k {
	case KeyShiftTab:
		s.toggleMode()
	case KeyCtrlO:
		s.toggleResults()
	}
}

// toggleMode switches between manual and auto mode, and says so.
func (s *Server) toggleMode() {
	if s.profile.Production {
		s.println(paint.Warn("auto mode is not available on a production profile: every statement is prompted"))
		return
	}
	s.auto = !s.auto
	s.audit(audit.Record{Event: audit.EventMode, Decision: s.modeName()})
	if s.auto {
		s.println(paint.Yellow(ui.MarkWarn + " auto mode: statements allowed by the tier and the weight check run without a prompt; unmasked queries and REFUSE verdicts are still prompted or refused (Shift+Tab: back to manual)"))
	} else {
		s.println(paint.OK("manual mode: every statement is prompted"))
	}
	s.refreshStatus()
}

// toggleResults switches the clear results on or off, and says so.
func (s *Server) toggleResults() {
	s.showResults = !s.showResults
	decision := "hidden"
	if s.showResults {
		decision = "shown"
	}
	s.audit(audit.Record{Event: audit.EventResults, Decision: decision})
	if s.showResults {
		msg := "results: the result of each query is printed here in clear, PII included; the agent still gets it masked (Ctrl-O: hide)"
		if s.profile.Production {
			s.println(red + ui.MarkWarn + " " + msg + " (PRODUCTION data: mind screen sharing and the terminal's scrollback)" + reset)
		} else {
			s.println(paint.Warn(msg))
		}
	} else {
		s.println(paint.OK("results: hidden here; only the masked result leaves, to the agent"))
	}
	s.refreshStatus()
}

// statusLine is the text of the status row: the profile, the mode, the
// results switch, what else widens the session and what awaits the human.
func (s *Server) statusLine() string {
	sep := paint.Dim(" · ")
	name := strings.ToUpper(s.profile.Name)
	if s.profile.Production {
		name = paint.Red(name)
	} else {
		name = paint.Brand(name)
	}
	parts := []string{name + " " + paint.Dim("tier "+s.profile.Tier.String())}
	mode := paint.Green("manual")
	if s.autoApprove() {
		mode = paint.Paint(bold+ui.Yellow, "AUTO")
	}
	if s.profile.Production {
		parts = append(parts, "mode "+mode)
	} else {
		parts = append(parts, "mode "+mode+" "+paint.Dim("⇧Tab"))
	}
	results := paint.Dim("masked")
	if s.showResults {
		results = paint.Yellow("clear")
	}
	parts = append(parts, "results "+results+" "+paint.Dim("^O"))
	if s.cfg.AllowUnmask {
		parts = append(parts, paint.Red("unmask allowed"))
	}
	if n := len(s.plans); n > 0 {
		parts = append(parts, fmt.Sprintf("%d plan%s open", n, plural(n)))
	}
	if s.pending != nil {
		parts = append(parts, paint.Red("policy change pending")+" "+paint.Dim(":review"))
	}
	if n := len(s.requests); n > 0 {
		parts = append(parts, fmt.Sprintf("%d change request%s", n, plural(n))+" "+paint.Dim(":review"))
	}
	return strings.Join(parts, sep)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// refreshStatus redraws the status row when the IO has one.
func (s *Server) refreshStatus() {
	if st, ok := s.cfg.IO.(StatusLine); ok {
		st.SetStatus(s.statusLine())
	}
}

// clearStatus removes the status row when the IO has one.
func (s *Server) clearStatus() {
	if st, ok := s.cfg.IO.(StatusLine); ok {
		st.SetStatus("")
	}
}
