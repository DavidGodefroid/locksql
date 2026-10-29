package console

import (
	"context"
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/ui"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// The console's live switches: the approval mode (manual, where every
// statement is prompted, or auto, where statements allowed by the tier and
// the weight check run without a prompt), the clear results (the result of
// each masked query printed here, in clear) and unmasked output (whether a
// client may ask for it, each such query then approved here). They change
// only from the console's own keyboard, Shift+Tab, Ctrl-O and :unmask (or
// :mode and :results), never from a client or a config file, and each
// change is audited. A production profile stays in manual mode. Allowing
// unmasked output is a typed command confirmed with y, never a single key.

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

// widenRefused refuses a switch that widens while a prompt waits for the
// human: the answer or the finger meant for that prompt must not decide
// another decision nested in it. Narrowing stays allowed.
func (s *Server) widenRefused(what string) bool {
	if s.prompting == 0 {
		return false
	}
	s.println(paint.Warn(what + ": not while a prompt waits; answer it first"))
	return true
}

// toggleMode switches between manual and auto mode, and says so.
func (s *Server) toggleMode() {
	if s.profile.Production {
		s.println(paint.Warn("auto mode is not available on a production profile: every statement is prompted"))
		return
	}
	if !s.auto && s.cfg.Hub != nil {
		s.println(paint.Warn("auto mode is not available in hub mode: lockhub decides every statement"))
		return
	}
	if !s.auto && s.widenRefused("auto mode") {
		return
	}
	if !s.auto && s.cfg.Fingerprint {
		// Level 2: auto mode widens what runs unprompted, so a typed
		// answer alone, which the agent could type too, never turns it on.
		if r := s.decide(context.Background(), Decision{Prompt: "Switch to auto mode? [y/N] ", Expected: "y"}); r.Outcome != Approved {
			if reason, errText := noFingerFields(r); reason != "" {
				s.audit(audit.Record{Event: audit.EventMode, Decision: "refused", Reason: reason, Error: errText})
			}
			s.println("mode: still manual")
			s.refreshStatus()
			return
		}
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
	if !s.showResults && s.cfg.Fingerprint {
		// Level 2: the window is on the agent's desktop, which could read
		// the clear results off it.
		s.println(paint.Warn("results stay masked at level 2: the window is on the agent's desktop"))
		return
	}
	if !s.showResults && s.level1() {
		// Level 1: the agent's account can read this window.
		s.println(paint.Warn("results stay masked at level 1: the agent's account can read this window"))
		return
	}
	if !s.showResults && s.widenRefused("clear results") {
		return
	}
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

// toggleUnmask allows or stops unmasked output, and says so. Allowing it
// widens what a client may ask for: the human confirms it. Turning it off
// takes effect at once, open unmask plans included.
func (s *Server) toggleUnmask(ctx context.Context) {
	if s.allowUnmask {
		s.allowUnmask = false
		s.audit(audit.Record{Event: audit.EventUnmask, Decision: "off"})
		s.println(paint.OK("unmask: off; clients get masked output only, and open unmask plans are refused"))
		s.refreshStatus()
		return
	}
	if s.widenRefused("unmask") {
		return
	}
	warn := "allow clients to ask for unmasked PII output? Each such query is still approved here, never auto-approved"
	if s.profile.Production {
		warn += " (PRODUCTION data)"
	}
	s.println(red + ui.MarkWarn + " " + warn + reset)
	if r := s.decide(ctx, Decision{Prompt: "Allow unmasked output? [y/N] ", Expected: "y"}); r.Outcome != Approved {
		if reason, errText := noFingerFields(r); reason != "" {
			s.audit(audit.Record{Event: audit.EventUnmask, Decision: "refused", Reason: reason, Error: errText})
		}
		s.println("unmask: still off")
		return
	}
	s.allowUnmask = true
	s.audit(audit.Record{Event: audit.EventUnmask, Decision: "allowed", Approval: s.approver.Mode()})
	s.println(red + "unmask: allowed; clients may ask for unmasked output, approved here each time (:unmask: off)" + reset)
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
	if s.allowUnmask {
		parts = append(parts, paint.Red("unmask allowed"))
	}
	if n := len(s.plans); n > 0 {
		parts = append(parts, fmt.Sprintf("%d plan%s open", n, plural(n)))
	}
	if s.level1() {
		parts = append(parts, paint.Red("level 1: desktop boundary"))
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

// level1 reports the desktop shape without a fingerprint reader: the
// agent's account can read this window.
func (s *Server) level1() bool { return s.cfg.Boundary != "" && !s.cfg.Fingerprint }
