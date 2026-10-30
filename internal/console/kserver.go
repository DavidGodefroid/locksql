package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	kaudit "github.com/DavidGodefroid/lockkit/audit"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Server is lockkit's console backend: it serves the SQL methods and words
// the console's lines as locksql always did (the goldens of
// testdata/screens hold them).

// kpolicy is a locksql policy as lockkit's console holds it. Its JSON is
// the canonical policy: lockkit saves it as the approved policy and
// fingerprints it, exactly as config.SaveApproved and config.Fingerprint.
type kpolicy struct{ p config.Policy }

func (k kpolicy) MarshalJSON() ([]byte, error) { return json.Marshal(config.Canonical(k.p)) }

func (k *kpolicy) UnmarshalJSON(b []byte) error {
	var p config.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	k.p = config.Canonical(p)
	return nil
}

// Diff implements lockkit's config.Policy: the changes from approved to k.
func (k kpolicy) Diff(approved kconfig.Policy) []kconfig.Change {
	return config.Diff(approved.(kpolicy).p, k.p)
}

// Describe implements lockkit's config.Policy.
func (k kpolicy) Describe() []string { return describePolicy(k.p) }

// Profile is what lockkit's console needs of the profile.
func (k kpolicy) Profile() kconsole.Profile {
	pr := k.p.Profile
	where := pr.Host
	if pr.Engine == config.EngineSQLite {
		where = pr.Path
	}
	return kconsole.Profile{Name: pr.Name, Production: pr.Production, Where: where, Host: pr.Host, Port: pr.Port,
		User: pr.User, Credentials: pr.Credentials, VaultPath: pr.VaultPath, CredentialsTTL: pr.CredentialsTTL,
		IdleTimeout: pr.Limits.IdleTimeout, MaxSession: pr.Limits.MaxSession}
}

// noFingerFields is the audit text of a refusal for want of a finger; it
// is empty for any other outcome.
func noFingerFields(r Result) (reason, errText string) {
	if r.Outcome != NoFinger {
		return "", ""
	}
	return "no fingerprint", r.Err.Error()
}

// Methods implements kconsole.Backend: the SQL methods. hello, status,
// pii.list, pii.add, change.request and logout are the console's.
func (s *Server) Methods() map[string]kconsole.Handler {
	h := func(f func(context.Context, ipc.Request) ipc.Response) kconsole.Handler {
		return func(ctx context.Context, req ipc.Request, _ kconsole.Env) ipc.Response { return f(ctx, req) }
	}
	return map[string]kconsole.Handler{
		ipc.MethodCatalogList:     h(s.catalog),
		ipc.MethodCatalogDescribe: h(s.catalog),
		ipc.MethodQueryPlan:       h(s.queryPlan),
		ipc.MethodQueryRun:        h(s.queryRun),
	}
}

// Connect implements kconsole.Backend. locksql runs its own start-up
// (lifecycle.go) and reconnection (ServerConfig.Reconnect): lockkit's
// console never connects for it.
func (s *Server) Connect(context.Context, kconsole.Credentials) (kconsole.Session, error) {
	return nil, errors.New("console: locksql connects through its own start-up")
}

// Checks implements kconsole.Backend: the privilege audit of the tier in
// force. lockkit's console runs it when the profile becomes production.
func (s *Server) Checks(ctx context.Context, sess kconsole.Session) []kconsole.Finding {
	es, ok := kconsole.Unwrap(sess).(engine.Session)
	if !ok {
		return []kconsole.Finding{{Refuse: true, Text: "not a database session"}}
	}
	warns, err := es.ExtraPrivileges(ctx, s.profile.Tier)
	if err != nil {
		warns = append(warns, "privilege audit failed: "+secrets.Sanitize(err))
	}
	out := make([]kconsole.Finding, 0, len(warns))
	for _, w := range warns {
		out = append(out, kconsole.Finding{Text: w})
	}
	return out
}

// LoadPolicy implements kconsole.Backend.
func (s *Server) LoadPolicy() (kconsole.Policy, error) {
	if s.cfg.LoadPolicy == nil {
		return kpolicy{s.approved}, nil // nothing to poll: the policy in force
	}
	p, err := s.cfg.LoadPolicy()
	if err != nil {
		return nil, err
	}
	return kpolicy{p}, nil
}

// ApplyPolicy implements kconsole.PolicyApplier: it compiles the PII rules,
// the detectors and the SQL dialect of p, which then is in force.
func (s *Server) ApplyPolicy(kp kconsole.Policy) error {
	p := kp.(kpolicy).p
	d, err := sqlclass.DialectFor(p.Profile.Engine)
	if err != nil {
		return err
	}
	ds, err := pii.Detectors(p.Profile.Detectors)
	if err != nil {
		return err
	}
	// Before anything changes: a policy is applied whole or not at all.
	fp, err := ticket.HashOf(p)
	if err != nil {
		return err
	}
	s.approved = p
	s.profile = p.Profile
	s.rules = pii.Rules{Mask: append([]string(nil), p.PIIMask...), Allow: append([]string(nil), p.PIIAllow...), Modes: p.PIIModes}
	s.detectors = ds
	s.dialect = d
	s.setLive(fp) // what the hub's goroutine checks tickets against
	return nil
}

// Status implements kconsole.Backend (unused: StatusAnswer answers).
func (s *Server) Status(kconsole.Session) any { return nil }

// StatusAnswer implements kconsole.StatusAnswerer: locksql's clients read
// a flat status answer.
func (s *Server) StatusAnswer(c kconsole.StatusResult, _ kconsole.Session) any { return s.statusOf(c) }

func (s *Server) statusOf(c kconsole.StatusResult) ipc.StatusResult {
	return ipc.StatusResult{
		Profile:        s.profile.Name,
		Engine:         s.profile.Engine,
		Host:           s.host(),
		HostConfirmed:  true, // the host is part of the approved policy
		Production:     s.profile.Production,
		AutoApprove:    c.AutoApprove,
		AllowUnmask:    c.AllowUnmask,
		ShowResults:    c.ShowResults,
		Tier:           s.profile.Tier.String(),
		Databases:      nonNil(s.cfg.Databases),
		Limits:         s.profile.Limits,
		IdleTimeoutInS: c.IdleTimeoutInS,
		SessionEndsInS: c.SessionEndsInS,
		Health:         s.cfg.Health,
	}
}

// StatusRows implements kconsole.StatusRower: the :status screen.
func (s *Server) StatusRows(v kconsole.StatusView) [][2]string {
	st := s.statusOf(v.Status)
	l := st.Limits
	w := s.Words()
	rows := [][2]string{
		{"profile", fmt.Sprintf("%s · %s %s · tier %s · production %t", st.Profile, st.Engine, safeText(st.Host, false), st.Tier, st.Production)},
		{"databases", safeText(strings.Join(st.Databases, ", "), false)},
		{"mode", kconsole.StatusModeRow(v, w)},
		{"results", kconsole.StatusResultsRow(v, w)},
		{"unmask", kconsole.StatusUnmaskRow(v)},
		{"limits", fmt.Sprintf("timeout %s · warn %d · refuse %d · max_rows %d · max_cell_chars %d · max_output_bytes %d",
			l.StatementTimeout, l.ExplainRowsWarn, l.ExplainRowsRefuse, l.MaxRows, l.MaxCellChars, l.MaxOutputBytes)},
		{"session", fmt.Sprintf("ends in %d min (max_session %s) · idle_timeout %s", st.SessionEndsInS/60, l.MaxSession, l.IdleTimeout)},
		{"plans open", fmt.Sprint(len(s.plans))},
		{"policy change", kconsole.StatusPendingRow(v)},
	}
	if b := kconsole.StatusBoundaryRow(v); b != "" {
		rows = append(rows, [2]string{"boundary", b})
	}
	return rows
}

// StatusLineParts implements kconsole.StatusLiner: the tier follows the
// profile name, and the open plans are counted.
func (s *Server) StatusLineParts(kconsole.StatusView) (string, []string) {
	var parts []string
	if n := len(s.plans); n > 0 {
		parts = append(parts, fmt.Sprintf("%d plan%s open", n, plural(n)))
	}
	return paint.Dim("tier " + s.profile.Tier.String()), parts
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// FormatChanges implements kconsole.ChangeFormatter.
func (s *Server) FormatChanges(changes []kconfig.Change) []string { return formatChanges(changes) }

// ConnectionChanged implements kconsole.ConnectionComparer: a change of the
// connection settings, the transport (the tls settings, the ssh table,
// proxy_command) included, ends the session: the open connection no longer
// matches the policy.
func (s *Server) ConnectionChanged(oldP, nextP kconsole.Policy) bool {
	old, n := oldP.(kpolicy).p.Profile, nextP.(kpolicy).p.Profile
	return old.Engine != n.Engine || old.Host != n.Host || old.Port != n.Port || old.Path != n.Path ||
		old.User != n.User || old.Database != n.Database ||
		old.TLS != n.TLS || old.TLSCA != n.TLSCA || old.TLSCert != n.TLSCert || old.TLSKey != n.TLSKey ||
		old.TLSServerName != n.TLSServerName || !sameSSH(old.SSH, n.SSH) || !slices.Equal(old.ProxyCommand, n.ProxyCommand)
}

// sameSSH reports two ssh tables that reach the database the same way;
// nil is no tunnel.
func sameSSH(a, b *config.SSHProfile) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Words implements kconsole.Worder: locksql's words for the console's
// lines.
func (s *Server) Words() kconsole.Words {
	return kconsole.Words{
		AutoStart:        "auto mode: statements allowed by the tier and the weight check run without a prompt (Shift+Tab: manual)",
		AutoOn:           "auto mode: statements allowed by the tier and the weight check run without a prompt; unmasked queries and REFUSE verdicts are still prompted or refused (Shift+Tab: back to manual)",
		Manual:           "manual mode: every statement is prompted",
		NoAutoProduction: "auto mode is not available on a production profile: every statement is prompted",
		NoAutoHub:        "auto mode is not available in hub mode: lockhub decides every statement",
		StatusAuto:       "auto: statements allowed by the tier and the weight check run without a prompt",
		StatusManual:     "manual: every statement is prompted",
		ResultsOn:        "results: the result of each query is printed here in clear, PII included; the agent still gets it masked (Ctrl-O: hide)",
		StatusResults:    "shown here in clear, PII included",
		UnmaskAsk:        "allow clients to ask for unmasked PII output? Each such query is still approved here, never auto-approved",
		UnmaskOff:        "unmask: off; clients get masked output only, and open unmask plans are refused",
		ReviewAuto:       "auto mode is on: once applied, statements run without a prompt",
		ChangeQueued: func(change string) string {
			return "change requested by a client: " + change + " — type :review to see it"
		},
		Reconnecting: "reconnecting to the database…",
		TTLReached: func(ttl time.Duration, credentials string) string {
			if credentials == config.CredentialsVault {
				return fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and a fresh login read from Vault", ttl)
			}
			return fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and the secret asked again", ttl)
		},
		ProductionChecks: func(kconsole.Profile, []kconsole.Finding) (string, string) {
			return "the profile is now production and the account has privileges beyond tier " + s.profile.Tier.String() + ": the session ends",
				"privilege audit failed after the profile became production"
		},
		ConnLost: "the database connection is lost; the human must restart the console",
	}
}

// AuditRecord turns the console's own records (modes, policy, login) into
// locksql's, stamped with the database and its user.
func (s *Server) AuditRecord(b kaudit.Base) kaudit.Record {
	return s.stamp(audit.Record{Event: b.Event, Profile: b.Profile, Decision: b.Decision, Error: b.Error, Code: b.Code, Span: b.Span,
		Warnings: b.Warnings, Intent: b.Intent, Reason: b.Reason, Approval: b.Approval, PeerUID: b.PeerUID, PeerPID: b.PeerPID,
		PeerUser: b.PeerUser, Ticket: b.Ticket, Approver: b.Approver, Facade: b.Facade, HubSig: b.HubSig})
}

// PIIRules implements kconsole.PIIBackend (pii.list), sorted.
func (s *Server) PIIRules(kp kconsole.Policy) (mask, allow []string) {
	p := kp.(kpolicy).p
	return nonNil(p.PIIMask), nonNil(p.PIIAllow)
}

// CheckMask implements kconsole.PIIBackend: the canonical form of a
// db.table.column pattern.
func (s *Server) CheckMask(pattern string) (string, error) {
	var probe pii.Rules
	if err := probe.Add(pattern); err != nil {
		return "", err
	}
	return probe.Mask[0], nil
}

// SaveMask implements kconsole.PIIBackend: the rule is added to the rule
// set's file as it is on disk, so that unconfirmed edits of the human are
// neither lost nor applied.
func (s *Server) SaveMask(pattern string) error {
	onDisk, err := pii.LoadRulesFile(s.cfg.RulesPath)
	if err != nil {
		return err
	}
	if err := onDisk.Add(pattern); err != nil {
		return err
	}
	return pii.SaveRulesFile(s.cfg.RulesPath, onDisk)
}

// WithMask implements kconsole.PIIBackend.
func (s *Server) WithMask(kp kconsole.Policy, pattern string) kconsole.Policy {
	p := kp.(kpolicy).p
	mask := append(append([]string(nil), p.PIIMask...), pattern)
	return kpolicy{config.NewPolicy(p.Profile, mask, p.PIIAllow).WithModes(p.PIIModes)}
}
