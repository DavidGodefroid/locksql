package config

import (
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/kit"

	"github.com/DavidGodefroid/locksql/internal/product"
)

// Policy is the security-relevant view of one profile plus its PII rules.
// The console compares the current policy with the last approved one and
// asks the human before applying any loosening.
type Policy struct {
	Profile  Profile  `json:"profile"`
	PIIMask  []string `json:"pii_mask"`  // sorted column patterns
	PIIAllow []string `json:"pii_allow"` // sorted column patterns
	// PIIModes maps a mask pattern to its mode when it is not the default
	// (redact): partial or email.
	PIIModes map[string]string `json:"pii_modes,omitempty"`
}

// NewPolicy builds a policy with sorted, de-duplicated PII lists.
func NewPolicy(p Profile, mask, allow []string) Policy {
	return canonical(Policy{Profile: p, PIIMask: mask, PIIAllow: allow})
}

// WithModes returns p with the mask modes m (pattern -> mode).
func (p Policy) WithModes(m map[string]string) Policy {
	p.PIIModes = m
	return canonical(p)
}

// DefaultMaskMode is the mode of a mask rule that sets none.
const DefaultMaskMode = "redact"

// Canonical is p in its canonical form: sorted lists, defaults applied.
// Its JSON is what is saved as the approved policy and fingerprinted.
func Canonical(p Policy) Policy { return canonical(p) }

func canonical(p Policy) Policy {
	p.Profile.Detectors = kconfig.SortedSet(p.Profile.Detectors)
	p.PIIMask = kconfig.SortedSet(p.PIIMask)
	p.PIIAllow = kconfig.SortedSet(p.PIIAllow)
	var modes map[string]string
	for pat, m := range p.PIIModes {
		if m == "" || m == DefaultMaskMode {
			continue
		}
		if _, found := slices.BinarySearch(p.PIIMask, pat); !found {
			continue
		}
		if modes == nil {
			modes = map[string]string{}
		}
		modes[pat] = m
	}
	p.PIIModes = modes
	if l := &p.Profile.Limits; l.IdleTimeout == 0 || l.MaxSession == 0 {
		// Approved before the session limits existed: the defaults applied.
		d := DefaultLimits(p.Profile.Production)
		if l.MaxSession == 0 {
			l.MaxSession = d.MaxSession
		}
		if l.IdleTimeout == 0 {
			l.IdleTimeout = min(d.IdleTimeout, l.MaxSession)
		}
	}
	if p.Profile.WriteFunctions == WriteFunctionsDenylist {
		p.Profile.WriteFunctions = "" // the default
	}
	if p.Profile.TLS == "" && p.Profile.Engine != EngineSQLite && p.Profile.Engine != "" {
		p.Profile.TLS = TLSPrefer // approved before the setting existed
	}
	return p
}

// modeOf is the mode of a mask pattern in p.
func (p Policy) modeOf(pat string) string {
	if m, ok := p.PIIModes[pat]; ok {
		return m
	}
	return DefaultMaskMode
}

// Fingerprint returns the hex sha256 of the policy's canonical JSON.
// List order does not change the fingerprint.
// Only an out-of-range Tier can fail to encode; lockkit then fingerprints
// its raw form so that it still differs from every valid policy.
func Fingerprint(p Policy) string { return kconfig.Fingerprint(canonical(p)) }

// Diff lists the changes from approved to current and marks each loosening
// (spec section 4): a higher tier, production true→false, a larger limit
// (0 means unlimited), a longer idle_timeout or max_session, a removed PII
// rule or detector, an added allow rule, any change of engine, host, port,
// path, database or user, and a credentials mode other than ask, a weaker
// tls mode, any change of tls_ca, tls_cert, tls_key or tls_server_name, any
// change of the ssh table or of proxy_command, any change of the PII rule
// set, and write_functions from allowlist to denylist.
func Diff(approved, current Policy) []Change {
	a, c := canonical(approved), canonical(current)
	ap, cp := a.Profile, c.Profile
	var out []Change

	same := func(field, o, n string) {
		if o != n {
			out = append(out, Change{Field: field, Old: o, New: n, Loosens: true})
		}
	}
	same("engine", ap.Engine, cp.Engine)
	same("host", ap.Host, cp.Host)
	same("port", strconv.Itoa(ap.Port), strconv.Itoa(cp.Port))
	same("path", ap.Path, cp.Path)
	same("database", ap.Database, cp.Database)
	same("user", ap.User, cp.User)

	if ap.Tier != cp.Tier {
		out = append(out, Change{Field: "tier", Old: ap.Tier.String(), New: cp.Tier.String(), Loosens: cp.Tier > ap.Tier})
	}
	if ap.Production != cp.Production {
		out = append(out, Change{Field: "production", Old: strconv.FormatBool(ap.Production), New: strconv.FormatBool(cp.Production), Loosens: ap.Production})
	}
	if ap.Credentials != cp.Credentials {
		out = append(out, Change{Field: "credentials", Old: ap.Credentials, New: cp.Credentials, Loosens: cp.Credentials != CredentialsAsk})
	}
	// Another Vault path is another login, possibly with more grants.
	same("vault_path", ap.VaultPath, cp.VaultPath)
	if ap.TLS != cp.TLS {
		out = append(out, Change{Field: "tls", Old: ap.TLS, New: cp.TLS, Loosens: TLSRank(cp.TLS) < TLSRank(ap.TLS)})
	}
	// A new CA can vouch for any certificate: every change loosens.
	same("tls_ca", ap.TLSCA, cp.TLSCA)
	// Another client certificate is another identity on the server, and
	// another server name accepts another certificate: every change loosens.
	same("tls_cert", ap.TLSCert, cp.TLSCert)
	same("tls_key", ap.TLSKey, cp.TLSKey)
	same("tls_server_name", ap.TLSServerName, cp.TLSServerName)

	switch as, cs := ap.SSH, cp.SSH; {
	case as == nil && cs == nil:
	case as == nil || cs == nil:
		// Added or removed: the database is reached another way.
		out = append(out, Change{Field: "ssh", Old: SSHString(as), New: SSHString(cs), Loosens: true})
	default:
		same("ssh.host", as.Host, cs.Host)
		same("ssh.port", strconv.Itoa(as.Port), strconv.Itoa(cs.Port))
		same("ssh.user", as.User, cs.User)
		same("ssh.auth", as.Auth, cs.Auth)
		same("ssh.key", as.Key, cs.Key)
		if as.Credentials != cs.Credentials {
			out = append(out, Change{Field: "ssh.credentials", Old: as.Credentials, New: cs.Credentials, Loosens: cs.Credentials != CredentialsAsk})
		}
	}

	// Another command reaches the database another way, as the console
	// account: every change loosens.
	same("proxy_command", ProxyString(ap.ProxyCommand), ProxyString(cp.ProxyCommand))

	limit := func(field string, o, n int64, format func(int64) string) {
		if o != n {
			out = append(out, Change{Field: "limits." + field, Old: format(o), New: format(n), Loosens: kconfig.LooserLimit(o, n)})
		}
	}
	num := func(v int64) string { return strconv.FormatInt(v, 10) }
	dur := func(v int64) string { return time.Duration(v).String() }
	al, cl := ap.Limits, cp.Limits
	limit("statement_timeout", int64(al.StatementTimeout), int64(cl.StatementTimeout), dur)
	limit("explain_rows_warn", al.ExplainRowsWarn, cl.ExplainRowsWarn, num)
	limit("explain_rows_refuse", al.ExplainRowsRefuse, cl.ExplainRowsRefuse, num)
	limit("max_rows", int64(al.MaxRows), int64(cl.MaxRows), num)
	limit("max_cell_chars", int64(al.MaxCellChars), int64(cl.MaxCellChars), num)
	limit("max_output_bytes", int64(al.MaxOutputBytes), int64(cl.MaxOutputBytes), num)
	if al.ExplainCostRefuse != cl.ExplainCostRefuse {
		f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
		out = append(out, Change{Field: "limits.explain_cost_refuse", Old: f(al.ExplainCostRefuse), New: f(cl.ExplainCostRefuse),
			Loosens: cl.ExplainCostRefuse == 0 || al.ExplainCostRefuse != 0 && cl.ExplainCostRefuse > al.ExplainCostRefuse})
	}
	if al.KAnonymity != cl.KAnonymity {
		// A smaller k loosens; 0 (an approved policy from before k existed)
		// is the loosest.
		out = append(out, Change{Field: "limits.k_anonymity", Old: num(int64(al.KAnonymity)), New: num(int64(cl.KAnonymity)),
			Loosens: cl.KAnonymity < al.KAnonymity})
	}
	// 0 is an approved policy from before reference_probe existed: the
	// default applied, so the current value is compared with it.
	rp := al.ReferenceProbe
	if rp == 0 {
		rp = DefaultLimits(ap.Production).ReferenceProbe
	}
	if rp != cl.ReferenceProbe {
		out = append(out, Change{Field: "limits.reference_probe", Old: num(int64(rp)), New: num(int64(cl.ReferenceProbe)),
			Loosens: cl.ReferenceProbe > rp})
	}
	// A longer session limit loosens. canonical gave a policy approved
	// before they existed their defaults.
	for _, f := range []struct {
		field string
		o, n  time.Duration
	}{{"idle_timeout", al.IdleTimeout, cl.IdleTimeout}, {"max_session", al.MaxSession, cl.MaxSession}} {
		if f.o != f.n {
			out = append(out, Change{Field: "limits." + f.field, Old: f.o.String(), New: f.n.String(), Loosens: f.n > f.o})
		}
	}
	if ap.WriteFunctions != cp.WriteFunctions {
		name := func(v string) string {
			if v == "" {
				return WriteFunctionsDenylist
			}
			return v
		}
		out = append(out, Change{Field: "write_functions", Old: name(ap.WriteFunctions), New: name(cp.WriteFunctions),
			Loosens: ap.WriteFunctions == WriteFunctionsAllowlist})
	}
	if ap.CredentialsTTL != cp.CredentialsTTL {
		out = append(out, Change{Field: "credentials_ttl", Old: dur(int64(ap.CredentialsTTL)), New: dur(int64(cp.CredentialsTTL)),
			Loosens: kconfig.LooserLimit(int64(ap.CredentialsTTL), int64(cp.CredentialsTTL))})
	}

	// Another rule set can drop masks, now or at its next edit. An approval
	// from before named sets has none: its rules came from the shared
	// pii.toml, and the rule lists below show what differs.
	if ap.PIIRules != "" && ap.PIIRules != cp.PIIRules {
		out = append(out, Change{Field: "pii_rules", Old: ap.PIIRules, New: cp.PIIRules, Loosens: true})
	}

	out = append(out, kconfig.SetDiff("detectors", ap.Detectors, cp.Detectors, true)...)
	out = append(out, kconfig.SetDiff("pii.mask", a.PIIMask, c.PIIMask, true)...)
	out = append(out, kconfig.SetDiff("pii.allow", a.PIIAllow, c.PIIAllow, false)...)
	for _, pat := range c.PIIMask {
		if _, found := slices.BinarySearch(a.PIIMask, pat); !found {
			if m := c.modeOf(pat); m != DefaultMaskMode {
				// A new rule's mode is shown with it; it only tightens.
				out = append(out, Change{Field: "pii.mode", New: pat + " = " + m})
			}
			continue
		}
		if o, n := a.modeOf(pat), c.modeOf(pat); o != n {
			// Any mode but redact reveals more than redact; between the
			// others there is no order, so every other change loosens.
			out = append(out, Change{Field: "pii.mode", Old: pat + " = " + o, New: pat + " = " + n, Loosens: n != "redact"})
		}
	}
	return out
}

// ApprovedKey names the approved-policy file of a profile:
// <ProjectHash(root)>-<profile>, or user-<profile> for a profile that comes
// from the user config only (root == "").
func ApprovedKey(root, profile string) string { return kconfig.ApprovedKey(root, profile) }

// LoadApproved reads <stateDir>/locksql/approved/<key>.json. When no policy
// was approved yet, the error wraps fs.ErrNotExist.
func LoadApproved(stateDir, key string) (*Policy, error) {
	var p Policy
	ok, err := kconfig.LoadApproved(product.P, stateDir, key, &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("config: approved policy: %w", fs.ErrNotExist)
	}
	p = canonical(p)
	return &p, nil
}

// SaveApproved atomically writes the policy to
// <stateDir>/locksql/approved/<key>.json with mode 0600.
func SaveApproved(stateDir, key string, p Policy) error {
	return kconfig.SaveApproved(product.P, stateDir, key, canonical(p))
}

// StateDir returns the user state directory (without the locksql suffix):
// $XDG_STATE_HOME or ~/.local/state on Linux and other Unix systems,
// and os.UserConfigDir() on macOS.
func StateDir() (string, error) { return kit.StateBase() }
