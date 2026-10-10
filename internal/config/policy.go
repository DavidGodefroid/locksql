package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"time"
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

// Change is one difference between two policies. For list fields (detectors,
// pii.mask, pii.allow) each added or removed element is its own Change, with
// Old empty for an addition and New empty for a removal.
type Change struct {
	Field    string
	Old, New string
	Loosens  bool
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

// sortedSet returns a sorted, de-duplicated, non-nil copy of s.
func sortedSet(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func canonical(p Policy) Policy {
	p.Profile.Detectors = sortedSet(p.Profile.Detectors)
	p.PIIMask = sortedSet(p.PIIMask)
	p.PIIAllow = sortedSet(p.PIIAllow)
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
func Fingerprint(p Policy) string {
	b, err := json.Marshal(canonical(p))
	if err != nil {
		// Only an out-of-range Tier can fail; fingerprint its raw form so
		// that it still differs from every valid policy.
		b = fmt.Appendf(nil, "invalid:%#v", p)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SSHString shows a bastion in a policy change.
func SSHString(s *SSHProfile) string {
	if s == nil {
		return "none"
	}
	return s.User + "@" + s.Host + ":" + strconv.Itoa(s.Port) + " (" + s.Auth + ")"
}

// Diff lists the changes from approved to current and marks each loosening
// (spec section 4): a higher tier, production true→false, a larger limit
// (0 means unlimited), a removed PII rule or detector, an added allow rule,
// any change of engine, host, port, path, database or user, and a
// credentials mode other than ask, a weaker tls mode, any change of tls_ca and any change of the ssh table.
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
	if ap.TLS != cp.TLS {
		out = append(out, Change{Field: "tls", Old: ap.TLS, New: cp.TLS, Loosens: TLSRank(cp.TLS) < TLSRank(ap.TLS)})
	}
	// A new CA can vouch for any certificate: every change loosens.
	same("tls_ca", ap.TLSCA, cp.TLSCA)

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

	limit := func(field string, o, n int64, format func(int64) string) {
		if o != n {
			out = append(out, Change{Field: "limits." + field, Old: format(o), New: format(n), Loosens: looserLimit(o, n)})
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
	if ap.CredentialsTTL != cp.CredentialsTTL {
		out = append(out, Change{Field: "credentials_ttl", Old: dur(int64(ap.CredentialsTTL)), New: dur(int64(cp.CredentialsTTL)),
			Loosens: looserLimit(int64(ap.CredentialsTTL), int64(cp.CredentialsTTL))})
	}

	out = append(out, setDiff("detectors", ap.Detectors, cp.Detectors, true)...)
	out = append(out, setDiff("pii.mask", a.PIIMask, c.PIIMask, true)...)
	out = append(out, setDiff("pii.allow", a.PIIAllow, c.PIIAllow, false)...)
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

// looserLimit reports whether moving a limit from o to n loosens it.
// Zero means unlimited.
func looserLimit(o, n int64) bool {
	switch {
	case n == 0:
		return o != 0
	case o == 0:
		return false
	default:
		return n > o
	}
}

// setDiff reports removed and added elements of two sorted sets. When
// removalLoosens, a removal loosens the policy; otherwise an addition does.
func setDiff(field string, old, cur []string, removalLoosens bool) []Change {
	var out []Change
	for _, v := range old {
		if _, found := slices.BinarySearch(cur, v); !found {
			out = append(out, Change{Field: field, Old: v, Loosens: removalLoosens})
		}
	}
	for _, v := range cur {
		if _, found := slices.BinarySearch(old, v); !found {
			out = append(out, Change{Field: field, New: v, Loosens: !removalLoosens})
		}
	}
	return out
}

var stateKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ApprovedKey names the approved-policy file of a profile:
// <ProjectHash(root)>-<profile>, or user-<profile> for a profile that comes
// from the user config only (root == "").
func ApprovedKey(root, profile string) string {
	if root == "" {
		return "user-" + profile
	}
	return ProjectHash(root) + "-" + profile
}

func approvedPath(stateDir, key string) (string, error) {
	if !stateKeyRe.MatchString(key) {
		return "", fmt.Errorf("config: invalid approved-policy key %q", key)
	}
	return filepath.Join(stateDir, appDirName, "approved", key+".json"), nil
}

// LoadApproved reads <stateDir>/locksql/approved/<key>.json. When no policy
// was approved yet, the error wraps fs.ErrNotExist.
func LoadApproved(stateDir, key string) (*Policy, error) {
	path, err := approvedPath(stateDir, key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: approved policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("config: approved policy %s: %w", path, err)
	}
	p = canonical(p)
	return &p, nil
}

// SaveApproved atomically writes the policy to
// <stateDir>/locksql/approved/<key>.json with mode 0600.
func SaveApproved(stateDir, key string, p Policy) error {
	path, err := approvedPath(stateDir, key)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(canonical(p), "", "  ")
	if err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+key+".*.tmp")
	if err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	ok = true
	return nil
}

// StateDir returns the user state directory (without the locksql suffix):
// $XDG_STATE_HOME or ~/.local/state on Linux and other Unix systems,
// and os.UserConfigDir() on macOS.
func StateDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return os.UserConfigDir()
	default:
		if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
			return d, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if home == "" {
			return "", errors.New("config: no home directory for the state dir")
		}
		return filepath.Join(home, ".local", "state"), nil
	}
}
