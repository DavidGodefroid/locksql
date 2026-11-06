package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The auto mode of a profile (locksql#185): for each action, what `lox
// run` does with a ticket of this profile while it runs in auto mode. In
// manual mode it asks for everything, whatever the profile says.
//
//	[profiles.local]
//	auto = "full-auto"
//
//	[profiles.prod.auto]
//	connect = "ask"
//	read = "auto"
//	write = "ask"
//	ddl = "deny"
//
// The lock enforces its side: an action whose rule is deny is refused
// before any ticket, and the ticket of an action whose rule is ask is
// marked never-auto (ticket.Flags.NeverAuto), so that no auto rule may
// approve it.

// AutoValue is what auto mode does with one action.
type AutoValue string

// The values of an action, from the strictest.
const (
	// AutoDeny refuses the action, even when a human would approve it.
	AutoDeny AutoValue = "deny"
	// AutoAsk asks the human: once per lox run session for connect, every
	// time for the other actions.
	AutoAsk AutoValue = "ask"
	// AutoAuto approves the action without a question.
	AutoAuto AutoValue = "auto"
)

// rank orders the values from the strictest: a higher rank loosens.
func (v AutoValue) rank() int {
	switch v {
	case AutoDeny:
		return 0
	case AutoAsk:
		return 1
	case AutoAuto:
		return 2
	}
	return -1
}

// ParseAutoValue parses "auto", "ask" or "deny".
func ParseAutoValue(s string) (AutoValue, error) {
	if v := AutoValue(s); v.rank() >= 0 {
		return v, nil
	}
	return "", errors.New("want auto, ask or deny")
}

// AutoAction is what a rule applies to.
type AutoAction string

// The actions of an auto rule.
const (
	// ActionConnect opens the profile's connection.
	ActionConnect AutoAction = "connect"
	// ActionRead runs a read (SELECT, a grant's scope).
	ActionRead AutoAction = "read"
	// ActionWrite runs a write: INSERT, UPDATE, UPSERT, DELETE, MERGE.
	ActionWrite AutoAction = "write"
	// ActionDDL runs a schema change, or an admin statement.
	ActionDDL AutoAction = "ddl"
	// ActionUnmask runs a read whose results come back in clear.
	ActionUnmask AutoAction = "unmask"
)

// AutoActions lists the actions in the order they are shown.
var AutoActions = []AutoAction{ActionConnect, ActionRead, ActionWrite, ActionDDL, ActionUnmask}

// PresetFullAuto sets every action to auto; PresetDefault is the
// defaults (DefaultAutoRules).
const (
	PresetFullAuto = "full-auto"
	PresetDefault  = "default"
)

// AutoRules is the auto mode of a profile, one value per action. The
// zero value of a field is its default (DefaultAutoRules): a profile
// stores only what differs from it, so that a policy approved before auto
// rules existed keeps its fingerprint.
type AutoRules struct {
	Connect AutoValue `json:"connect,omitempty"`
	Read    AutoValue `json:"read,omitempty"`
	Write   AutoValue `json:"write,omitempty"`
	DDL     AutoValue `json:"ddl,omitempty"`
	Unmask  AutoValue `json:"unmask,omitempty"`
}

// DefaultAutoRules is the auto mode of a profile that sets none: connect
// asked once per session, reads auto, writes, schema changes and
// unmasked results asked every time.
var DefaultAutoRules = AutoRules{Connect: AutoAsk, Read: AutoAuto, Write: AutoAsk, DDL: AutoAsk, Unmask: AutoAsk}

// FullAutoRules is the full-auto preset: every action auto.
var FullAutoRules = AutoRules{Connect: AutoAuto, Read: AutoAuto, Write: AutoAuto, DDL: AutoAuto, Unmask: AutoAuto}

func (r *AutoRules) field(a AutoAction) *AutoValue {
	switch a {
	case ActionConnect:
		return &r.Connect
	case ActionRead:
		return &r.Read
	case ActionWrite:
		return &r.Write
	case ActionDDL:
		return &r.DDL
	case ActionUnmask:
		return &r.Unmask
	}
	return nil
}

// Get is the value of action a, its default when r does not set it.
func (r AutoRules) Get(a AutoAction) AutoValue {
	if f := r.field(a); f != nil && *f != "" {
		return *f
	}
	if f := DefaultAutoRules.field(a); f != nil {
		return *f
	}
	return AutoDeny // an unknown action: fail closed
}

// Effective is r with every action set (defaults filled in).
func (r AutoRules) Effective() AutoRules {
	var out AutoRules
	for _, a := range AutoActions {
		*out.field(a) = r.Get(a)
	}
	return out
}

// sparse is r with the defaults left out, nil when every action is its
// default: what a Profile stores.
func (r AutoRules) sparse() *AutoRules {
	var out AutoRules
	set := false
	for _, a := range AutoActions {
		if v := r.Get(a); v != *DefaultAutoRules.field(a) {
			*out.field(a), set = v, true
		}
	}
	if !set {
		return nil
	}
	return &out
}

// Preset names the preset r is, "" for none.
func (r AutoRules) Preset() string {
	switch r.Effective() {
	case FullAutoRules:
		return PresetFullAuto
	case DefaultAutoRules:
		return PresetDefault
	}
	return ""
}

// String is r in one line: "connect ask · read auto · write ask · ddl
// ask · unmask ask", with the preset it is when it is one.
func (r AutoRules) String() string {
	parts := make([]string, 0, len(AutoActions))
	for _, a := range AutoActions {
		parts = append(parts, string(a)+" "+string(r.Get(a)))
	}
	s := strings.Join(parts, " · ")
	if p := r.Preset(); p != "" {
		s += " (" + p + ")"
	}
	return s
}

// AutoRules is the effective auto mode of p.
func (p Profile) AutoRules() AutoRules {
	if p.Auto == nil {
		return DefaultAutoRules
	}
	return p.Auto.Effective()
}

// AutoRuleOf is the action of a statement class (read, write, ddl, admin),
// unmasked or not: an unmasked read is decided by the stricter of read
// and unmask (unmask when they are equal).
func AutoRuleOf(r AutoRules, class Tier, unmask bool) (AutoAction, AutoValue) {
	switch {
	case class >= TierDDL:
		return ActionDDL, r.Get(ActionDDL)
	case class == TierWrite:
		return ActionWrite, r.Get(ActionWrite)
	case unmask && r.Get(ActionUnmask).rank() <= r.Get(ActionRead).rank():
		return ActionUnmask, r.Get(ActionUnmask)
	}
	return ActionRead, r.Get(ActionRead)
}

// rawAuto is the auto key of a profile as written: a preset name
// (`auto = "full-auto"`, Preset), or a table of actions with an optional
// preset that the actions override. buildProfile checks the values.
type rawAuto struct {
	Preset  string `toml:"preset"`
	Connect string `toml:"connect"`
	Read    string `toml:"read"`
	Write   string `toml:"write"`
	DDL     string `toml:"ddl"`
	Unmask  string `toml:"unmask"`
	// bad is what UnmarshalTOML refused, reported by rules with the
	// profile's name (an error from the decoder would lose its text).
	bad error
}

func (r *rawAuto) fields() map[string]*string {
	return map[string]*string{"preset": &r.Preset, "connect": &r.Connect, "read": &r.Read, "write": &r.Write, "ddl": &r.DDL, "unmask": &r.Unmask}
}

// UnmarshalTOML reads `auto = "<preset>"` or an [auto] table of strings;
// an unknown key is refused. Errors name the key, never quote a value.
func (r *rawAuto) UnmarshalTOML(v any) error {
	r.bad = r.decode(v)
	return nil
}

func (r *rawAuto) decode(v any) error {
	switch t := v.(type) {
	case string:
		*r = rawAuto{Preset: t}
		if t == "" {
			return errors.New("auto: unknown preset (empty)")
		}
		return nil
	case map[string]any:
		*r = rawAuto{}
		f := r.fields()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dst, ok := f[k]
			if !ok {
				return fmt.Errorf("auto: unknown key %q (want preset, %s)", safeKey(k), actionNames())
			}
			s, isStr := t[k].(string)
			if !isStr || s == "" {
				if k == "preset" {
					return errors.New("auto.preset: want a string")
				}
				return fmt.Errorf("auto.%s: want auto, ask or deny", k)
			}
			*dst = s
		}
		return nil
	}
	return fmt.Errorf("auto: want a preset (%q) or a table of %s", PresetFullAuto, actionNames())
}

// rules checks r and returns the rules it sets: the preset (the defaults
// without one), then each action set.
func (r rawAuto) rules() (AutoRules, error) {
	if r.bad != nil {
		return AutoRules{}, r.bad
	}
	out := DefaultAutoRules
	switch r.Preset {
	case "":
	case PresetFullAuto:
		out = FullAutoRules
	case PresetDefault:
	default:
		return AutoRules{}, fmt.Errorf("auto: unknown preset (want %q or %q)", PresetFullAuto, PresetDefault)
	}
	for _, a := range AutoActions {
		s := *r.fields()[string(a)]
		if s == "" {
			continue
		}
		v, err := ParseAutoValue(s)
		if err != nil {
			return AutoRules{}, fmt.Errorf("auto.%s: %v", a, err)
		}
		*out.field(a) = v
	}
	return out, nil
}

// rawAutoOf is the config form of rules (nil: the defaults): a preset
// when it is one, else the actions that differ from the defaults.
func rawAutoOf(r *AutoRules) *rawAuto {
	if r == nil || r.sparse() == nil {
		return nil
	}
	if r.Preset() == PresetFullAuto {
		return &rawAuto{Preset: PresetFullAuto}
	}
	sp := r.sparse()
	return &rawAuto{Connect: string(sp.Connect), Read: string(sp.Read), Write: string(sp.Write), DDL: string(sp.DDL), Unmask: string(sp.Unmask)}
}

func actionNames() string {
	n := make([]string, len(AutoActions))
	for i, a := range AutoActions {
		n[i] = string(a)
	}
	return strings.Join(n, ", ")
}

// safeKey is a key fit for an error message: printable ASCII, cut short.
func safeKey(k string) string {
	var b strings.Builder
	for _, c := range k {
		if b.Len() >= 32 {
			b.WriteString("…")
			break
		}
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteRune(c)
	}
	return b.String()
}

// autoDiff lists the changes of the auto rules: a value that moves toward
// auto (deny → ask → auto) loosens.
func autoDiff(a, c AutoRules) []Change {
	var out []Change
	for _, act := range AutoActions {
		o, n := a.Get(act), c.Get(act)
		if o != n {
			out = append(out, Change{Field: "auto." + string(act), Old: string(o), New: string(n), Loosens: n.rank() > o.rank()})
		}
	}
	return out
}

// sparseCopy is a copy of r without its defaults (nil for nil or the
// defaults).
func (r *AutoRules) sparseCopy() *AutoRules {
	if r == nil {
		return nil
	}
	return r.sparse()
}
