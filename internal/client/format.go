package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// This file renders console answers for the CLI. Text output is meant for
// people and agents alike; --json output is the ipc result as is (pretty
// printed), except where a function says otherwise.

// WriteJSON writes v as indented JSON followed by a newline.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ProfileStatus is one line of `locksql status` without a profile: every
// configured profile, with the console status when one runs.
type ProfileStatus struct {
	Profile string            `json:"profile"`
	Running bool              `json:"running"`
	Status  *ipc.StatusResult `json:"status,omitempty"`
	// Start is the command that starts the console, when none runs.
	Start string `json:"start,omitempty"`
	// Error is set when the console could not be asked.
	Error string `json:"error,omitempty"`
}

// Description is a table description with the columns the PII rules mask.
type Description struct {
	engine.TableInfo
	Masked []string `json:"masked"`
}

// MaskedColumns lists the columns of info that the rules mask.
func MaskedColumns(info engine.TableInfo, rules ipc.PIIListResult) []string {
	r := pii.Rules{Mask: rules.Mask, Allow: rules.Allow}
	out := []string{}
	for _, c := range info.Columns {
		if r.Matches(info.DB, info.Table, c.Name) {
			out = append(out, c.Name)
		}
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// FormatStatus writes the console status as aligned "key value" lines.
func FormatStatus(w io.Writer, s ipc.StatusResult) {
	kv := func(k, v string) { fmt.Fprintf(w, "%-13s%s\n", k, clean(v)) }
	kv("profile", s.Profile)
	kv("engine", s.Engine)
	kv("host", s.Host)
	kv("tier", s.Tier)
	kv("production", yesNo(s.Production))
	kv("auto-approve", yesNo(s.SkipPermissions))
	kv("unmask", allowedOff(s.AllowUnmask))
	kv("databases", strings.Join(s.Databases, ", "))
	kv("limits", FormatLimits(s.Limits))
	kv("session", fmt.Sprintf("idle timeout %s · ends in %s",
		time.Duration(s.IdleTimeoutInS)*time.Second, time.Duration(s.SessionEndsInS)*time.Second))
}

// FormatLimits renders limits on one line; 0 means unlimited.
func FormatLimits(l config.Limits) string {
	n := func(v int64) string {
		if v <= 0 {
			return "unlimited"
		}
		return Group(v)
	}
	timeout := "none"
	if l.StatementTimeout > 0 {
		timeout = l.StatementTimeout.String()
	}
	return fmt.Sprintf("timeout %s · warn %s rows · refuse %s rows · max_rows %s · max_cell_chars %s · max_output_bytes %s",
		timeout, n(l.ExplainRowsWarn), n(l.ExplainRowsRefuse), n(int64(l.MaxRows)), n(int64(l.MaxCellChars)), n(int64(l.MaxOutputBytes)))
}

// Group writes n with a space every three digits ("1 000 000").
func Group(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// FormatProfiles writes one block per profile: the status of a running
// console, or how to start it.
func FormatProfiles(w io.Writer, list []ProfileStatus) {
	for i, p := range list {
		if i > 0 {
			fmt.Fprintln(w)
		}
		switch {
		case p.Running && p.Status != nil:
			fmt.Fprintf(w, "%s: console running\n", clean(p.Profile))
			FormatStatus(w, *p.Status)
		case p.Error != "":
			fmt.Fprintf(w, "%s: console running, status failed: %s\n", clean(p.Profile), clean(p.Error))
		default:
			fmt.Fprintf(w, "%s: no console (start: %s)\n", clean(p.Profile), p.Start)
		}
	}
}

// FormatTables writes one table name per line.
func FormatTables(w io.Writer, t ipc.TablesResult) {
	for _, name := range t.Tables {
		fmt.Fprintln(w, clean(name))
	}
}

// FormatDescribe writes a header, the columns as TSV (column, type, null,
// key, default, pii) and the indexes.
func FormatDescribe(w io.Writer, d Description) {
	rows := "~? rows"
	if d.EstRows >= 0 {
		rows = "~" + Group(d.EstRows) + " rows"
	}
	name := d.Table
	if d.DB != "" {
		name = d.DB + "." + d.Table
	}
	fmt.Fprintf(w, "%s  %s\n", clean(name), rows)
	fmt.Fprintln(w, "column\ttype\tnull\tkey\tdefault\tpii")
	for _, c := range d.Columns {
		key := ""
		if c.PrimaryKey {
			key = "PK"
		}
		def := ""
		if c.Default != nil {
			def = *c.Default
		}
		masked := ""
		if slices.Contains(d.Masked, c.Name) {
			masked = "masked"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", clean(c.Name), clean(c.Type), yesNo(c.Nullable), key, clean(def), masked)
	}
	if len(d.Indexes) > 0 {
		fmt.Fprintln(w, "indexes:")
		for _, ix := range d.Indexes {
			cols := make([]string, len(ix.Columns))
			for i, c := range ix.Columns {
				cols[i] = clean(c)
			}
			kind := ""
			switch {
			case ix.Primary:
				kind = " primary"
			case ix.Unique:
				kind = " unique"
			}
			fmt.Fprintf(w, "  %s (%s)%s\n", clean(ix.Name), strings.Join(cols, ", "), kind)
		}
	}
}

// FormatPlan writes a plan and the command that runs it.
func FormatPlan(w io.Writer, p ipc.PlanResult) {
	kv := func(k, v string) { fmt.Fprintf(w, "%-9s%s\n", k, v) }
	kv("plan_id", p.PlanID)
	kv("profile", clean(p.Profile))
	kv("host", clean(p.Host))
	kv("db", clean(p.DB))
	kv("class", strings.ToUpper(p.Class))
	kv("verdict", p.Verdict)
	kv("explain", clean(p.Summary))
	for _, r := range p.Reasons {
		kv("reason", clean(r))
	}
	if p.Unmask {
		kv("unmask", "yes: the human must approve unmasked output")
	}
	kv("sql", clean(p.SQL))
	fmt.Fprintf(w, "next: locksql run --profile %s %s  (one-shot, valid 10 min; the human approves it in the console)\n",
		p.Profile, p.PlanID)
}

// FormatRun writes the console's TSV rendering of a result.
func FormatRun(w io.Writer, r ipc.RunResult) {
	text := r.Text
	if text == "" && len(r.Columns) == 0 {
		text = fmt.Sprintf("(%d rows affected)\n", r.Affected)
	}
	io.WriteString(w, text)
	if text != "" && !strings.HasSuffix(text, "\n") {
		fmt.Fprintln(w)
	}
}

// FormatPII writes the rules as "mask<TAB>pattern" and "allow<TAB>pattern".
func FormatPII(w io.Writer, r ipc.PIIListResult) {
	if len(r.Mask) == 0 && len(r.Allow) == 0 {
		fmt.Fprintln(w, "(no rules)")
		return
	}
	for _, m := range r.Mask {
		fmt.Fprintf(w, "mask\t%s\n", clean(m))
	}
	for _, a := range r.Allow {
		fmt.Fprintf(w, "allow\t%s\n", clean(a))
	}
}

// ErrorInfo is the --json form of a failed command.
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
	// Start is the command that starts the console (kind no_console).
	Start string `json:"start,omitempty"`
}

// DescribeError classifies err for output: kind is one of no_console,
// refused, denied, timeout, no_such_plan, connection_lost, policy_pending,
// invalid_params, console_closed, cancelled or error.
func DescribeError(err error) ErrorInfo {
	var nc *NoConsoleError
	if errors.As(err, &nc) {
		return ErrorInfo{Kind: "no_console", Message: nc.Error(), Start: nc.Command()}
	}
	var re *ipc.RPCError
	if errors.As(err, &re) {
		kinds := map[int]string{
			ipc.CodeRefused:       "refused",
			ipc.CodeDenied:        "denied",
			ipc.CodeTimeout:       "timeout",
			ipc.CodeNoSuchPlan:    "no_such_plan",
			ipc.CodeConnLost:      "connection_lost",
			ipc.CodePolicyPending: "policy_pending",
			ipc.CodeInvalidParams: "invalid_params",
		}
		kind, ok := kinds[re.Code]
		if !ok {
			kind = "error"
		}
		return ErrorInfo{Kind: kind, Code: re.Code, Message: re.Message}
	}
	switch {
	case errors.Is(err, ErrConsoleClosed):
		return ErrorInfo{Kind: "console_closed", Message: err.Error()}
	case errors.Is(err, context.Canceled):
		return ErrorInfo{Kind: "cancelled", Message: "cancelled"}
	}
	return ErrorInfo{Kind: "error", Message: err.Error()}
}

// ErrorText is the one-line text form of err: "<kind>: <message>" for
// console errors, the message alone otherwise.
func ErrorText(err error) string {
	e := DescribeError(err)
	switch e.Kind {
	case "no_console", "error", "cancelled", "console_closed":
		return e.Message
	}
	label := strings.ReplaceAll(e.Kind, "_", " ")
	if strings.HasPrefix(strings.ToLower(e.Message), label) {
		return e.Message
	}
	return label + ": " + e.Message
}

// clean escapes control and format characters so that a crafted name or
// value cannot break the line layout or the terminal.
func clean(s string) string {
	ok := true
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			ok = false
			break
		}
	}
	if ok {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`�`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x100 && unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func allowedOff(b bool) string {
	if b {
		return "allowed (each query approved in the console)"
	}
	return "off (console started without --allow-unmask)"
}
