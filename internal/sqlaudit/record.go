// Package sqlaudit is locksql's audit record on lockkit's audit log: one
// JSONL record per event, never secrets and never row data. The record
// keeps locksql 0.8's fields in their order, so a line written today is
// byte-identical to one written before lockkit for the same event.
package sqlaudit

import (
	"github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/locksql/internal/product"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// Log is lockkit's audit log.
type Log = audit.Log

// Events: lockkit's console events.
const (
	EventLogin     = audit.EventLogin
	EventPolicy    = audit.EventPolicy
	EventRefused   = audit.EventRefused
	EventApproved  = audit.EventApproved
	EventDenied    = audit.EventDenied
	EventTimeout   = audit.EventTimeout
	EventAbandoned = audit.EventAbandoned
	EventAuto      = audit.EventAuto
	EventRun       = audit.EventRun
	EventCatalog   = audit.EventCatalog
	EventMode      = audit.EventMode
	EventResults   = audit.EventResults
	EventUnmask    = audit.EventUnmask
	EventLogout    = audit.EventLogout
	// EventPending is a request handed to lockhub (hub mode): its ticket
	// is in the reason.
	EventPending = "pending"
	// EventConfigImport is a `locksql config import`, applied or refused.
	EventConfigImport = "config_import"
)

// Open opens locksql's audit log: <stateDir>/locksql/audit.log.
func Open(stateDir string) (*Log, error) { return audit.Open(product.P, stateDir) }

// Record is one audit event. It has no field able to hold a password or row
// data: Error must already be sanitised by the caller.
type Record struct {
	Event      string `json:"event"`
	Profile    string `json:"profile,omitempty"`
	Engine     string `json:"engine,omitempty"`
	Host       string `json:"host,omitempty"`
	DB         string `json:"db,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	SSHHost    string `json:"ssh_host,omitempty"`
	SSHHostKey string `json:"ssh_host_key,omitempty"`
	Class      string `json:"class,omitempty"`
	SQL        string `json:"sql,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Error      string `json:"error,omitempty"`
	// Code is the refusal code of a refused record (package refusal), and
	// Span where the refusal points in the statement, when known.
	Code       string        `json:"code,omitempty"`
	Span       *refusal.Span `json:"span,omitempty"`
	Rows       int64         `json:"rows,omitempty"`
	Affected   int64         `json:"affected,omitempty"`
	DurationMS int64         `json:"duration_ms,omitempty"`
	Truncated  bool          `json:"truncated,omitempty"`
	Unmasked   bool          `json:"unmasked,omitempty"`
	Warnings   []string      `json:"warnings,omitempty"`
	// Intent is the agent's one-line reason for a plan (untrusted text,
	// like SQL), kept on every record of that plan.
	Intent string `json:"intent,omitempty"`
	// Reason is the human's reason for a denial, escaped.
	Reason string `json:"reason,omitempty"`
	// Approval is how the human approved: "session" (typed in a login
	// session of the console account), "desktop+typed" (typed in a desktop
	// window, level 1) or "desktop+fingerprint" (level 2).
	Approval string `json:"approval,omitempty"`
	// The client behind a request, from the kernel's peer credentials:
	// set on the records of client requests only. PeerUID is nil when
	// unknown (uid 0 is root); PeerUser is the account name when it
	// resolves. The process name is the agent's choice and is not kept.
	PeerUID  *int   `json:"peer_uid,omitempty"`
	PeerPID  int    `json:"peer_pid,omitempty"`
	PeerUser string `json:"peer_user,omitempty"`
	// Scope, Profiles and AllowLoosen describe a config import: the scope
	// written (user or project), the profiles it changes and whether
	// loosening was allowed. Never a value.
	Scope       string   `json:"scope,omitempty"`
	Profiles    []string `json:"profiles,omitempty"`
	AllowLoosen bool     `json:"allow_loosen,omitempty"`
}

// AuditEvent implements lockkit's audit.Record.
func (r Record) AuditEvent() string { return r.Event }
