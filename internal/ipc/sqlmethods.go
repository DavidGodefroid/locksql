// Package ipc is locksql's console protocol: lockkit's transport and
// methods (package lockkit/ipc, re-exported here under the same names)
// plus the SQL methods and their types.
package ipc

import (
	"net"

	kipc "github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// lockkit's transport.
type (
	Request  = kipc.Request
	Response = kipc.Response
	RPCError = kipc.RPCError
	Cred     = kipc.Cred
)

// ProtocolMajor is exchanged in the hello handshake.
const ProtocolMajor = kipc.ProtocolMajor

// MaxMessage is the largest message, excluding the newline, in bytes.
const MaxMessage = kipc.MaxMessage

var (
	ErrTooLarge       = kipc.ErrTooLarge
	ErrAlreadyRunning = kipc.ErrAlreadyRunning

	Compatible       = kipc.Compatible
	WriteMsg         = kipc.WriteMsg
	ReadMsg          = kipc.ReadMsg
	Listen           = kipc.Listen
	PeerCred         = kipc.PeerCred
	PeerAllowed      = kipc.PeerAllowed
	SharedSocketPath = kipc.SharedSocketPath
)

// RuntimeDirEnv overrides the runtime dir of locksql's sockets
// (LOCKSQL_RUNTIME_DIR).
var RuntimeDirEnv = product.P.RuntimeDirEnv()

// SocketPath is locksql's console socket of a project and profile.
func SocketPath(projectHash, profile string) (string, error) {
	return kipc.SocketPath(product.P, projectHash, profile)
}

// ListenShared opens locksql's console socket in the shared directory.
func ListenShared(path string, gid int) (net.Listener, error) {
	return kipc.ListenShared(product.P, path, gid)
}

// Methods, spec §7. None of them loosens policy: change.request only queues
// a proposal that the console shows to the human.
const (
	MethodHello           = kipc.MethodHello
	MethodStatus          = kipc.MethodStatus
	MethodCatalogList     = "catalog.list"
	MethodCatalogDescribe = "catalog.describe"
	MethodQueryPlan       = "query.plan"
	MethodQueryRun        = "query.run"
	// MethodGrant asks for a grant (one human decision for a bounded read
	// scope), or activates the decided one (GrantParams.Ticket). Its name
	// does not read as an approval: nothing a client sends approves.
	MethodGrant         = "scope.request"
	MethodPIIList       = kipc.MethodPIIList
	MethodPIIAdd        = kipc.MethodPIIAdd
	MethodChangeRequest = kipc.MethodChangeRequest
	MethodLogout        = kipc.MethodLogout
)

// Methods lists every method name.
func Methods() []string {
	return []string{
		MethodHello, MethodStatus, MethodCatalogList, MethodCatalogDescribe, MethodQueryPlan,
		MethodQueryRun, MethodGrant, MethodPIIList, MethodPIIAdd, MethodChangeRequest, MethodLogout,
	}
}

// Error codes (lockkit's).
const (
	CodeRefused       = kipc.CodeRefused
	CodeDenied        = kipc.CodeDenied
	CodeTimeout       = kipc.CodeTimeout
	CodeNoSuchPlan    = kipc.CodeNoSuchPlan
	CodeConnLost      = kipc.CodeConnLost
	CodePolicyPending = kipc.CodePolicyPending
	// CodeWrongRequester: a plan or ticket presented by another agent than
	// the one that made it (Requester.Token).
	CodeWrongRequester = kipc.CodeWrongRequester
	// CodeWithdrawn: a hub ticket run by a console that now runs without
	// its hub (rollback of hub mode): plan again.
	CodeWithdrawn = kipc.CodeWithdrawn

	CodeParseError     = kipc.CodeParseError
	CodeInvalidRequest = kipc.CodeInvalidRequest
	CodeMethodNotFound = kipc.CodeMethodNotFound
	CodeInvalidParams  = kipc.CodeInvalidParams
	CodeInternal       = kipc.CodeInternal
)

// lockkit's method types.
type (
	HelloParams   = kipc.HelloParams
	HelloResult   = kipc.HelloResult
	PIIListResult = kipc.PIIListResult
	PIIAddParams  = kipc.PIIAddParams
	ChangeParams  = kipc.ChangeParams
	ChangeResult  = kipc.ChangeResult
	// Requester is the agent behind a plan or run request: its lea name and
	// the hash of its lea token (mcpkit.RequesterFromEnv). A plan or ticket
	// runs only for the token that asked for it. Agents of one account can
	// read each other's token: it catches mistakes, it is no security
	// boundary.
	Requester = kipc.Requester
)

// PlanParams asks for a plan (classification, EXPLAIN, weight, approval).
type PlanParams struct {
	DB     string `json:"db"`
	SQL    string `json:"sql"`
	Unmask bool   `json:"unmask,omitempty"`
	// Intent is one line from the agent saying why the query is needed,
	// shown to the human on the approval screen and audited. It is
	// untrusted text of at most MaxIntent bytes.
	Intent string `json:"intent,omitempty"`
	// Requester is the agent asking (the plan runs only for its token).
	Requester Requester `json:"requester,omitzero"`
}

// MaxIntent bounds PlanParams.Intent.
const MaxIntent = 200

// PlanResult is an approved, one-shot plan.
type PlanResult struct {
	PlanID  string   `json:"plan_id"`
	Profile string   `json:"profile"`
	Host    string   `json:"host"`
	DB      string   `json:"db"`
	SQL     string   `json:"sql"`
	Class   string   `json:"class"`
	Verdict string   `json:"verdict"`
	Summary string   `json:"summary"`
	Reasons []string `json:"reasons,omitempty"`
	Unmask  bool     `json:"unmask,omitempty"`
	// PlanHash binds the plan to what it resolves to: the statement, the
	// policy and, on PostgreSQL, the definitions of the objects it uses
	// ("sha256:…"). The run refuses with E_STALE once it no longer matches.
	PlanHash string `json:"plan_hash,omitempty"`
}

// RunParams runs an approved plan.
type RunParams struct {
	PlanID string `json:"plan_id,omitempty"`
	// Ticket runs the plan of a ticket decided in lockhub (hub mode), in
	// place of PlanID.
	Ticket string `json:"ticket,omitempty"`
	// Requester is the agent asking: the token that planned it.
	Requester Requester `json:"requester,omitzero"`
}

// RunResult is a capped, masked result. Text is the rendered TSV.
type RunResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
	Affected  int64    `json:"affected,omitempty"`
	// CutCells counts the cells whose value was cut (it ends with "…"):
	// longer than max_cell_chars, or than the engine's per-cell cap.
	CutCells int `json:"cut_cells,omitempty"`
	// DurationMS is no longer filled: timings stay on the console.
	DurationMS int64  `json:"duration_ms,omitempty"`
	Text       string `json:"text,omitempty"`
	// Status is "pending" (hub mode: the human decides in lockhub; run
	// Ticket once decided) or "stale" (the plan of StaleTicket changed:
	// Ticket is the new one); "" for a result.
	Status      string `json:"status,omitempty"`
	Ticket      string `json:"ticket,omitempty"`
	Lock        string `json:"lock,omitempty"`
	Instance    string `json:"instance,omitempty"`
	StaleTicket string `json:"stale_ticket,omitempty"`
	// Grant is the grant the run ran under, without a ticket, and
	// GrantLeft what is left of its budget.
	Grant     string       `json:"grant,omitempty"`
	GrantLeft *GrantBudget `json:"grant_left,omitempty"`
}

// StatusResult describes the console session.
type StatusResult struct {
	Profile       string `json:"profile"`
	Engine        string `json:"engine"`
	Host          string `json:"host"`
	HostConfirmed bool   `json:"host_confirmed"`
	Production    bool   `json:"production"`
	// AutoApprove is always false: lockhub decides every statement. Kept
	// for the clients that read it.
	AutoApprove bool `json:"auto_approve"`
	// Auto is the profile's auto mode in force, every action set
	// (locksql#185): what lox run's auto mode may approve without a
	// question (auto), must ask (ask) or never gets (deny).
	Auto           config.AutoRules `json:"auto"`
	AllowUnmask    bool             `json:"allow_unmask"`
	ShowResults    bool             `json:"show_results"`
	Tier           string           `json:"tier"`
	Databases      []string         `json:"databases"`
	Limits         config.Limits    `json:"limits"`
	IdleTimeoutInS int              `json:"idle_timeout_in_s"`
	SessionEndsInS int              `json:"session_ends_in_s"`
	// Health is what the console found at start-up, for locksql doctor.
	Health *Health `json:"health,omitempty"`
	// Grants are the active grants, oldest first.
	Grants []GrantInfo `json:"grants,omitempty"`
}

// GrantParams asks for a grant: one human decision covering reads of
// Tables of DB for Duration, within a budget of statements, rows and
// bytes returned. A value of 0 (or "") asks for the profile's limit; a
// value above it is clamped to it. With Ticket, the decided grant of that
// ticket is activated instead, and the other fields are ignored.
type GrantParams struct {
	DB         string   `json:"db,omitempty"`
	Tables     []string `json:"tables,omitempty"`
	Duration   string   `json:"duration,omitempty"`
	Statements int64    `json:"statements,omitempty"`
	Rows       int64    `json:"rows,omitempty"`
	Bytes      int64    `json:"bytes,omitempty"`
	// Intent is one line from the agent saying why, shown to the human
	// and audited (untrusted text of at most MaxIntent bytes).
	Intent string `json:"intent,omitempty"`
	Ticket string `json:"ticket,omitempty"`
	// Requester is the agent asking: only its token may activate the
	// grant and run under it.
	Requester Requester `json:"requester,omitzero"`
}

// GrantBudget is a read budget: statements run, rows and bytes returned.
type GrantBudget struct {
	Statements int64 `json:"statements"`
	Rows       int64 `json:"rows"`
	Bytes      int64 `json:"bytes"`
}

// GrantInfo is an active grant: its scope, its budget and what is left.
type GrantInfo struct {
	ID         string      `json:"id"`
	DB         string      `json:"db"`
	Tables     []string    `json:"tables"`
	Duration   string      `json:"duration"`
	ExpiresInS int         `json:"expires_in_s"`
	Budget     GrantBudget `json:"budget"`
	Remaining  GrantBudget `json:"remaining"`
	// Agent is the agent that asked for it, as the console names it.
	Agent string `json:"agent,omitempty"`
}

// GrantResult answers scope.request: pending with the ticket the human
// decides in lockhub, or active with the grant.
type GrantResult struct {
	Status   string     `json:"status"`
	Ticket   string     `json:"ticket,omitempty"`
	Lock     string     `json:"lock,omitempty"`
	Instance string     `json:"instance,omitempty"`
	Grant    *GrantInfo `json:"grant,omitempty"`
}

// Health is the console's own diagnosis of its setup.
type Health struct {
	// Separated is set when the console runs as a dedicated account,
	// apart from the agent (sysconf).
	Separated bool   `json:"separated"`
	Display   string `json:"display"`
	// Privileges are the privilege audit's findings: what the database
	// account can do beyond the profile tier.
	Privileges []string `json:"privileges"`
	// ExplainOK reports that EXPLAIN works on the server.
	ExplainOK bool `json:"explain_ok"`
	// ReadOnly reports that the session is read-only on the server.
	ReadOnly bool `json:"read_only"`
}

// TablesParams lists the tables of a database (catalog.list).
type TablesParams struct {
	DB string `json:"db"`
}

// TablesResult answers catalog.list.
type TablesResult struct {
	DB     string   `json:"db"`
	Tables []string `json:"tables"`
}

// DescribeParams describes one table (catalog.describe); the result is an
// engine.TableInfo.
type DescribeParams struct {
	DB    string `json:"db"`
	Table string `json:"table"`
}
