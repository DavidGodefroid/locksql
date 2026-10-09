package ipc

import "github.com/DavidGodefroid/locksql/internal/config"

// Methods, spec §7. None of them loosens policy: change.request only queues
// a proposal that the console shows to the human.
const (
	MethodHello           = "hello"
	MethodStatus          = "status"
	MethodCatalogList     = "catalog.list"
	MethodCatalogDescribe = "catalog.describe"
	MethodQueryPlan       = "query.plan"
	MethodQueryRun        = "query.run"
	MethodPIIList         = "pii.list"
	MethodPIIAdd          = "pii.add"
	MethodChangeRequest   = "change.request"
	MethodLogout          = "logout"
)

// Methods lists every method name.
func Methods() []string {
	return []string{
		MethodHello, MethodStatus, MethodCatalogList, MethodCatalogDescribe, MethodQueryPlan,
		MethodQueryRun, MethodPIIList, MethodPIIAdd, MethodChangeRequest, MethodLogout,
	}
}

// Error codes. The -320xx range is reserved by JSON-RPC for implementation
// errors; the standard codes are kept for protocol faults.
const (
	CodeRefused       = -32001 // classifier, tier or weight check refused
	CodeDenied        = -32002 // the human denied
	CodeTimeout       = -32003 // no answer within the approval timeout
	CodeNoSuchPlan    = -32004 // unknown, used or expired plan id
	CodeConnLost      = -32005 // the database connection was lost
	CodePolicyPending = -32006 // a policy change awaits the human

	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// HelloParams opens a session; Client is a free-form name and version.
type HelloParams struct {
	ProtocolMajor int    `json:"protocol_major"`
	Client        string `json:"client,omitempty"`
}

// HelloResult answers hello.
type HelloResult struct {
	ProtocolMajor  int    `json:"protocol_major"`
	ConsoleVersion string `json:"console_version,omitempty"`
	Profile        string `json:"profile"`
}

// PlanParams asks for a plan (classification, EXPLAIN, weight, approval).
type PlanParams struct {
	DB     string `json:"db"`
	SQL    string `json:"sql"`
	Unmask bool   `json:"unmask,omitempty"`
}

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
	// Values are the placeholder names the human typed in this console
	// session: '${name}' reuses a value without a prompt.
	Values []string `json:"values,omitempty"`
}

// RunParams runs an approved plan.
type RunParams struct {
	PlanID string `json:"plan_id"`
}

// RunResult is a capped, masked result. Text is the rendered TSV.
type RunResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
	Affected  int64    `json:"affected,omitempty"`
	// DurationMS is no longer filled: timings stay on the console.
	DurationMS int64  `json:"duration_ms,omitempty"`
	Text       string `json:"text,omitempty"`
}

// StatusResult describes the console session.
type StatusResult struct {
	Profile         string        `json:"profile"`
	Engine          string        `json:"engine"`
	Host            string        `json:"host"`
	HostConfirmed   bool          `json:"host_confirmed"`
	Production      bool          `json:"production"`
	SkipPermissions bool          `json:"skip_permissions"`
	AllowUnmask     bool          `json:"allow_unmask"`
	ShowResults     bool          `json:"show_results"`
	Tier            string        `json:"tier"`
	Databases       []string      `json:"databases"`
	Limits          config.Limits `json:"limits"`
	IdleTimeoutInS  int           `json:"idle_timeout_in_s"`
	SessionEndsInS  int           `json:"session_ends_in_s"`
	// Health is what the console found at start-up, for locksql doctor.
	Health *Health `json:"health,omitempty"`
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

// PIIListResult answers pii.list with the column rules.
type PIIListResult struct {
	Mask  []string `json:"mask"`
	Allow []string `json:"allow"`
}

// PIIAddParams proposes a mask pattern "db.table.column".
type PIIAddParams struct {
	Pattern string `json:"pattern"`
}

// ChangeParams queues a policy change proposal for the human.
type ChangeParams struct {
	Change string `json:"change"`
}

// ChangeResult answers change.request.
type ChangeResult struct {
	Queued bool `json:"queued"`
}
