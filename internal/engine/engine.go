// Package engine defines the database engine interface the console drives,
// and the engine-independent types it returns: catalog descriptions, result
// sets and normalised query plans.
//
// A Session is owned by the console. It never receives SQL from an agent
// without the classifier having seen it first, and its catalog methods only
// run SQL built by the engine itself.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Flavor is the concrete server family behind a session.
type Flavor string

// Flavors, matching the config engine names.
const (
	FlavorMariaDB  Flavor = "mariadb"
	FlavorMySQL    Flavor = "mysql"
	FlavorPostgres Flavor = "postgres"
	FlavorSQLite   Flavor = "sqlite"
)

// ErrConnLost reports that the database connection is gone. The console
// reconnects (asking for the secret again if needed) instead of retrying.
var ErrConnLost = errors.New("connection lost")

// ColumnInfo is one column of a table, as used for PII detection.
type ColumnInfo struct {
	DB     string `json:"db"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Type   string `json:"type"`
	// View is set for a column of a view (or a materialized view or a
	// foreign table): its base columns are unknown.
	View bool `json:"view,omitempty"`
}

// ColumnDesc describes one column for catalog.describe.
type ColumnDesc struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key,omitempty"`
	// Default is the column default as the catalog spells it, nil when none.
	Default *string `json:"default,omitempty"`
}

// IndexDesc describes one index for catalog.describe.
type IndexDesc struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique,omitempty"`
	Primary bool     `json:"primary,omitempty"`
}

// TableInfo is the catalog description of one table or view.
type TableInfo struct {
	DB      string       `json:"db"`
	Table   string       `json:"table"`
	Columns []ColumnDesc `json:"columns"`
	Indexes []IndexDesc  `json:"indexes,omitempty"`
	// EstRows is the engine's row estimate, or -1 when it has none.
	EstRows int64 `json:"est_rows"`
}

// ResultColumn is one result column: its label, and the base column it
// comes from when the engine reports it. The origin fields are all empty
// when the origin is unknown or not trustworthy.
type ResultColumn struct {
	Label        string `json:"label"`
	OriginDB     string `json:"origin_db,omitempty"`
	OriginTable  string `json:"origin_table,omitempty"`
	OriginColumn string `json:"origin_column,omitempty"`
}

// HasOrigin reports whether the column carries an origin.
func (c ResultColumn) HasOrigin() bool { return c.OriginTable != "" && c.OriginColumn != "" }

// Result is the outcome of Run. Rows hold driver values (nil, int64,
// float64, string, []byte, time.Time, ...); rendering and masking happen
// later, in the console.
type Result struct {
	Columns []ResultColumn `json:"columns"`
	Rows    [][]any        `json:"rows"`
	// Truncated is set when the statement produced more than maxRows rows.
	Truncated bool `json:"truncated"`
	// Affected is the number of rows changed by a write-class statement.
	Affected int64 `json:"affected"`
}

// Access methods of a PlanNode.
const (
	AccessFull    = "full"    // full table scan
	AccessIndex   = "index"   // full scan of an index
	AccessRange   = "range"   // index or key range
	AccessLookup  = "lookup"  // equality lookup on a key or index
	AccessUnknown = "unknown" // the engine did not say
)

// PlanNode is one node of a normalised plan.
//
// A node with a Table is a table access. A node without one is a group: the
// plan root, a subquery, a derived table, a compound arm and so on, with
// Detail naming it. The table children of a group form, in order, one
// nested-loop pipeline: the rows examined are the product of their EstRows.
// The group children are subqueries and materialisations: their cost adds
// to the group, multiplied by the outer rows when Correlated.
type PlanNode struct {
	Table string `json:"table,omitempty"`
	// Access is one of the Access* constants for a table node, "" for a group.
	Access string `json:"access,omitempty"`
	// EstRows is the engine's estimate of rows examined per execution of the
	// node, or -1 when the engine has none.
	EstRows int64 `json:"est_rows"`
	// Sort and Temp report a sort or a temporary table. On a group they apply
	// to the output of the group's pipeline.
	Sort bool `json:"sort,omitempty"`
	Temp bool `json:"temp,omitempty"`
	// Correlated marks a subquery evaluated once per outer row.
	Correlated bool `json:"correlated,omitempty"`
	// NoJoinCond marks a table joined without a usable join condition, so
	// that every outer row reads all of it.
	NoJoinCond bool `json:"no_join_cond,omitempty"`
	// Detail is the engine's own label for the node, for display only.
	Detail   string     `json:"detail,omitempty"`
	Children []PlanNode `json:"children,omitempty"`
}

// Plan is a normalised plan plus the engine's raw plan, kept for the audit
// log and for debugging.
type Plan struct {
	Root PlanNode `json:"root"`
	// Cost is the engine's total cost estimate for the statement, in its
	// own units (PostgreSQL Total Cost, MySQL query_cost, MariaDB cost), or
	// -1 when the engine gives none.
	Cost float64         `json:"cost"`
	Raw  json.RawMessage `json:"raw"`
}

// Session is one open connection with its policy-relevant settings applied
// (read-only mode for tier read, timeouts).
type Session interface {
	ServerVersion() string
	Flavor() Flavor
	// OriginColumns reports whether Run fills in result column origins.
	OriginColumns() bool
	// ExtraPrivileges lists the warnings about what the connection could do
	// beyond the profile tier.
	ExtraPrivileges(ctx context.Context, tier config.Tier) ([]string, error)
	Databases(ctx context.Context) ([]string, error)
	Tables(ctx context.Context, db string) ([]string, error)
	Describe(ctx context.Context, db, table string) (TableInfo, error)
	Columns(ctx context.Context, db string) ([]ColumnInfo, error)
	Explain(ctx context.Context, db, sql string) (Plan, error)
	// Run executes one classified statement. Write classes run in a
	// transaction and report Affected. Rows are capped at maxRows (no cap
	// when maxRows <= 0) and Truncated says whether more were available.
	Run(ctx context.Context, db string, st sqlclass.Statement, maxRows int) (Result, error)
	Ping(ctx context.Context) error
	Close() error
}

// Noticer is implemented by sessions with something the human must know
// about the connection itself, such as a fallback to no encryption. The
// console prints and audits each notice after connecting.
type Noticer interface {
	Notices() []string
}

// DialFunc opens the network connection to the database server. nil is a
// direct TCP or Unix socket connection.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Engine opens sessions for one engine name. secret is the password, or nil
// when the engine needs none; it is never stored past Connect. dial, when not
// nil, opens every network connection of the session (main, control and
// cancel connections).
type Engine interface {
	Connect(ctx context.Context, p config.Profile, secret []byte, dial DialFunc) (Session, error)
}
