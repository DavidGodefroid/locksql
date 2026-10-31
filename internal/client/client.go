// Package client is the secret-free side of locksql: lockkit's client
// (dial, hello, call) with locksql's names and its SQL methods. The CLI
// client commands and the MCP server are built on it.
//
// A call carries no client-side timeout: query.run waits for the human as
// long as the console allows (5 minutes for an approval). The caller's
// context is the only way to abandon a call, and abandoning one closes the
// connection, which the console sees as "client gone".
package client

import (
	"context"

	kclient "github.com/DavidGodefroid/lockkit/client"
	"github.com/DavidGodefroid/lockkit/mcpkit"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// ErrNoConsole means no console listens for the profile.
// Errors that match it are *NoConsoleError values carrying the command the
// human must run.
var ErrNoConsole = kclient.ErrNoConsole

// ErrConsoleClosed means the console closed the connection before
// answering (the session ended, or the console stopped).
var ErrConsoleClosed = kclient.ErrConsoleClosed

// NoConsoleError reports a missing console and how to start it.
type NoConsoleError = kclient.NoConsoleError

// StartCommand is the command that starts the console: `lox up`, for
// every profile and project (a console is started by `lox up` only, so no
// profile or project value is put in it).
func StartCommand(profile, project string) string {
	return kclient.StartCommand(product.P, profile, project)
}

// StartHint is what an agent asks of the user when no console runs; it
// carries no value.
const StartHint = kclient.StartHint

// ShellQuote quotes s for a POSIX shell when it holds anything beyond
// letters, digits and ./_-+:,@%=.
func ShellQuote(s string) string { return kclient.ShellQuote(s) }

// SocketPath is the console socket of profile for the project of cwd.
func SocketPath(cwd, profile string) (string, error) {
	return kclient.SocketPath(product.P, cwd, profile)
}

// Client is one connection to a console. Calls are serialised.
type Client struct {
	*kclient.Client
}

// Dial connects to the console of profile for the project of cwd. It
// returns a *NoConsoleError (matching ErrNoConsole) when none is running.
// The hello handshake happens on the first call, under that call's context.
func Dial(cwd, profile string) (*Client, error) {
	c, err := kclient.Dial(product.P, cwd, profile)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

// Status describes the console session.
func (c *Client) Status(ctx context.Context) (ipc.StatusResult, error) {
	var r ipc.StatusResult
	err := c.Call(ctx, ipc.MethodStatus, nil, &r)
	return r, err
}

// Tables lists the tables of db ("" for the profile's database).
func (c *Client) Tables(ctx context.Context, db string) (ipc.TablesResult, error) {
	var r ipc.TablesResult
	err := c.Call(ctx, ipc.MethodCatalogList, ipc.TablesParams{DB: db}, &r)
	return r, err
}

// Describe describes one table of db.
func (c *Client) Describe(ctx context.Context, db, table string) (engine.TableInfo, error) {
	var r engine.TableInfo
	err := c.Call(ctx, ipc.MethodCatalogDescribe, ipc.DescribeParams{DB: db, Table: table}, &r)
	return r, err
}

// Requester is the agent behind the plan and run requests: from lea's
// environment (mcpkit.RequesterFromEnv), empty outside lea. A plan or
// ticket runs only for the agent that asked for it.
var Requester = mcpkit.RequesterFromEnv

// Plan validates and weighs a statement and returns a one-shot plan.
func (c *Client) Plan(ctx context.Context, p ipc.PlanParams) (ipc.PlanResult, error) {
	var r ipc.PlanResult
	if p.Requester == (ipc.Requester{}) {
		p.Requester = Requester()
	}
	err := c.Call(ctx, ipc.MethodQueryPlan, p, &r)
	return r, err
}

// Run asks the human to approve a plan and returns its result. It waits as
// long as the console does: there is no client-side timeout.
func (c *Client) Run(ctx context.Context, planID string) (ipc.RunResult, error) {
	var r ipc.RunResult
	err := c.Call(ctx, ipc.MethodQueryRun, ipc.RunParams{PlanID: planID, Requester: Requester()}, &r)
	return r, err
}

// RunTicket runs the plan of a ticket decided in lockhub (hub mode).
func (c *Client) RunTicket(ctx context.Context, ticket string) (ipc.RunResult, error) {
	var r ipc.RunResult
	err := c.Call(ctx, ipc.MethodQueryRun, ipc.RunParams{Ticket: ticket, Requester: Requester()}, &r)
	return r, err
}

// PIIList returns the column rules in force.
func (c *Client) PIIList(ctx context.Context) (ipc.PIIListResult, error) {
	var r ipc.PIIListResult
	err := c.Call(ctx, ipc.MethodPIIList, nil, &r)
	return r, err
}

// PIIAdd adds a mask rule "db.table.column" (a tightening, applied at once)
// and returns the rules in force.
func (c *Client) PIIAdd(ctx context.Context, pattern string) (ipc.PIIListResult, error) {
	var r ipc.PIIListResult
	err := c.Call(ctx, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: pattern}, &r)
	return r, err
}

// Request queues a policy change proposal for the human. It never changes
// the policy itself.
func (c *Client) Request(ctx context.Context, change string) (ipc.ChangeResult, error) {
	var r ipc.ChangeResult
	err := c.Call(ctx, ipc.MethodChangeRequest, ipc.ChangeParams{Change: change}, &r)
	return r, err
}

// Logout ends the console session.
func (c *Client) Logout(ctx context.Context) error {
	return c.Call(ctx, ipc.MethodLogout, nil, nil)
}
