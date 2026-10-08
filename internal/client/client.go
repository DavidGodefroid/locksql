// Package client is the secret-free side of locksql: it dials the console
// socket of a project and profile and calls the console's JSON-RPC methods.
// The CLI client commands and the MCP server are built on it.
//
// A call carries no client-side timeout: query.run waits for the human as
// long as the console allows (5 minutes for an approval). The caller's
// context is the only way to abandon a call, and abandoning one closes the
// connection, which the console sees as "client gone".
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sysconf"
)

// ErrNoConsole means no console listens for the profile.
// Errors that match it are *NoConsoleError values carrying the command the
// human must run.
var ErrNoConsole = errors.New("no console is running")

// ErrConsoleClosed means the console closed the connection before
// answering (the session ended, or the console stopped).
var ErrConsoleClosed = errors.New("the console closed the connection")

// NoConsoleError reports a missing console and how to start it.
type NoConsoleError struct {
	Profile string
	Socket  string
	Err     error
}

func (e *NoConsoleError) Error() string {
	return fmt.Sprintf("no locksql console is running for profile %s: ask the user to run `locksql` (or the exact command below) in a separate terminal:\n  %s",
		e.Profile, StartCommand(e.Profile))
}

// Is makes errors.Is(err, ErrNoConsole) true.
func (e *NoConsoleError) Is(target error) bool { return target == ErrNoConsole }

func (e *NoConsoleError) Unwrap() error { return e.Err }

// StartCommand is the exact command that starts the console for profile.
func StartCommand(profile string) string { return "locksql console --profile " + profile }

// SocketPath is the console socket of profile for the project of cwd. The
// console computes the same path: in the shared socket directory when the
// machine separates the console from the agent (sysconf), in the user's
// runtime directory otherwise.
func SocketPath(cwd, profile string) (string, error) {
	sys, err := sysconf.Load()
	if err != nil {
		return "", err
	}
	if sys != nil {
		return ipc.SharedSocketPath(sys.SocketDir, config.ProjectKey(cwd), profile)
	}
	return ipc.SocketPath(config.ProjectKey(cwd), profile)
}

// dialUnix opens the socket; tests replace it to watch the connection.
var dialUnix = func(path string) (net.Conn, error) { return net.Dial("unix", path) }

// Client is one connection to a console. Calls are serialised.
type Client struct {
	// Name identifies the client in the hello handshake ("locksql" when
	// empty).
	Name string
	// ConsoleVersion is the console's version, known after the first call.
	ConsoleVersion string

	profile string
	conn    net.Conn
	r       *bufio.Reader

	mu     sync.Mutex
	nextID int64
	hello  bool
	broken error
	// lastDeadline records the deadline of the last call's context, nil
	// when it had none (tests check that query.run carries none).
	lastDeadline *time.Time
}

// Dial connects to the console of profile for the project of cwd. It
// returns a *NoConsoleError (matching ErrNoConsole) when none is running.
// The hello handshake happens on the first call, under that call's context.
func Dial(cwd, profile string) (*Client, error) {
	path, err := SocketPath(cwd, profile)
	if err != nil {
		return nil, err
	}
	conn, err := dialUnix(path)
	if err != nil {
		if noListener(err) {
			return nil, &NoConsoleError{Profile: profile, Socket: path, Err: err}
		}
		return nil, fmt.Errorf("client: connecting to the console: %w", err)
	}
	if err := checkConsole(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{profile: profile, conn: conn, r: bufio.NewReader(conn)}, nil
}

// checkConsole verifies, in a separated setup, that the process behind the
// socket runs as the console account: the kernel reports the server's
// credentials to the client too.
func checkConsole(conn net.Conn) error {
	sys, err := sysconf.Load()
	if err != nil || sys == nil {
		return err
	}
	want, err := sys.ServiceUID()
	if err != nil {
		return err
	}
	cred, err := ipc.PeerCred(conn)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if cred.UID != want {
		return fmt.Errorf("client: the socket is served by uid %d, not by the console account %q", cred.UID, sys.ServiceUser)
	}
	return nil
}

// noListener reports a dial error meaning nobody listens at the path: no
// socket file, or a socket left by a console that died.
func noListener(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOTDIR)
}

// Profile is the profile this client talks to.
func (c *Client) Profile() string { return c.profile }

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends one request and decodes its result into result (nil to
// ignore it). A console error is returned as *ipc.RPCError. Numbers in
// result decode as json.Number when result holds interface values.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hello && method != ipc.MethodHello {
		if err := c.handshake(ctx); err != nil {
			return err
		}
	}
	return c.call(ctx, method, params, result)
}

func (c *Client) handshake(ctx context.Context) error {
	name := c.Name
	if name == "" {
		name = "locksql"
	}
	var hr ipc.HelloResult
	if err := c.call(ctx, ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: name}, &hr); err != nil {
		return err
	}
	if !ipc.Compatible(hr.ProtocolMajor) {
		return fmt.Errorf("protocol mismatch: the console speaks %d, this client speaks %d; use the same locksql version on both sides",
			hr.ProtocolMajor, ipc.ProtocolMajor)
	}
	if hr.Profile != c.profile {
		return fmt.Errorf("the console on this socket serves profile %s, not %s", hr.Profile, c.profile)
	}
	c.ConsoleVersion = hr.ConsoleVersion
	c.hello = true
	return nil
}

func (c *Client) call(ctx context.Context, method string, params, result any) error {
	if dl, ok := ctx.Deadline(); ok {
		c.lastDeadline = &dl
	} else {
		c.lastDeadline = nil
	}
	if c.broken != nil {
		return c.broken
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("client: encode params: %w", err)
		}
		raw = b
	}
	c.nextID++
	req := ipc.Request{JSONRPC: "2.0", ID: c.nextID, Method: method, Params: raw}

	// Abandoning the call closes the connection: the console cancels a
	// pending approval prompt when it sees the client gone.
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()

	if err := ipc.WriteMsg(c.conn, req); err != nil {
		return c.fail(ctx, err)
	}
	var resp ipc.Response
	if err := ipc.ReadMsg(c.r, &resp); err != nil {
		return c.fail(ctx, err)
	}
	if resp.ID != req.ID {
		c.broken = fmt.Errorf("client: response id %d for request %d", resp.ID, req.ID)
		return c.broken
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result == nil || len(resp.Result) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.UseNumber()
	if err := dec.Decode(result); err != nil {
		return fmt.Errorf("client: decode %s result: %w", method, err)
	}
	return nil
}

// fail marks the connection unusable after a transport error.
func (c *Client) fail(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		c.broken = ctx.Err()
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		c.broken = ErrConsoleClosed
		return ErrConsoleClosed
	}
	c.broken = fmt.Errorf("client: %w", err)
	return c.broken
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

// Plan validates and weighs a statement and returns a one-shot plan.
func (c *Client) Plan(ctx context.Context, p ipc.PlanParams) (ipc.PlanResult, error) {
	var r ipc.PlanResult
	err := c.Call(ctx, ipc.MethodQueryPlan, p, &r)
	return r, err
}

// Run asks the human to approve a plan and returns its result. It waits as
// long as the console does: there is no client-side timeout.
func (c *Client) Run(ctx context.Context, planID string) (ipc.RunResult, error) {
	var r ipc.RunResult
	err := c.Call(ctx, ipc.MethodQueryRun, ipc.RunParams{PlanID: planID}, &r)
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
