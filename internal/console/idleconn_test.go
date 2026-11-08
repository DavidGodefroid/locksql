package console

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// fakeConnector is Run's starter connecting through the fake engine.
type fakeConnector struct{ st *starter }

func (c fakeConnector) connectNeeds(p config.Profile) (bool, bool) { return c.st.connectNeeds(p) }

func (c fakeConnector) reconnectSealed(ctx context.Context, p config.Profile, sec *connectSecrets) (engine.Session, error) {
	p.Engine = fakeEngineName
	return c.st.reconnectSealed(ctx, p, sec)
}

// idleHarness is a console whose connection closes on idle and opens
// again on connect tickets, through the start-up path and the fake
// engine, whose next session is returned.
func idleHarness(t *testing.T, p config.Profile, extra []string) (*harness, *fakeSession) {
	t.Helper()
	next := &fakeSession{origin: true, dbs: []string{"app", "other"}, plan: okPlan(), result: userResult(), extra: extra}
	fakeNext, fakeSecret = next, nil
	h := newHarness(t, p, func(c *ServerConfig) {
		sp := p
		sp.Engine = fakeEngineName
		st := &starter{io: c.IO, log: c.Audit, profile: sp, user: p.User, privWarns: extra}
		c.Reconnect = func(ctx context.Context, cur config.Profile) (engine.Session, error) {
			cur.Engine = fakeEngineName
			return st.reconnect(ctx, cur)
		}
		c.IdleConnect = fakeConnector{st}
	})
	return h, next
}

// goIdle moves past idle_timeout and ticks.
func goIdle(h *harness) {
	h.now = h.now.Add(h.s.idleTimeout() + time.Second)
	h.s.Tick()
}

// async runs a request on its own goroutine: it waits on its connect
// tickets meanwhile.
func async(h *harness, method string, params any) <-chan ipc.Response {
	raw, _ := json.Marshal(params)
	out := make(chan ipc.Response, 1)
	go func() {
		out <- h.s.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 9, Method: method, Params: raw})
	}()
	return out
}

// nextTicket waits for a ticket the hub holds that is not in seen, and
// adds it.
func nextTicket(t *testing.T, h *harness, seen map[string]bool) *ticket.Ticket {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, id := range h.hub.Tickets() {
			if seen[id] {
				continue
			}
			seen[id] = true
			var tk ticket.Ticket
			if err := json.Unmarshal(h.hub.Ticket(id), &tk); err != nil {
				t.Fatal(err)
			}
			return &tk
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no new ticket reached the hub")
	return nil
}

// decideConnect decides connect ticket tk, sealing secret to it (nil:
// none).
func decideConnect(t *testing.T, h *harness, tk *ticket.Ticket, out ticket.Outcome, secret []byte) {
	t.Helper()
	h.hub.DecideWith(tk.ID, out, "", nil, func(d *ticket.Decision) {
		d.At = h.now // dated on the console's clock, as the harness runs it
		if secret == nil {
			return
		}
		box, err := ticket.SealSecret(tk, secret)
		if err != nil {
			t.Error(err)
		}
		d.Secret = box
	})
}

func wait(t *testing.T, ch <-chan ipc.Response) ipc.Response {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("the request did not finish")
	}
	return ipc.Response{}
}

// At idle_timeout the connection closes and the console goes on: not
// ended, on record, its socket's methods still answered, and nothing
// asked on the terminal.
func TestIdleClosesTheConnectionNotTheConsole(t *testing.T) {
	h, _ := idleHarness(t, uatProfile(), nil)
	h.now = h.now.Add(h.s.idleTimeout() - time.Second)
	h.s.Tick()
	if h.sess.closed {
		t.Fatal("closed before idle_timeout")
	}
	goIdle(h)
	if reason, ended := h.s.Ended(); ended {
		t.Fatalf("console ended at idle_timeout: %q", reason)
	}
	if !h.sess.closed {
		t.Fatal("database connection left open after idle_timeout")
	}
	if !strings.Contains(h.auditLog(t), `"decision":"idle-closed"`) {
		t.Errorf("idle close not on record:\n%s", h.auditLog(t))
	}
	if !containsLine(h.io, "the console keeps running") {
		t.Errorf("console output:\n%s", h.io.output())
	}
	h.ok(t, ipc.MethodStatus, nil, nil)
	// Ticking on while idle closes nothing again and ends nothing.
	h.now = h.now.Add(time.Hour)
	h.s.Tick()
	if _, ended := h.s.Ended(); ended || strings.Count(h.auditLog(t), "idle-closed") != 1 {
		t.Fatalf("second idle tick: ended or closed again\n%s", h.auditLog(t))
	}
	if len(h.io.prompts) != 0 || h.hub.Pushed() != 0 {
		t.Fatalf("idle close asked something: prompts %q, tickets %d", h.io.prompts, h.hub.Pushed())
	}
}

// The next request after an idle end asks a connect ticket; once it is
// approved with the password sealed in the decision, the request is
// served on the new connection: no question on the terminal, and the
// password in neither the ticket nor the audit log.
func TestIdleNextRequestAsksConnect(t *testing.T) {
	h, next := idleHarness(t, uatProfile(), nil)
	goIdle(h)
	resp := async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	tk := nextTicket(t, h, map[string]bool{})
	if tk.Kind != ticket.KindConnect || tk.Subject == nil || tk.Subject.Profile != "uat" ||
		tk.Subject.Endpoint != "db.uat.example.com:3306" || tk.Subject.Credential != ticket.CredentialAsk || tk.Subject.SecretTo == "" {
		t.Fatalf("connect ticket: kind %s subject %+v", tk.Kind, tk.Subject)
	}
	if tk.Risk != ticket.RiskUnlock || !tk.Flags.NeverAuto {
		t.Errorf("risk %s never_auto %v", tk.Risk, tk.Flags.NeverAuto)
	}
	const pw = "s3cret-pw-198"
	decideConnect(t, h, tk, ticket.Approved, []byte(pw))
	if r := wait(t, resp); r.Error != nil {
		t.Fatalf("request after the connect ticket: %d %q", r.Error.Code, r.Error.Message)
	}
	if string(fakeSecret) != pw {
		t.Fatalf("connected with %q, want the sealed password", fakeSecret)
	}
	if next.catalog != 1 {
		t.Fatalf("catalog calls on the new connection = %d", next.catalog)
	}
	if len(h.io.prompts) != 0 {
		t.Fatalf("asked on the terminal: %q", h.io.prompts)
	}
	log := h.auditLog(t)
	if strings.Contains(log, pw) || strings.Contains(string(h.hub.Ticket(tk.ID)), pw) || strings.Contains(h.io.output(), pw) {
		t.Fatal("the password left the connection")
	}
	for _, want := range []string{`"event":"pending"`, `"event":"approved"`, `"decision":"reconnected"`, `"ticket":"` + tk.ID + `"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit lacks %s:\n%s", want, log)
		}
	}
	if !h.hub.Consumed(tk.ID) {
		t.Error("connect ticket not consumed")
	}
	// The new connection is shared until the next idle end.
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	if h.hub.Pushed() != 1 || next.catalog != 2 {
		t.Fatalf("second request: tickets %d, catalog %d", h.hub.Pushed(), next.catalog)
	}
	// It closes at the next idle end too, and the next request asks again.
	goIdle(h)
	if !next.closed {
		t.Fatal("reopened connection not closed at the next idle_timeout")
	}
	resp = async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	seen := map[string]bool{tk.ID: true}
	tk2 := nextTicket(t, h, seen)
	next2 := &fakeSession{origin: true, dbs: []string{"app"}, plan: okPlan(), result: userResult()}
	fakeNext = next2
	decideConnect(t, h, tk2, ticket.Approved, []byte(pw))
	if r := wait(t, resp); r.Error != nil || next2.catalog != 1 {
		t.Fatalf("after the second idle end: %+v, catalog %d", r.Error, next2.catalog)
	}
}

// A connect ticket refused in lox run gives the agent a clear error; the
// console keeps running and the next request asks again.
func TestIdleConnectRefused(t *testing.T) {
	h, next := idleHarness(t, uatProfile(), nil)
	goIdle(h)
	resp := async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	seen := map[string]bool{}
	tk := nextTicket(t, h, seen)
	decideConnect(t, h, tk, ticket.Denied, nil)
	r := wait(t, resp)
	if r.Error == nil || r.Error.Code != ipc.CodeConnLost || !strings.Contains(r.Error.Message, "refused in lox run") ||
		strings.Contains(r.Error.Message, "restart") {
		t.Fatalf("refused connect: %+v", r.Error)
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("console ended on a refused connect ticket")
	}
	if next.catalog != 0 || fakeSecret != nil {
		t.Fatal("connected after a refusal")
	}
	if !strings.Contains(h.auditLog(t), `"event":"denied"`) {
		t.Errorf("refusal not on record:\n%s", h.auditLog(t))
	}
	resp = async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	tk2 := nextTicket(t, h, seen)
	decideConnect(t, h, tk2, ticket.Approved, []byte("pw"))
	if r := wait(t, resp); r.Error != nil || next.catalog != 1 {
		t.Fatalf("after a refusal, asking again: %+v", r.Error)
	}
}

// An approval without the secret the ticket asked for opens nothing.
func TestIdleConnectWithoutTheSecret(t *testing.T) {
	h, next := idleHarness(t, uatProfile(), nil)
	goIdle(h)
	resp := async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	decideConnect(t, h, nextTicket(t, h, map[string]bool{}), ticket.Approved, nil)
	if r := wait(t, resp); r.Error == nil || next.catalog != 0 {
		t.Fatalf("connected on an approval without the secret: %+v", r.Error)
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("console ended")
	}
}

// The findings of the privilege audit the human accepted at start are not
// asked again after an idle end; new ones are.
func TestIdlePrivilegeAuditNotAskedAgain(t *testing.T) {
	extra := []string{"INSERT on app.users"}
	h, next := idleHarness(t, uatProfile(), extra)
	goIdle(h)
	resp := async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	decideConnect(t, h, nextTicket(t, h, map[string]bool{}), ticket.Approved, []byte("pw"))
	if r := wait(t, resp); r.Error != nil || next.catalog != 1 {
		t.Fatalf("after the idle end: %+v", r.Error)
	}
	if len(h.io.prompts) != 0 {
		t.Fatalf("asked again: %q", h.io.prompts)
	}
}

// max_session still ends the session.
func TestIdleMaxSessionStillEnds(t *testing.T) {
	h, _ := idleHarness(t, uatProfile(), nil)
	goIdle(h)
	h.now = h.now.Add(config.DefaultLimits(false).MaxSession)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "maximum session length" {
		t.Fatalf("max_session: %q %v", reason, ended)
	}
}

// Activity holds the idle end off: a request that reaches the database
// does, a status poll does not.
func TestIdleActivity(t *testing.T) {
	h, _ := idleHarness(t, uatProfile(), nil)
	idle := h.s.idleTimeout()
	h.now = h.now.Add(idle - time.Second)
	h.ok(t, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"}, nil)
	h.now = h.now.Add(idle - time.Second)
	h.s.Tick()
	if h.sess.closed {
		t.Fatal("closed although a request came within idle_timeout")
	}
	h.ok(t, ipc.MethodStatus, nil, nil)
	h.now = h.now.Add(2 * time.Second)
	h.s.Tick()
	if !h.sess.closed {
		t.Fatal("a status poll held the idle end off")
	}
	var st ipc.StatusResult
	h.ok(t, ipc.MethodStatus, nil, &st)
	if st.IdleTimeoutInS != int(idle/time.Second) {
		t.Fatalf("status idle_timeout_in_s %d", st.IdleTimeoutInS)
	}
}

// With ssh.credentials = "ask", the SSH leg asks its own connect ticket
// for the bastion's secret; each secret goes to its own leg.
func TestIdleSSHLegAsksItsOwnTicket(t *testing.T) {
	p := uatProfile()
	p.SSH = &config.SSHProfile{Host: "bastion.example.com", Port: 22, User: "ops", Auth: config.SSHAuthKey, Key: "~/.ssh/id", Credentials: config.CredentialsAsk}
	rec := &recordingConnector{sess: &fakeSession{origin: true, dbs: []string{"app"}, plan: okPlan(), result: userResult()}}
	h := newHarness(t, p, func(c *ServerConfig) { c.IdleConnect = rec })
	goIdle(h)
	resp := async(h, ipc.MethodCatalogList, ipc.TablesParams{DB: "app"})
	seen := map[string]bool{}
	db := nextTicket(t, h, seen)
	decideConnect(t, h, db, ticket.Approved, []byte("db-pw"))
	ssh := nextTicket(t, h, seen)
	if ssh.Subject.Endpoint != "bastion.example.com:22" || ssh.Subject.Profile != "uat" || ssh.Subject.SecretTo == "" ||
		db.Subject.Endpoint != "db.uat.example.com:3306" {
		t.Fatalf("legs: db %+v ssh %+v", db.Subject, ssh.Subject)
	}
	decideConnect(t, h, ssh, ticket.Approved, []byte("key-pass"))
	if r := wait(t, resp); r.Error != nil {
		t.Fatalf("request: %+v", r.Error)
	}
	if rec.db != "db-pw" || rec.ssh != "key-pass" {
		t.Fatalf("secrets: db %q ssh %q", rec.db, rec.ssh)
	}
}

// recordingConnector records the secrets it was handed.
type recordingConnector struct {
	sess    *fakeSession
	db, ssh string
}

func (r *recordingConnector) connectNeeds(p config.Profile) (bool, bool) {
	return p.Credentials == config.CredentialsAsk, p.SSH != nil
}

func (r *recordingConnector) reconnectSealed(_ context.Context, _ config.Profile, sec *connectSecrets) (engine.Session, error) {
	r.db, r.ssh = string(sec.db), string(sec.ssh)
	return r.sess, nil
}

func TestConnectNeeds(t *testing.T) {
	ssh := func(auth, cred string) *config.SSHProfile {
		return &config.SSHProfile{Host: "b", Port: 22, User: "u", Auth: auth, Credentials: cred}
	}
	for _, c := range []struct {
		name     string
		cred     string
		ssh      *config.SSHProfile
		asked    bool
		db, sshS bool
	}{
		{"ask", config.CredentialsAsk, nil, false, true, false},
		{"keychain", config.CredentialsKeychain, nil, false, false, false},
		{"vault", config.CredentialsVault, nil, false, false, false},
		{"ssh key asked", config.CredentialsKeychain, ssh(config.SSHAuthKey, config.CredentialsAsk), true, false, true},
		{"ssh key never asked", config.CredentialsKeychain, ssh(config.SSHAuthKey, config.CredentialsAsk), false, false, false},
		{"ssh agent", config.CredentialsAsk, ssh(config.SSHAuthAgent, config.CredentialsAsk), true, true, false},
		{"ssh keychain", config.CredentialsAsk, ssh(config.SSHAuthPassword, config.CredentialsKeychain), true, true, false},
	} {
		p := uatProfile()
		p.Credentials, p.SSH = c.cred, c.ssh
		st := &starter{sshAsked: c.asked}
		if db, s := st.connectNeeds(p); db != c.db || s != c.sshS {
			t.Errorf("%s: needs db %v ssh %v, want %v %v", c.name, db, s, c.db, c.sshS)
		}
	}
}

// A reconnection with sealed secrets never asks on the terminal: a secret
// its tickets did not carry fails it.
func TestSealedSecretNotAskedOnTheTerminal(t *testing.T) {
	io := &fakeIO{secrets: []string{"typed"}}
	st := &starter{io: io, user: "alice", sealed: &connectSecrets{}}
	open := func(secret []byte) (engine.Session, error) { return &fakeSession{}, nil }
	if _, err := st.connectSecret(context.Background(), uatProfile(), open, false); !errors.Is(err, errNotSealed) {
		t.Fatalf("without the sealed secret: %v", err)
	}
	var got []byte
	st.sealed = &connectSecrets{db: []byte("sealed")}
	open = func(secret []byte) (engine.Session, error) { got = slices.Clone(secret); return &fakeSession{}, nil }
	if _, err := st.connectSecret(context.Background(), uatProfile(), open, false); err != nil || string(got) != "sealed" {
		t.Fatalf("with the sealed secret: %v %q", err, got)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("asked on the terminal: %q", io.prompts)
	}
}

func TestDBEndpoint(t *testing.T) {
	p := uatProfile()
	if e := dbEndpoint(p); e != "db.uat.example.com:3306" {
		t.Errorf("no database: %q", e)
	}
	p.Database = "shop"
	if e := dbEndpoint(p); e != "db.uat.example.com:3306/shop" {
		t.Errorf("database: %q", e)
	}
	p.Database = "we?ird db"
	if e := dbEndpoint(p); e != "db.uat.example.com:3306" {
		t.Errorf("a name a ticket refuses: %q", e)
	}
	p = config.Profile{Engine: config.EngineSQLite, Path: "/data/app.db"}
	if e := dbEndpoint(p); e != "sqlite/app.db" {
		t.Errorf("sqlite: %q", e)
	}
}
