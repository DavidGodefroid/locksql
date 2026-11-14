//go:build integration && linux

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// The idle end of a session, end to end (locksql#198): a console whose
// profile reaches Postgres through an SSH bastion with a passphrase key,
// both secrets "ask". At idle_timeout the connection and the tunnel close
// and the console keeps running; the agent's next query asks the connect
// tickets, the passphrase and the password come sealed in the decisions,
// and the SELECT is served without any question on the terminal. Twice.
//
//	go test -tags integration -run TestIdleEndReconnectsOnConnectTickets ./test/integration
func TestIdleEndReconnectsOnConnectTickets(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for two idle timeouts of a minute")
	}
	db := startPostgres(t, "17")
	if _, err := buildLocksql(); err != nil {
		t.Fatal(err)
	}
	const passphrase = "key-pass-198"
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	bastion := newSSHServer(t, clientKey)
	sshHost, sshPort, err := net.SplitHostPort(bastion.addr)
	if err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(bastion.addr)}, bastion.hostKey.PublicKey())
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`[profiles.p]
engine = "postgres"
host = %q
port = %d
user = "ro"
database = "app"
tls = "prefer"
credentials = "ask"

[profiles.p.limits]
idle_timeout = "1m"

[profiles.p.ssh]
host = %q
port = %s
user = "it"
auth = "key"
key = "~/.ssh/id_ed25519"
credentials = "ask"
`, db.Host, db.Port, sshHost, sshPort)
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, "state")
	env := []string{
		"PATH=" + os.Getenv("PATH"), "TERM=xterm", "HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + state,
		"XDG_RUNTIME_DIR=" + runDir,
	}

	c := startConsole(t, project, env, "--profile", "p")
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	c.expect("Passphrase for ")
	c.send(passphrase + "\n")
	c.expect("Password for ro@" + db.Host + ": ")
	c.send(ROPassword + "\n")
	c.expect("Accept all [a], review [r], skip [s]: ")
	c.send("a\n")
	m := socketLine.FindStringSubmatch(c.expect("Listening…"))
	if m == nil {
		t.Fatal("no socket path")
	}
	cl := dialConsole(t, m[1])
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, confinedHello, &hr); e != nil {
		t.Fatal(e)
	}
	selectOne := func() {
		t.Helper()
		var pr ipc.PlanResult
		if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT 1 AS one LIMIT 1"}, &pr); e != nil {
			t.Fatalf("plan: %v", e)
		}
		var rr ipc.RunResult
		if e := cl.run(c.hub, pr.PlanID, &rr); e != nil || len(rr.Rows) != 1 {
			t.Fatalf("run: %v %+v", e, rr)
		}
	}
	selectOne()
	if bastion.openConns() != 1 {
		t.Fatalf("SSH connections open: %d", bastion.openConns())
	}

	seen := map[string]bool{}
	for _, id := range c.hub.Tickets() {
		seen[id] = true
	}
	for round := 1; round <= 2; round++ {
		c.expectWithin("the console keeps running", 3*time.Minute) // idle_timeout is 1m
		select {
		case err := <-c.done:
			t.Fatalf("round %d: the console exited at idle_timeout: %v", round, err)
		default:
		}
		deadline := time.Now().Add(10 * time.Second)
		for bastion.openConns() != 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if n := bastion.openConns(); n != 0 {
			t.Fatalf("round %d: %d SSH connections still open after idle_timeout", round, n)
		}
		var st ipc.StatusResult
		if e := cl.call(ipc.MethodStatus, nil, &st); e != nil {
			t.Fatalf("round %d: status after idle_timeout: %v", round, e)
		}

		// The agent's next query asks the connect tickets: the database
		// leg with the password, then the SSH leg with the passphrase.
		done := make(chan *ipc.RPCError, 1)
		go func() {
			var pr ipc.PlanResult
			done <- cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT 1 AS one LIMIT 1"}, &pr)
		}()
		dbLeg := waitConnect(t, c.hub, seen)
		if dbLeg.Subject.Endpoint != fmt.Sprintf("%s:%d/app", db.Host, db.Port) || dbLeg.Subject.SecretTo == "" {
			t.Fatalf("database leg: %+v", dbLeg.Subject)
		}
		sealDecide(t, c.hub, dbLeg, ROPassword)
		sshLeg := waitConnect(t, c.hub, seen)
		if sshLeg.Subject.Endpoint != bastion.addr || sshLeg.Subject.SecretTo == "" {
			t.Fatalf("ssh leg: %+v", sshLeg.Subject)
		}
		sealDecide(t, c.hub, sshLeg, passphrase)
		select {
		case e := <-done:
			if e != nil {
				t.Fatalf("round %d: plan after the connect tickets: %v", round, e)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("round %d: the plan did not finish", round)
		}
		selectOne()
		for _, id := range c.hub.Tickets() {
			seen[id] = true
		}
	}
	if strings.Count(c.output(), "Passphrase for ") != 1 || strings.Count(c.output(), "Password for ") != 1 {
		t.Error("a start question was asked again on the terminal")
	}
	c.send("\x03")
	if err := c.wait(); err != nil {
		t.Fatalf("console exit: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(log), `"decision":"idle-closed"`) != 2 || strings.Count(string(log), `"decision":"reconnected"`) != 2 {
		t.Errorf("idle ends and reconnections not on record:\n%s", log)
	}
	for _, secret := range []string{ROPassword, passphrase} {
		if strings.Contains(c.output(), secret) || strings.Contains(string(log), secret) {
			t.Errorf("a secret leaked: %q", secret)
		}
		for _, id := range c.hub.Tickets() {
			if strings.Contains(string(c.hub.Ticket(id)), secret) {
				t.Errorf("a secret is in ticket %s", id)
			}
		}
		for _, d := range c.hub.Decisions() {
			if strings.Contains(string(d), secret) {
				t.Error("a secret is in clear in a decision")
			}
		}
	}
}

// waitConnect waits for a connect ticket the hub holds that is not in
// seen, and adds it.
func waitConnect(t *testing.T, hub *hubtest.Hub, seen map[string]bool) *ticket.Ticket {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, id := range hub.Tickets() {
			if seen[id] {
				continue
			}
			seen[id] = true
			var tk ticket.Ticket
			if err := json.Unmarshal(hub.Ticket(id), &tk); err != nil {
				t.Fatal(err)
			}
			if tk.Kind != ticket.KindConnect {
				t.Fatalf("ticket %s: kind %s, want connect", id, tk.Kind)
			}
			return &tk
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no connect ticket reached the hub")
	return nil
}

// sealDecide approves connect ticket tk with secret sealed to it, as
// lox run does.
func sealDecide(t *testing.T, hub *hubtest.Hub, tk *ticket.Ticket, secret string) {
	t.Helper()
	hub.DecideWith(tk.ID, ticket.Approved, "", nil, func(d *ticket.Decision) {
		box, err := ticket.SealSecret(tk, []byte(secret))
		if err != nil {
			t.Error(err)
		}
		d.Secret = box
	})
}
