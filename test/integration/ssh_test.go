//go:build integration && linux

package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// sshServer is an in-process SSH server that accepts one client key and
// forwards direct-tcpip channels, the way sshd does with
// AllowTcpForwarding. It is a copy of internal/tunnel's test server, which
// this package cannot import.
type sshServer struct {
	addr    string
	hostKey ssh.Signer
	mu      sync.Mutex
	conns   []net.Conn
	// forwarded are the destinations of the accepted channels.
	forwarded []string
}

func newSSHServer(t *testing.T, client ssh.PublicKey) *sshServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), client.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown key")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sshServer{addr: ln.Addr().String(), hostKey: signer}
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, nc)
			s.mu.Unlock()
			go s.serve(nc, cfg)
		}
	}()
	return s
}

func (s *sshServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(false, nil) // OpenSSH answers keepalive@ with failure
			}
		}
	}()
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		var req struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(nch.ExtraData(), &req); err != nil {
			nch.Reject(ssh.ConnectionFailed, "bad request")
			continue
		}
		addr := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
		dst, err := net.Dial("tcp", addr)
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		s.mu.Lock()
		s.forwarded = append(s.forwarded, addr)
		s.mu.Unlock()
		go ssh.DiscardRequests(chReqs)
		go func() { io.Copy(ch, dst); ch.CloseWrite() }()
		go func() { io.Copy(dst, ch); dst.Close() }()
	}
}

func (s *sshServer) forwardedTo(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.forwarded {
		if a == addr {
			return true
		}
	}
	return false
}

// assertSSHConsole starts a console whose profile reaches db through an
// in-process SSH server with key authentication and a pre-recorded host
// key, runs SELECT 1 through it, and checks that the database connection
// went through the tunnel and that the audit log names the bastion.
func assertSSHConsole(t *testing.T, eng string, db Server) {
	t.Helper()
	if _, err := buildLocksql(); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
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
engine = %q
host = %q
port = %d
user = "ro"
database = "app"
tls = "prefer"

[profiles.p.ssh]
host = %q
port = %s
user = "it"
auth = "key"
key = "~/.ssh/id_ed25519"
`, eng, db.Host, db.Port, sshHost, sshPort)
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, "state")
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + state,
		"XDG_RUNTIME_DIR=" + runDir,
	}

	c := startConsole(t, project, append(env, "HOME="+home), "--profile", "p")
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	c.expect("Password for ro@" + db.Host + ": ")
	c.send(ROPassword + "\n")
	c.expect("Accept all [a], review [r], skip [s]: ")
	c.send("a\n")
	seen := c.expect("Listening…")
	m := socketLine.FindStringSubmatch(seen)
	if m == nil {
		t.Fatalf("no socket path in %q", seen)
	}

	cl := dialConsole(t, m[1])
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor}, &hr); e != nil {
		t.Fatal(e)
	}
	var pr ipc.PlanResult
	if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT 1 AS one LIMIT 1"}, &pr); e != nil {
		t.Fatalf("plan: %v", e)
	}
	cl.send(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
	c.expect("Approve? [y/N] ")
	c.send("y\n")
	resp, err := cl.recv(30 * time.Second)
	if err != nil || resp.Error != nil {
		t.Fatalf("run: %+v %v", resp, err)
	}
	if !strings.Contains(string(resp.Result), "1") {
		t.Errorf("result %s", resp.Result)
	}
	c.send("\x03")
	if err := c.wait(); err != nil {
		t.Fatalf("console exit: %v", err)
	}

	if dst := net.JoinHostPort(db.Host, strconv.Itoa(db.Port)); !bastion.forwardedTo(dst) {
		t.Errorf("the bastion never forwarded to %s", dst)
	}
	log, err := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), `"ssh_host"`) || !strings.Contains(string(log), `"decision":"tunnel"`) {
		t.Errorf("the audit log does not record the tunnel:\n%s", log)
	}
	if strings.Contains(c.output(), ROPassword) || strings.Contains(string(log), ROPassword) {
		t.Error("the password leaked")
	}
}

func TestConsoleThroughSSHPostgres(t *testing.T) {
	assertSSHConsole(t, "postgres", startPostgres(t, "17"))
}

func TestConsoleThroughSSHMariaDB(t *testing.T) {
	assertSSHConsole(t, string(engine.FlavorMariaDB), startMySQL(t, mysqlTarget{engine.FlavorMariaDB, "11.4"}))
}
