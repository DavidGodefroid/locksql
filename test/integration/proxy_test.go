//go:build integration && linux

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/proxycmd"
)

// buildStdioTCP builds testdata/stdiotcp for the containers' platform once
// per test binary.
var buildStdioTCP = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "ls-stdiotcp-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "stdiotcp")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/stdiotcp")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %v: %s", err, out)
	}
	return bin, nil
})

// withRelay copies stdiotcp into the container at /stdiotcp.
func withRelay(seed func(Server) error) func(Server) error {
	return func(s Server) error {
		bin, err := buildStdioTCP()
		if err != nil {
			return err
		}
		if out, err := exec.Command("docker", "cp", bin, s.Name+":/stdiotcp").CombinedOutput(); err != nil {
			return fmt.Errorf("docker cp: %v: %s", err, out)
		}
		return seed(s)
	}
}

// startLoopbackPostgres runs PostgreSQL listening on 127.0.0.1 inside its
// container only, with no port published.
func startLoopbackPostgres(t *testing.T) Server {
	ready := func(s Server) error {
		return Exec(s, "", "pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres", "-d", "app")
	}
	return StartUnpublished(t, "loopback", "postgres:17", []string{"POSTGRES_PASSWORD=" + RootPassword, "POSTGRES_DB=app"},
		[]string{"-c", "listen_addresses=127.0.0.1"}, ready, withRelay(func(s Server) error {
			return Exec(s, postgresSeed, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app")
		}))
}

// startLoopbackMariaDB runs MariaDB bound to 127.0.0.1 inside its
// container only, with no port published.
func startLoopbackMariaDB(t *testing.T) Server {
	ready := func(s Server) error {
		return Exec(s, "", "mariadb-admin", "--protocol=tcp", "-h127.0.0.1", "-uroot", "-p"+RootPassword, "ping")
	}
	return StartUnpublished(t, "loopback", "mariadb:11.4", []string{"MARIADB_ROOT_PASSWORD=" + RootPassword},
		[]string{"--bind-address=127.0.0.1"}, ready, withRelay(func(s Server) error {
			return Exec(s, mysqlSeedCommon+mariadbSeed, "mariadb", "-uroot", "-p"+RootPassword)
		}))
}

// assertProxyConsole starts a console whose profile reaches db, a server
// that listens on its container's loopback and publishes no port, through
// proxy_command = docker exec, and runs SELECT 1 through it.
func assertProxyConsole(t *testing.T, eng string, db Server, port int) {
	t.Helper()
	if out, _ := exec.Command("docker", "port", db.Name).Output(); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("the container publishes %s", out)
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`[profiles.p]
engine = %q
host = "127.0.0.1"
port = %d
user = "ro"
database = "app"
proxy_command = [%q, "exec", "-i", %q, "/stdiotcp", "127.0.0.1:%d"]
`, eng, port, docker, db.Name, port)
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
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + state,
		"XDG_RUNTIME_DIR=" + runDir,
	}
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		env = append(env, "DOCKER_HOST="+h)
	}

	c := startConsole(t, project, env, "--profile", "p")
	seen := c.expect("Apply these changes? [y/N]")
	if !strings.Contains(seen, "proxy_command: ") || !strings.Contains(seen, `"/stdiotcp"`) {
		t.Errorf("the approval screen does not show proxy_command:\n%s", seen)
	}
	c.send("y\n")
	c.expect("Password for ro@127.0.0.1: ")
	c.send(ROPassword + "\n")
	c.expect("Accept all [a], review [r], skip [s]: ")
	c.send("a\n")
	seen = c.expect("Listening…")
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
	if strings.Contains(c.output(), "NOT encrypted") {
		t.Errorf("a loopback database behind proxy_command is reported unencrypted:\n%s", c.output())
	}
	log, err := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.output(), ROPassword) || strings.Contains(string(log), ROPassword) {
		t.Error("the password leaked")
	}
}

func TestConsoleThroughProxyCommandPostgres(t *testing.T) {
	assertProxyConsole(t, "postgres", startLoopbackPostgres(t), 5432)
}

func TestConsoleThroughProxyCommandMariaDB(t *testing.T) {
	assertProxyConsole(t, "mariadb", startLoopbackMariaDB(t), 3306)
}

// A proxy_command that fails leaves its stderr for the connection error.
func TestProxyCommandStderr(t *testing.T) {
	db := startLoopbackPostgres(t)
	e, err := engine.Get(config.EnginePostgres)
	if err != nil {
		t.Fatal(err)
	}
	p := config.Profile{Name: "it", Engine: config.EnginePostgres, Host: "127.0.0.1", Port: 5432, User: "ro", Database: "app",
		TLS: config.TLSDisable, Limits: config.Limits{StatementTimeout: 5 * time.Second, MaxRows: 10}}
	ok := proxycmd.New([]string{"docker", "exec", "-i", db.Name, "/stdiotcp", "127.0.0.1:5432"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := e.Connect(ctx, p, []byte(ROPassword), ok.Dial)
	if err != nil {
		t.Fatalf("connect through docker exec: %v", err)
	}
	s.Close()

	bad := proxycmd.New([]string{"docker", "exec", "-i", db.Name + "-missing", "/stdiotcp", "127.0.0.1:5432"})
	if _, err := e.Connect(ctx, p, []byte(ROPassword), bad.Dial); err == nil {
		t.Fatal("connect through a missing container succeeded")
	}
	if msg := bad.Stderr(); !strings.Contains(strings.ToLower(msg), "no such container") && !strings.Contains(msg, "no container") {
		t.Errorf("stderr = %q", msg)
	}
}
