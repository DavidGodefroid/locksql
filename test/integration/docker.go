//go:build integration

// Package integration holds the tests that run against real database
// servers in throwaway Docker containers. Containers are named "ls-it-*",
// publish their port on 127.0.0.1 only, and are removed when the test binary
// exits (see StopAll).
package integration

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-only credentials of the throwaway containers.
const (
	RootPassword = "root-test-only"
	ROPassword   = "ro-test-only"
	RWPassword   = "rw-test-only"
)

// Server is one running container.
type Server struct {
	Name    string
	Image   string
	Host    string
	Port    int
	Started time.Time
}

var (
	mu      sync.Mutex
	servers = map[string]*serverOnce{}
	running []string
)

type serverOnce struct {
	once sync.Once
	srv  Server
	err  error
}

// DockerAvailable reports whether the docker CLI can reach a daemon.
func DockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	if exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Run() == nil {
		return true
	}
	// Podman's docker shim has no ServerVersion in its info.
	return exec.Command("docker", "info", "--format", "{{.Host.Arch}}").Run() == nil
}

// Start returns the container for image, starting it on first use. env are
// the container's environment variables, ready waits until the server
// accepts a login, seed prepares it. The container is shared by every test
// of the binary and stopped by StopAll.
func Start(t testing.TB, image string, containerPort int, env []string,
	ready func(ctx context.Context, host string, port int) error, seed func(Server) error) Server {
	t.Helper()
	return StartVariant(t, "", image, containerPort, env, nil, nil, ready, seed)
}

// StartVariant is Start for a second container of image, told apart by
// variant, started with runArgs before the image (volumes) and cmdArgs after
// it (server options).
func StartVariant(t testing.TB, variant, image string, containerPort int, env, runArgs, cmdArgs []string,
	ready func(ctx context.Context, host string, port int) error, seed func(Server) error) Server {
	t.Helper()
	if !DockerAvailable() {
		t.Skip("docker is not available")
	}
	key := image
	if variant != "" {
		key += "-" + variant
	}
	mu.Lock()
	so, ok := servers[key]
	if !ok {
		so = &serverOnce{}
		servers[key] = so
	}
	mu.Unlock()
	so.once.Do(func() { so.srv, so.err = start(key, image, containerPort, env, runArgs, cmdArgs, ready, seed) })
	if so.err != nil {
		t.Fatalf("start %s: %v", key, so.err)
	}
	return so.srv
}

func start(key, image string, containerPort int, env, runArgs, cmdArgs []string,
	ready func(ctx context.Context, host string, port int) error, seed func(Server) error) (Server, error) {
	name := "ls-it-" + strings.NewReplacer(":", "-", "/", "-", ".", "").Replace(key) + "-" + strconv.Itoa(os.Getpid())
	args := []string{"run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1::%d", containerPort)}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, runArgs...)
	args = append(args, image)
	args = append(args, cmdArgs...)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		return Server{}, fmt.Errorf("docker run: %v: %s", err, out)
	}
	mu.Lock()
	running = append(running, name)
	mu.Unlock()

	out, err := exec.Command("docker", "port", name, strconv.Itoa(containerPort)).Output()
	if err != nil {
		return Server{}, fmt.Errorf("docker port: %v", err)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	_, portStr, err := net.SplitHostPort(line)
	if err != nil {
		return Server{}, fmt.Errorf("docker port %q: %v", line, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Server{}, err
	}
	srv := Server{Name: name, Image: image, Host: "127.0.0.1", Port: port}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	for {
		// The images run their init phase with networking off, so a
		// successful login means the final server is up.
		c, err := net.DialTimeout("tcp", net.JoinHostPort(srv.Host, portStr), time.Second)
		if err == nil {
			c.Close()
			attempt, cancelAttempt := context.WithTimeout(ctx, 5*time.Second)
			err = ready(attempt, srv.Host, port)
			cancelAttempt()
			if err == nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return Server{}, fmt.Errorf("%s did not become ready: %v", image, err)
		case <-time.After(time.Second):
		}
	}
	if seed != nil {
		if err := seed(srv); err != nil {
			return Server{}, fmt.Errorf("seed %s: %v", image, err)
		}
	}
	srv.Started = time.Now()
	return srv, nil
}

// Exec runs a command inside the container with stdin.
func Exec(srv Server, stdin string, cmd ...string) error {
	args := append([]string{"exec", "-i", srv.Name}, cmd...)
	c := exec.Command("docker", args...)
	c.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, stderr.String())
	}
	return nil
}

// StopAll stops (and so removes) every container this binary started.
func StopAll() {
	mu.Lock()
	names := running
	running = nil
	mu.Unlock()
	if len(names) == 0 {
		return
	}
	_ = exec.Command("docker", append([]string{"stop", "-t", "2"}, names...)...).Run()
}

// Versions returns the comma-separated list in env var name, or def.
func Versions(name string, def ...string) []string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return strings.Split(v, ",")
	}
	return def
}

// StartUnpublished is StartVariant for a container that publishes no port:
// its server is reached only from inside it (docker exec). ready runs until
// it succeeds, typically a client inside the container on 127.0.0.1.
func StartUnpublished(t testing.TB, variant, image string, env, cmdArgs []string,
	ready func(Server) error, seed func(Server) error) Server {
	t.Helper()
	if !DockerAvailable() {
		t.Skip("docker is not available")
	}
	key := image + "-" + variant
	mu.Lock()
	so, ok := servers[key]
	if !ok {
		so = &serverOnce{}
		servers[key] = so
	}
	mu.Unlock()
	so.once.Do(func() { so.srv, so.err = startUnpublished(key, image, env, cmdArgs, ready, seed) })
	if so.err != nil {
		t.Fatalf("start %s: %v", key, so.err)
	}
	return so.srv
}

func startUnpublished(key, image string, env, cmdArgs []string, ready, seed func(Server) error) (Server, error) {
	name := "ls-it-" + strings.NewReplacer(":", "-", "/", "-", ".", "").Replace(key) + "-" + strconv.Itoa(os.Getpid())
	args := []string{"run", "-d", "--rm", "--name", name}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image)
	args = append(args, cmdArgs...)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		return Server{}, fmt.Errorf("docker run: %v: %s", err, out)
	}
	mu.Lock()
	running = append(running, name)
	mu.Unlock()
	srv := Server{Name: name, Image: image, Host: "127.0.0.1"}

	deadline := time.Now().Add(4 * time.Minute)
	for {
		err := ready(srv)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return Server{}, fmt.Errorf("%s did not become ready: %v", image, err)
		}
		time.Sleep(time.Second)
	}
	if seed != nil {
		if err := seed(srv); err != nil {
			return Server{}, fmt.Errorf("seed %s: %v", image, err)
		}
	}
	srv.Started = time.Now()
	return srv, nil
}
