// Package proxycmd reaches a database through a command whose stdin and
// stdout carry the connection, as OpenSSH's ProxyCommand: docker exec,
// kubectl exec, or ssh to a host that relays to a socket. It serves
// databases that publish no port.
//
// The command runs without a shell, as the console account, in a session
// of its own with no controlling terminal, so that it can neither read
// what the human types into the console nor prompt there, and with an
// environment reduced to what such tools need to find their sockets and
// configuration.
package proxycmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// maxStderr bounds the stderr kept from a command, in bytes: the tail,
// where the error usually is.
const maxStderr = 512

// waitDelay bounds the wait for a command's pipes once it has ended.
const waitDelay = 2 * time.Second

// keptEnv are the environment variables the command inherits. Everything
// else, such as PGPASSWORD, MYSQL_PWD or VAULT_TOKEN, is dropped.
var keptEnv = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TMPDIR": true, "TZ": true,
	"SSH_AUTH_SOCK": true, "XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true,
	"DOCKER_HOST": true, "DOCKER_CONTEXT": true, "DOCKER_CONFIG": true,
	"CONTAINER_HOST": true, "CONTAINERS_CONF": true, "KUBECONFIG": true,
	// Windows needs these to start a program at all.
	"SystemRoot": true, "SYSTEMROOT": true, "windir": true, "ComSpec": true, "PATHEXT": true,
	"USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "ProgramData": true,
	"TEMP": true, "TMP": true, "Path": true,
}

// scrubEnv keeps the variables of environ named in keptEnv, in order.
func scrubEnv(environ []string) []string {
	var out []string
	for _, kv := range environ {
		if k, _, ok := strings.Cut(kv, "="); ok && keptEnv[k] {
			out = append(out, kv)
		}
	}
	return out
}

// Proxy opens connections by running one argv per connection.
type Proxy struct {
	argv []string

	mu     sync.Mutex
	stderr string
}

// New returns a Proxy running argv; argv[0] is looked up in PATH unless it
// is a path.
func New(argv []string) *Proxy { return &Proxy{argv: append([]string(nil), argv...)} }

// Stderr is the sanitized tail of what the last command that ended wrote
// to its stderr, "" when it wrote nothing.
func (p *Proxy) Stderr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stderr
}

// Dial starts the command and returns its stdin and stdout as one
// connection; network and addr are ignored, the command knows where the
// database is. Closing the connection ends the command.
func (p *Proxy) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.argv) == 0 {
		return nil, errors.New("proxy_command is empty")
	}
	cmd := exec.Command(p.argv[0], p.argv[1:]...)
	cmd.Env = scrubEnv(os.Environ())
	// Neither the console's working directory, the project, where a
	// relative argument would name a file the agent can write, nor the home,
	// which may hold the project: an empty directory of the command's own,
	// private to the console account, removed when it ends.
	dir, err := os.MkdirTemp("", "locksql-proxy-")
	if err != nil {
		return nil, fmt.Errorf("proxy_command: %w", err)
	}
	cmd.Dir = dir
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	// Wait gives up on the pipes WaitDelay after the command ended, when a
	// process the command started outside its group still holds them.
	cmd.WaitDelay = waitDelay
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy_command: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy_command: %w", err)
	}
	tail := &tailWriter{}
	cmd.Stderr = tail
	kill, err := start(cmd)
	if err != nil {
		return nil, fmt.Errorf("proxy_command: %w", err)
	}

	// The drivers bound their handshakes and reads with deadlines, which a
	// pipe to a process does not support; a net.Pipe does. When either copy
	// ends, the command is ended and waited for, its stderr is kept, and only
	// then is the driver's end closed: a driver that sees the connection end
	// finds the command's error in Stderr.
	driver, bridge := net.Pipe()
	var once sync.Once
	end := func() {
		once.Do(func() {
			stdin.Close()
			kill()
			cmd.Wait()
			os.RemoveAll(dir)
			if s := sanitize(tail.String()); s != "" {
				p.mu.Lock()
				p.stderr = s
				p.mu.Unlock()
			}
			bridge.Close()
		})
	}
	ok = true
	go func() { io.Copy(stdin, bridge); end() }()
	go func() { io.Copy(bridge, stdout); end() }()
	return &conn{Conn: driver, remote: cmdAddr(p.argv[0])}, nil
}

// conn reports the command as its remote address.
type conn struct {
	net.Conn
	remote net.Addr
}

func (c *conn) LocalAddr() net.Addr  { return cmdAddr("locksql") }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

type cmdAddr string

func (a cmdAddr) Network() string { return "proxy_command" }
func (a cmdAddr) String() string  { return string(a) }

// tailWriter keeps the last maxStderr*2 bytes written to it.
type tailWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *tailWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, b...)
	if over := len(w.buf) - 2*maxStderr; over > 0 {
		w.buf = append(w.buf[:0], w.buf[over:]...)
	}
	return len(b), nil
}

func (w *tailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buf)
}

// sanitize makes a command's stderr safe to print on the console and to
// audit: one line, no control or formatting characters, at most maxStderr
// bytes (the tail, marked with "...").
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "?")
	lines := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
	for i, l := range lines {
		lines[i] = strings.TrimSpace(strings.Map(func(r rune) rune {
			if kconfig.UnsafeRune(r) {
				return -1
			}
			return r
		}, l))
	}
	s = strings.Join(slices.DeleteFunc(lines, func(l string) bool { return l == "" }), "; ")
	if len(s) > maxStderr {
		s = s[len(s)-maxStderr:]
		s = "..." + strings.ToValidUTF8(s, "")
	}
	return s
}
