package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer is an SSH server that accepts direct-tcpip channels to any
// address and forwards them, the way sshd does with AllowTcpForwarding.
type testServer struct {
	addr     string
	hostKey  ssh.Signer
	mu       sync.Mutex
	conns    []net.Conn
	dropReqs bool // stop answering global requests (keepalive)
}

func newTestServer(t *testing.T, cfg *ssh.ServerConfig) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{addr: ln.Addr().String(), hostKey: signer}
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

func (s *testServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go func() {
		for r := range reqs {
			s.mu.Lock()
			drop := s.dropReqs
			s.mu.Unlock()
			if !drop && r.WantReply {
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
		dst, err := net.Dial("tcp", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() { io.Copy(ch, dst); ch.CloseWrite() }()
		go func() { io.Copy(dst, ch); dst.Close(); ch.Close() }() // as sshd, once the target stops taking data
	}
}

// echoServer accepts TCP connections and echoes what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func trust(s *testServer) ssh.HostKeyCallback { return ssh.FixedHostKey(s.hostKey.PublicKey()) }
