package mysql

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// TestProbeTLS checks that the doctor's probe gets the server certificate
// with the SSL request alone: no handshake response, so no user and no
// password, reaches the server.
func TestProbeTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t)
	f := &tlsServer{ln: ln, cert: cert, plugin: "mysql_native_password"}
	go f.serve()
	p := config.Profile{Engine: config.EngineMySQL, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u", TLS: config.TLSVerifyFull}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var prober engine.TLSProber = Engine{}
	certs, err := prober.ProbeTLS(ctx, p)
	ln.Close()
	f.done.Wait()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(certs) != 1 || string(certs[0].Raw) != string(cert.Certificate[0]) {
		t.Fatalf("probe returned %d certificates, want the server's", len(certs))
	}
	if !f.tlsDone || f.resp != nil {
		t.Errorf("tls = %v, handshake response = %x: want TLS and no response", f.tlsDone, f.resp)
	}
}

func TestProbeTLSNoServerTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ln: ln}
	go f.serve(t)
	defer func() { ln.Close(); f.done.Wait() }()
	p := config.Profile{Engine: config.EngineMySQL, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, TLS: config.TLSRequire}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (Engine{}).ProbeTLS(ctx, p); err != engine.ErrNoServerTLS {
		t.Errorf("probe of a server without TLS: err = %v, want ErrNoServerTLS", err)
	}
}
