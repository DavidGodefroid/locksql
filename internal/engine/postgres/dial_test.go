package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestConnConfigUsesDialFunc(t *testing.T) {
	called := false
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, errors.New("stub dialer")
	}
	p := config.Profile{Engine: config.EnginePostgres, Host: "db.internal", Port: 5432, User: "u", TLS: config.TLSDisable}
	_, err := Engine{}.Connect(t.Context(), p, nil, dial)
	if err == nil || !called {
		t.Fatalf("called = %v, err = %v", called, err)
	}
}

// TestCancelRequestDialsServerAddress drives pgconn's real CancelRequest over
// a connection whose RemoteAddr is meaningless, as a tunnel's is: the cancel
// dial must still receive the server address.
func TestCancelRequestDialsServerAddress(t *testing.T) {
	var mu sync.Mutex
	var addrs []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		addrs = append(addrs, network+" "+addr)
		n := len(addrs)
		mu.Unlock()
		if n > 1 {
			return nil, errors.New("stub cancel dial")
		}
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(s, buf); err != nil {
				return
			}
			rest := make([]byte, binary.BigEndian.Uint32(buf)-4)
			if _, err := io.ReadFull(s, rest); err != nil {
				return
			}
			var out []byte
			out = append(out, 'R', 0, 0, 0, 8, 0, 0, 0, 0)
			out = append(out, 'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2)
			out = append(out, 'Z', 0, 0, 0, 5, 'I')
			s.Write(out)
			io.Copy(io.Discard, s)
		}()
		return c, nil
	}
	p := config.Profile{Engine: config.EnginePostgres, Host: "db.internal", Port: 5432, User: "u", TLS: config.TLSDisable}
	cfg, err := connConfig(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	useDialer(cfg, dial)
	pc, err := pgconn.ConnectConfig(t.Context(), &cfg.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(context.Background())
	if err := pc.CancelRequest(t.Context()); err == nil || !strings.Contains(err.Error(), "stub cancel dial") {
		t.Fatalf("err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) != 2 || addrs[1] != "tcp db.internal:5432" {
		t.Errorf("dialled %v", addrs)
	}
}
