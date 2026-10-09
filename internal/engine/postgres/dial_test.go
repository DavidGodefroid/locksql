package postgres

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
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
