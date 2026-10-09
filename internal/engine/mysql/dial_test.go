package mysql

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestConnectDialsThroughDialFunc(t *testing.T) {
	var mu sync.Mutex
	var addrs []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		addrs = append(addrs, network+" "+addr)
		mu.Unlock()
		return nil, errors.New("stub dialer")
	}
	p := config.Profile{Engine: config.EngineMySQL, Host: "db.internal", Port: 3306, User: "u", TLS: config.TLSDisable}
	_, err := Engine{}.Connect(t.Context(), p, []byte("pw"), dial)
	if err == nil || !strings.Contains(err.Error(), "stub dialer") {
		t.Fatalf("err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) == 0 || addrs[0] != "tcp db.internal:3306" {
		t.Errorf("dialled %v", addrs)
	}
}
