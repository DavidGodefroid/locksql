package secrets

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestKeychainAccount(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"db.example.com", 5432, "uat@db.example.com:5432"},
		{"ssh:bastion.example.com", 22, "uat@ssh:bastion.example.com:22"},
		{"/run/mysqld/mysqld.sock", 3306, "uat@/run/mysqld/mysqld.sock"},
	} {
		if got := KeychainAccount("uat", c.host, c.port); got != c.want {
			t.Errorf("account(%s, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

// An item stored for one port is not handed out for another.
func TestKeychainPortIsPartOfTheItem(t *testing.T) {
	keyring.MockInit()
	if err := KeychainSet("uat", "h", 5432, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := KeychainGet("uat", "h", 5433, 5432); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other port: err = %v", err)
	}
	if err := KeychainHas("uat", "h", 5433); !errors.Is(err, ErrNotFound) {
		t.Fatalf("has, other port: err = %v", err)
	}
	if _, _, err := KeychainGet("uat", "h", 0, 3306); err == nil {
		t.Fatal("TCP host without a port accepted")
	}
}

// A legacy "<profile>@<host>" item is moved to the new name on the first
// read on the default port, once; on another port it is not used.
func TestKeychainMigratesLegacyItem(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set(KeychainService, "uat@h", "old"); err != nil {
		t.Fatal(err)
	}
	if err := KeychainHas("uat", "h", 5432); err != nil {
		t.Fatalf("has legacy: %v", err)
	}
	if _, err := keyring.Get(KeychainService, "uat@h"); err != nil {
		t.Fatalf("has moved the legacy item: %v", err)
	}
	// Not on the default port: the legacy name says nothing of the port.
	if _, migrated, err := KeychainGet("uat", "h", 5433, 5432); !errors.Is(err, ErrNotFound) || migrated {
		t.Fatalf("other port: migrated %t, err = %v", migrated, err)
	}
	if v, err := keyring.Get(KeychainService, "uat@h"); err != nil || v != "old" {
		t.Fatalf("legacy item after a non-default port = %q, %v", v, err)
	}
	if _, err := keyring.Get(KeychainService, "uat@h:5433"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("item created for the other port: %v", err)
	}
	got, migrated, err := KeychainGet("uat", "h", 5432, 5432)
	if err != nil || string(got) != "old" || !migrated {
		t.Fatalf("get = %q, %t, %v", got, migrated, err)
	}
	if v, err := keyring.Get(KeychainService, "uat@h:5432"); err != nil || v != "old" {
		t.Fatalf("new item = %q, %v", v, err)
	}
	if _, err := keyring.Get(KeychainService, "uat@h"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("legacy item kept: %v", err)
	}
	got, migrated, err = KeychainGet("uat", "h", 5432, 5432)
	if err != nil || string(got) != "old" || migrated {
		t.Fatalf("second get = %q, %t, %v", got, migrated, err)
	}
}

// A new item wins over a legacy one, which delete then removes too.
func TestKeychainDeleteRemovesLegacyItem(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set(KeychainService, "uat@h", "old"); err != nil {
		t.Fatal(err)
	}
	if err := KeychainSet("uat", "h", 5432, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, migrated, err := KeychainGet("uat", "h", 5432, 5432)
	if err != nil || string(got) != "new" || migrated {
		t.Fatalf("get = %q, %t, %v", got, migrated, err)
	}
	if err := KeychainDelete("uat", "h", 5432); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"uat@h", "uat@h:5432"} {
		if _, err := keyring.Get(KeychainService, account); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("%s kept: %v", account, err)
		}
	}
	if err := KeychainDelete("uat", "h", 5432); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: err = %v", err)
	}
	// Only a legacy item: delete removes it.
	if err := keyring.Set(KeychainService, "uat@h", "old"); err != nil {
		t.Fatal(err)
	}
	if err := KeychainDelete("uat", "h", 5432); err != nil {
		t.Fatalf("delete legacy only: %v", err)
	}
}

// A Unix socket keeps "<profile>@<path>", which is its own legacy name.
func TestKeychainSocketItem(t *testing.T) {
	keyring.MockInit()
	const sock = "/run/mysqld/mysqld.sock"
	if err := keyring.Set(KeychainService, "uat@"+sock, "pw"); err != nil {
		t.Fatal(err)
	}
	got, migrated, err := KeychainGet("uat", sock, 3306, 3306)
	if err != nil || string(got) != "pw" || migrated {
		t.Fatalf("get = %q, %t, %v", got, migrated, err)
	}
	if err := KeychainDelete("uat", sock, 0); err != nil {
		t.Fatal(err)
	}
}

func TestKeychainMock(t *testing.T) {
	keyring.MockInit()
	if _, _, err := KeychainGet("uat", "h", 5432, 5432); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: err = %v", err)
	}
	if err := KeychainSet("uat", "h", 5432, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	got, _, err := KeychainGet("uat", "h", 5432, 5432)
	if err != nil || string(got) != "pw" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := KeychainDelete("uat", "h", 5432); err != nil {
		t.Fatal(err)
	}
	if err := KeychainDelete("uat", "h", 5432); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: err = %v", err)
	}
}

func TestKeychainRefusesEmpty(t *testing.T) {
	keyring.MockInit()
	if err := KeychainSet("uat", "h", 5432, nil); err == nil {
		t.Fatal("empty secret accepted")
	}
	if err := KeychainSet("", "h", 5432, []byte("x")); err == nil {
		t.Fatal("empty profile accepted")
	}
}

func TestKeychainErrorsHideSecret(t *testing.T) {
	keyring.MockInitWithError(errors.New("backend said hunter2"))
	_, _, err := KeychainGet("uat", "h", 5432, 5432)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	err = KeychainSet("uat", "h", 5432, []byte("hunter2"))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("secret leaked in %v", err)
	}
}

// TestKeychainReal talks to the OS keychain. CI has no Secret Service,
// so it only runs with LOCKSQL_TEST_KEYCHAIN=1.
func TestKeychainReal(t *testing.T) {
	if os.Getenv("LOCKSQL_TEST_KEYCHAIN") != "1" {
		t.Skip("set LOCKSQL_TEST_KEYCHAIN=1 to use the OS keychain")
	}
	const profile, host, port = "locksql-test", "127.0.0.1", 5432
	t.Cleanup(func() { _ = KeychainDelete(profile, host, port) })
	if err := KeychainSet(profile, host, port, []byte("t3st")); err != nil {
		t.Fatal(err)
	}
	got, _, err := KeychainGet(profile, host, port, port)
	if err != nil || string(got) != "t3st" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := KeychainDelete(profile, host, port); err != nil {
		t.Fatal(err)
	}
	if _, _, err := KeychainGet(profile, host, port, port); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
