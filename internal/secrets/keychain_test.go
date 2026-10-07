package secrets

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestKeychainAccount(t *testing.T) {
	if got := keychainAccount("uat", "db.example.com"); got != "uat@db.example.com" {
		t.Fatalf("account = %q", got)
	}
}

func TestKeychainMock(t *testing.T) {
	keyring.MockInit()
	if _, err := KeychainGet("uat", "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: err = %v", err)
	}
	if err := KeychainSet("uat", "h", []byte("pw")); err != nil {
		t.Fatal(err)
	}
	got, err := KeychainGet("uat", "h")
	if err != nil || string(got) != "pw" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := KeychainDelete("uat", "h"); err != nil {
		t.Fatal(err)
	}
	if err := KeychainDelete("uat", "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: err = %v", err)
	}
}

func TestKeychainRefusesEmpty(t *testing.T) {
	keyring.MockInit()
	if err := KeychainSet("uat", "h", nil); err == nil {
		t.Fatal("empty secret accepted")
	}
	if err := KeychainSet("", "h", []byte("x")); err == nil {
		t.Fatal("empty profile accepted")
	}
}

func TestKeychainErrorsHideSecret(t *testing.T) {
	keyring.MockInitWithError(errors.New("backend said hunter2"))
	_, err := KeychainGet("uat", "h")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	err = KeychainSet("uat", "h", []byte("hunter2"))
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
	const profile, host = "locksql-test", "127.0.0.1"
	t.Cleanup(func() { _ = KeychainDelete(profile, host) })
	if err := KeychainSet(profile, host, []byte("t3st")); err != nil {
		t.Fatal(err)
	}
	got, err := KeychainGet(profile, host)
	if err != nil || string(got) != "t3st" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := KeychainDelete(profile, host); err != nil {
		t.Fatal(err)
	}
	if _, err := KeychainGet(profile, host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
