package secrets

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/zalando/go-keyring"
)

// KeychainService is the service name of every locksql keychain item. The
// account is "<profile>@<host>".
const KeychainService = "locksql"

var (
	// ErrNotFound means the keychain has no item for the profile and host.
	ErrNotFound = errors.New("secrets: no keychain item")
	// ErrUnavailable means the OS keychain could not be used, for example a
	// headless Linux without a Secret Service. The console then behaves as
	// credentials = "ask".
	ErrUnavailable = errors.New("secrets: OS keychain unavailable")
)

func keychainAccount(profile, host string) string {
	return profile + "@" + host
}

func checkItem(profile, host string) error {
	if profile == "" || host == "" {
		return errors.New("secrets: keychain item needs a profile and a host")
	}
	if strings.ContainsFunc(profile+host, unicode.IsControl) {
		return errors.New("secrets: keychain item name has control characters")
	}
	return nil
}

func keychainErr(op string, err error, secret []byte) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return fmt.Errorf("%w: %s: %s", ErrUnavailable, op, SanitizeString(err.Error(), secret))
}

// KeychainGet reads the secret of profile@host from the OS keychain.
func KeychainGet(profile, host string) ([]byte, error) {
	if err := checkItem(profile, host); err != nil {
		return nil, err
	}
	s, err := keyring.Get(KeychainService, keychainAccount(profile, host))
	if err != nil {
		return nil, keychainErr("get", err, nil)
	}
	return []byte(s), nil
}

// KeychainSet stores s as the secret of profile@host, replacing any
// previous one.
func KeychainSet(profile, host string, s []byte) error {
	if err := checkItem(profile, host); err != nil {
		return err
	}
	if len(s) == 0 {
		return errors.New("secrets: refusing to store an empty secret")
	}
	if err := keyring.Set(KeychainService, keychainAccount(profile, host), string(s)); err != nil {
		return keychainErr("set", err, s)
	}
	return nil
}

// KeychainDelete removes the item of profile@host. A missing item gives
// ErrNotFound.
func KeychainDelete(profile, host string) error {
	if err := checkItem(profile, host); err != nil {
		return err
	}
	if err := keyring.Delete(KeychainService, keychainAccount(profile, host)); err != nil {
		return keychainErr("delete", err, nil)
	}
	return nil
}
