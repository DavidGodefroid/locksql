package secrets

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/zalando/go-keyring"
)

// KeychainService is the service name of every locksql keychain item. The
// account is "<profile>@<host>:<port>", or "<profile>@<path>" for a Unix
// socket.
const KeychainService = "locksql"

var (
	// ErrNotFound means the keychain has no item for the profile and host.
	ErrNotFound = errors.New("secrets: no keychain item")
	// ErrUnavailable means the OS keychain could not be used, for example a
	// headless Linux without a Secret Service. The console then behaves as
	// credentials = "ask".
	ErrUnavailable = errors.New("secrets: OS keychain unavailable")
)

// KeychainAccount names the keychain item of profile at host and port:
// "<profile>@<host>:<port>". A Unix-socket host (a path) has no port and
// keeps "<profile>@<path>". The port is part of the name so that a changed
// port does not send the stored secret to whatever listens there.
func KeychainAccount(profile, host string, port int) string {
	if socketHost(host) {
		return legacyAccount(profile, host)
	}
	return profile + "@" + host + ":" + strconv.Itoa(port)
}

// legacyAccount is the name of the items stored before the port was part
// of it: "<profile>@<host>".
func legacyAccount(profile, host string) string {
	return profile + "@" + host
}

func socketHost(host string) bool { return strings.HasPrefix(host, "/") }

func checkItem(profile, host string, port int) error {
	if profile == "" || host == "" {
		return errors.New("secrets: keychain item needs a profile and a host")
	}
	if !socketHost(host) && (port <= 0 || port > 65535) {
		return errors.New("secrets: keychain item needs a port")
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

func get(account string) ([]byte, error) {
	s, err := keyring.Get(KeychainService, account)
	if err != nil {
		return nil, keychainErr("get", err, nil)
	}
	return []byte(s), nil
}

// Legacy says what KeychainGet did with a pre-upgrade item, named
// "<profile>@<host>" without the port.
type Legacy int

const (
	// LegacyNone: no pre-upgrade item was involved.
	LegacyNone Legacy = iota
	// LegacyMoved: the item was moved to the name of the default port, and
	// its secret returned.
	LegacyMoved
	// LegacyRemoved: the profile is on another port; the item was deleted
	// unread and ErrNotFound returned.
	LegacyRemoved
)

// KeychainGet reads the secret of profile at host and port from the OS
// keychain. When the item is missing and a pre-upgrade item named
// "<profile>@<host>" exists, the caller tells the human what happened to
// it (legacy): on the default port it is moved to the new name once and
// its secret returned; on any other port it is deleted without being read.
// The legacy name says nothing of the port, so a changed port must not get
// the secret, and an item left behind would reach whatever listens on the
// default port later.
func KeychainGet(profile, host string, port, defaultPort int) (secret []byte, legacy Legacy, err error) {
	if err := checkItem(profile, host, port); err != nil {
		return nil, LegacyNone, err
	}
	account := KeychainAccount(profile, host, port)
	s, err := get(account)
	old := legacyAccount(profile, host)
	if !errors.Is(err, ErrNotFound) || old == account {
		return s, LegacyNone, err
	}
	if port != defaultPort {
		switch err := keyring.Delete(KeychainService, old); {
		case err == nil:
			return nil, LegacyRemoved, ErrNotFound
		case errors.Is(err, keyring.ErrNotFound):
			return nil, LegacyNone, ErrNotFound
		default:
			return nil, LegacyNone, keychainErr("delete", err, nil)
		}
	}
	s, err = get(old)
	if err != nil {
		return nil, LegacyNone, err
	}
	if err := keyring.Set(KeychainService, account, string(s)); err != nil {
		err = keychainErr("set", err, s)
		Wipe(s)
		return nil, LegacyNone, err
	}
	if err := keyring.Delete(KeychainService, old); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		err = keychainErr("delete", err, s)
		Wipe(s)
		return nil, LegacyNone, err
	}
	return s, LegacyMoved, nil
}

// KeychainHas reports whether the keychain holds a secret for profile at
// host and port, under its name or the legacy one, without moving it: nil
// when one is there, ErrNotFound when neither is.
func KeychainHas(profile, host string, port int) error {
	if err := checkItem(profile, host, port); err != nil {
		return err
	}
	s, err := get(KeychainAccount(profile, host, port))
	Wipe(s)
	if errors.Is(err, ErrNotFound) {
		s, err = get(legacyAccount(profile, host))
		Wipe(s)
	}
	return err
}

// KeychainSet stores s as the secret of profile at host and port,
// replacing any previous one.
func KeychainSet(profile, host string, port int, s []byte) error {
	if err := checkItem(profile, host, port); err != nil {
		return err
	}
	if len(s) == 0 {
		return errors.New("secrets: refusing to store an empty secret")
	}
	if err := keyring.Set(KeychainService, KeychainAccount(profile, host, port), string(s)); err != nil {
		return keychainErr("set", err, s)
	}
	return nil
}

// KeychainDelete removes the item of profile at host and port and the
// legacy "<profile>@<host>" one. ErrNotFound means neither was there.
func KeychainDelete(profile, host string, port int) error {
	if err := checkItem(profile, host, port); err != nil {
		return err
	}
	found := false
	for _, account := range []string{KeychainAccount(profile, host, port), legacyAccount(profile, host)} {
		switch err := keyring.Delete(KeychainService, account); {
		case err == nil:
			found = true
		case !errors.Is(err, keyring.ErrNotFound):
			return keychainErr("delete", err, nil)
		}
	}
	if !found {
		return ErrNotFound
	}
	return nil
}
