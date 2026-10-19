package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// noUpdateCheckEnv disables the new-version notice of console and doctor.
const noUpdateCheckEnv = "LOCKSQL_NO_UPDATE_CHECK"

// noUpdateCheckFlag is the internal console flag that carries
// LOCKSQL_NO_UPDATE_CHECK to the console account: the handoff helper
// resets the environment.
const noUpdateCheckFlag = "--no-update-check"

// Update check limits: one request a day, and a short one.
const (
	updateCheckEvery   = 24 * time.Hour
	updateCheckTimeout = 2 * time.Second
)

// updateCheckEnv is what the new-version check reads from the system; nil
// fields mean the real one.
type updateCheckEnv struct {
	// upd is the release source: releases, exe, installed and client
	// (default: an http.Client with a 2s timeout).
	upd updateEnv
	// now is the clock.
	now func() time.Time
	// cacheDir is the base cache directory of this account.
	cacheDir func() (string, error)
	// getenv reads the environment.
	getenv func(string) string
}

func (c *updateCheckEnv) withDefaults() updateCheckEnv {
	d := *c
	if d.upd.client == nil {
		d.upd.client = &http.Client{Timeout: updateCheckTimeout}
	}
	d.upd = d.upd.withDefaults()
	if d.now == nil {
		d.now = time.Now
	}
	if d.getenv == nil {
		d.getenv = os.Getenv
	}
	if d.cacheDir == nil {
		getenv := d.getenv
		d.cacheDir = func() (string, error) {
			if x := getenv("XDG_CACHE_HOME"); filepath.IsAbs(x) {
				return x, nil
			}
			return os.UserCacheDir()
		}
	}
	return d
}

// updateCheckDisabled reports whether LOCKSQL_NO_UPDATE_CHECK is set.
func updateCheckDisabled(getenv func(string) string) bool {
	v := getenv(noUpdateCheckEnv)
	return v != "" && v != "0"
}

// updateCheckOff reports whether LOCKSQL_NO_UPDATE_CHECK is set for e.
func (e env) updateCheckOff() bool {
	if e.chk != nil && e.chk.getenv != nil {
		return updateCheckDisabled(e.chk.getenv)
	}
	return updateCheckDisabled(os.Getenv)
}

// updateNotice prints, on stderr, that a release newer than the running
// one exists. It checks the network at most once a day, and any failure
// prints nothing. Only console and doctor call it.
func updateNotice(e env) {
	c := e.chk
	if c == nil {
		c = &updateCheckEnv{}
	}
	if msg := newVersionNotice(c.withDefaults(), version); msg != "" {
		fmt.Fprint(e.stderr, msg)
	}
}

// newVersionNotice is the notice for running version running, or "".
func newVersionNotice(c updateCheckEnv, running string) string {
	if updateCheckDisabled(c.getenv) {
		return ""
	}
	running = strings.TrimPrefix(running, "v")
	if _, err := parseSemver(running); err != nil {
		return "" // dev
	}
	latest := cachedLatest(c)
	if latest == "" {
		return ""
	}
	if n, err := compareSemver(latest, running); err != nil || n <= 0 {
		return ""
	}
	bin, err := c.upd.exe()
	if err != nil {
		return ""
	}
	return noticeText(c.upd, bin, latest, running)
}

// noticeText tells how to get release latest for the channel of bin.
func noticeText(u updateEnv, bin, latest, running string) string {
	head := fmt.Sprintf("locksql v%s available (you run v%s)", latest, running)
	switch {
	case bin == u.installed:
		return head + ": locksql update\n"
	case strings.HasPrefix(bin, "/usr/bin/"):
		return head + "\n" + strings.TrimPrefix(packageHint(bin), "locksql update: ") + "Here V=" + latest + ".\n"
	default:
		return head + "\nGet it from " + releasesURL + "\n"
	}
}

// cachedLatest is the latest release (without its v), from the cache when
// it is less than a day old, else from the network; "" when unknown.
func cachedLatest(c updateCheckEnv) string {
	dir, err := c.cacheDir()
	if err != nil || dir == "" {
		return ""
	}
	file := filepath.Join(dir, "locksql", "update-check")
	now := c.now()
	if at, tag, ok := readUpdateCache(file); ok && !at.After(now) && now.Sub(at) < updateCheckEvery {
		return tag
	}
	// No cache, no request: the throttle must hold.
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return ""
	}
	tag, err := latestTag(c.upd)
	if err != nil {
		tag = ""
	}
	tag = strings.TrimPrefix(tag, "v")
	if _, err := parseSemver(tag); err != nil {
		tag = ""
	}
	// The check counts even when it failed: one request a day.
	if err := writeUpdateCache(file, now, tag); err != nil {
		return ""
	}
	return tag
}

// readUpdateCache reads "<unix seconds> <tag>" (the tag may be empty); ok
// is false for a missing or corrupt cache.
func readUpdateCache(file string) (at time.Time, tag string, ok bool) {
	b, err := os.ReadFile(file)
	if err != nil || len(b) > 256 {
		return at, "", false
	}
	f := strings.Fields(string(b))
	if len(f) < 1 || len(f) > 2 {
		return at, "", false
	}
	secs, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || secs < 0 {
		return at, "", false
	}
	if len(f) == 2 {
		if _, err := parseSemver(f[1]); err != nil {
			return at, "", false
		}
		tag = f[1]
	}
	return time.Unix(secs, 0), tag, true
}

// writeUpdateCache records a check made at at that found tag ("" for
// none), in a 0700 directory, as a 0600 file.
func writeUpdateCache(file string, at time.Time, tag string) error {
	f, err := os.CreateTemp(filepath.Dir(file), ".update-check-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := fmt.Fprintf(f, "%d %s\n", at.Unix(), tag); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), file)
}
