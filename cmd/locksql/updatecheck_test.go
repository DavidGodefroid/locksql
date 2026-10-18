//go:build unix

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// checkFixture is a fake release server that counts the requests to
// /releases/latest, a cache directory and a clock.
type checkFixture struct {
	srv     *httptest.Server
	latest  string // tag /releases/latest redirects to; "" for a 404
	status  int    // status of the tag page (default 200)
	hits    atomic.Int32
	other   atomic.Int32 // requests to any other path
	headers http.Header
	method  string
	body    int64
	now     time.Time
	cache   string
	envv    map[string]string
	exe     string
}

func newCheckFixture(t *testing.T, latest string) *checkFixture {
	t.Helper()
	f := &checkFixture{latest: latest, status: http.StatusOK, now: time.Unix(1_800_000_000, 0),
		cache: t.TempDir(), envv: map[string]string{}, exe: installedBinary}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/releases/latest":
			f.hits.Add(1)
			f.headers, f.method, f.body = r.Header.Clone(), r.Method, r.ContentLength
			if f.latest == "" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/releases/tag/"+f.latest, http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/releases/tag/") || r.URL.Path == "/releases":
			w.WriteHeader(f.status)
		default:
			f.other.Add(1)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *checkFixture) env() *updateCheckEnv {
	return &updateCheckEnv{
		upd: updateEnv{
			releases: f.srv.URL + "/releases",
			exe:      func() (string, error) { return f.exe, nil },
		},
		now:      func() time.Time { return f.now },
		cacheDir: func() (string, error) { return f.cache, nil },
		getenv:   func(k string) string { return f.envv[k] },
	}
}

func (f *checkFixture) notice(running string) string {
	return newVersionNotice(f.env().withDefaults(), running)
}

func (f *checkFixture) cacheFile() string { return filepath.Join(f.cache, "locksql", "update-check") }

func TestUpdateCheckDefaults(t *testing.T) {
	c := (&updateCheckEnv{}).withDefaults()
	if c.upd.client.Timeout != 2*time.Second {
		t.Errorf("client timeout %v, want 2s", c.upd.client.Timeout)
	}
	if c.upd.releases != releasesURL || c.upd.installed != installedBinary {
		t.Errorf("releases %q, installed %q", c.upd.releases, c.upd.installed)
	}
	t.Setenv("XDG_CACHE_HOME", "/x/cache")
	if d, err := c.cacheDir(); err != nil || d != "/x/cache" {
		t.Errorf("cache dir %q, %v; want $XDG_CACHE_HOME", d, err)
	}
	t.Setenv("XDG_CACHE_HOME", "")
	want, _ := os.UserCacheDir()
	if d, _ := c.cacheDir(); d != want {
		t.Errorf("cache dir %q, want os.UserCacheDir %q", d, want)
	}
}

// One GET a day: a valid cache answers for 24h, then a new GET; the cache
// holds the time and the tag, in a 0700 directory, as a 0600 file.
func TestUpdateCheckThrottle(t *testing.T) {
	f := newCheckFixture(t, "v1.2.0")
	if got := f.notice("1.0.0"); !strings.Contains(got, "locksql v1.2.0 available (you run v1.0.0)") {
		t.Fatalf("notice %q", got)
	}
	if f.hits.Load() != 1 || f.other.Load() != 0 {
		t.Fatalf("hits %d, other %d", f.hits.Load(), f.other.Load())
	}
	if f.method != http.MethodGet || f.body > 0 {
		t.Errorf("request %s, body %d", f.method, f.body)
	}
	for k := range f.headers {
		if k != "User-Agent" && k != "Accept-Encoding" {
			t.Errorf("added header %s", k)
		}
	}
	b, err := os.ReadFile(f.cacheFile())
	if err != nil || string(b) != "1800000000 1.2.0\n" {
		t.Fatalf("cache %q, %v", b, err)
	}
	for p, want := range map[string]os.FileMode{f.cacheFile(): 0o600, filepath.Dir(f.cacheFile()): 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, %v; want %o", p, fi.Mode().Perm(), err, want)
		}
	}

	// Within 24h: the cache answers, even when the server moved on.
	f.latest = "v9.0.0"
	f.now = f.now.Add(23 * time.Hour)
	if got := f.notice("1.0.0"); !strings.Contains(got, "v1.2.0 available") || f.hits.Load() != 1 {
		t.Fatalf("within 24h: notice %q, hits %d", got, f.hits.Load())
	}
	// After 24h: a new GET.
	f.now = f.now.Add(2 * time.Hour)
	if got := f.notice("1.0.0"); !strings.Contains(got, "v9.0.0 available") || f.hits.Load() != 2 {
		t.Fatalf("after 24h: notice %q, hits %d", got, f.hits.Load())
	}
	// Up to date or newer: nothing.
	if got := f.notice("9.0.0"); got != "" {
		t.Errorf("same version: %q", got)
	}
	if got := f.notice("v9.1.0"); got != "" {
		t.Errorf("newer version: %q", got)
	}
}

// A failed check prints nothing, and counts: no new GET for 24h.
func TestUpdateCheckSilentFailures(t *testing.T) {
	cases := map[string]func(f *checkFixture){
		"404":                 func(f *checkFixture) { f.latest = "" },
		"500":                 func(f *checkFixture) { f.status = http.StatusInternalServerError },
		"redirect without vX": func(f *checkFixture) { f.latest = "../../releases" },
		"invalid semver":      func(f *checkFixture) { f.latest = "vnext" },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCheckFixture(t, "v1.2.0")
			setup(f)
			if got := f.notice("1.0.0"); got != "" {
				t.Fatalf("notice %q", got)
			}
			if f.hits.Load() != 1 {
				t.Fatalf("hits %d", f.hits.Load())
			}
			f.now = f.now.Add(time.Hour)
			if got := f.notice("1.0.0"); got != "" || f.hits.Load() != 1 {
				t.Errorf("again: notice %q, hits %d", got, f.hits.Load())
			}
		})
	}
}

func TestUpdateCheckTimeout(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c := updateCheckEnv{
		upd: updateEnv{releases: srv.URL + "/releases", client: &http.Client{Timeout: 50 * time.Millisecond},
			exe: func() (string, error) { return installedBinary, nil }},
		cacheDir: func() (string, error) { return t.TempDir(), nil },
		getenv:   func(string) string { return "" },
	}
	start := time.Now()
	if got := newVersionNotice(c.withDefaults(), "1.0.0"); got != "" || hits.Load() != 1 {
		t.Fatalf("notice %q, hits %d", got, hits.Load())
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
}

// A corrupt or future-dated cache, or one with a tag that is not a version,
// leads to a new check; a bad tag is never printed.
func TestUpdateCheckBadCache(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt":        "garbage\x00",
		"too many":       "1800000000 1.2.0 x",
		"future":         "1800090000 1.5.0",
		"invalid semver": "1800000000 v1;rm",
		"negative":       "-5 1.5.0",
	} {
		t.Run(name, func(t *testing.T) {
			f := newCheckFixture(t, "")
			if err := os.MkdirAll(filepath.Dir(f.cacheFile()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.cacheFile(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := f.notice("1.0.0"); got != "" {
				t.Errorf("notice %q", got)
			}
			if f.hits.Load() != 1 {
				t.Errorf("hits %d, want a new check", f.hits.Load())
			}
		})
	}
	// A non-writable cache: no request, silence.
	f := newCheckFixture(t, "v1.2.0")
	f.cache = "/proc/locksql-no-such-dir"
	if got := f.notice("1.0.0"); got != "" || f.hits.Load() != 0 {
		t.Errorf("non-writable cache dir: notice %q, hits %d", got, f.hits.Load())
	}
	f = newCheckFixture(t, "v1.2.0")
	if err := os.MkdirAll(filepath.Dir(f.cacheFile()), 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if got := f.notice("1.0.0"); got != "" {
			t.Errorf("read-only cache dir: notice %q", got)
		}
	}
	// No cache directory at all.
	f = newCheckFixture(t, "v1.2.0")
	env := f.env()
	env.cacheDir = func() (string, error) { return "", os.ErrNotExist }
	if got := newVersionNotice(env.withDefaults(), "1.0.0"); got != "" || f.hits.Load() != 0 {
		t.Errorf("no cache dir: notice %q, hits %d", got, f.hits.Load())
	}
}

func TestUpdateCheckOptOutAndDev(t *testing.T) {
	f := newCheckFixture(t, "v1.2.0")
	f.envv[noUpdateCheckEnv] = "1"
	if got := f.notice("1.0.0"); got != "" || f.hits.Load() != 0 {
		t.Errorf("opt-out: notice %q, hits %d", got, f.hits.Load())
	}
	if _, err := os.Stat(f.cacheFile()); err == nil {
		t.Error("opt-out wrote the cache")
	}
	f.envv[noUpdateCheckEnv] = ""
	for _, v := range []string{"dev", "", "1.0", "vX"} {
		if got := f.notice(v); got != "" || f.hits.Load() != 0 {
			t.Errorf("version %q: notice %q, hits %d", v, got, f.hits.Load())
		}
	}
}

func TestUpdateNoticeChannels(t *testing.T) {
	f := newCheckFixture(t, "v1.2.0")
	f.exe = installedBinary
	got := f.notice("1.0.0")
	if got != "locksql v1.2.0 available (you run v1.0.0): locksql update\n" {
		t.Errorf("/usr/local/bin: %q", got)
	}

	f.exe = "/usr/bin/locksql"
	got = f.notice("1.0.0")
	for _, want := range []string{"locksql v1.2.0 available (you run v1.0.0)\n", "/usr/bin/locksql was installed by a package",
		"sudo apt install", "sudo dnf install", "apk add", "V=1.2.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("/usr/bin lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "locksql update:") || strings.Contains(got, ": locksql update") {
		t.Errorf("/usr/bin points at locksql update:\n%s", got)
	}

	f.exe = "/home/a/go/bin/locksql"
	got = f.notice("1.0.0")
	if got != "locksql v1.2.0 available (you run v1.0.0)\nGet it from "+releasesURL+"\n" {
		t.Errorf("other: %q", got)
	}

	for _, exe := range []string{installedBinary, "/usr/bin/locksql", "/opt/locksql"} {
		f.exe = exe
		if got := f.notice("1.0.0"); strings.Contains(got, "sudo locksql update") {
			t.Errorf("%s: %q", exe, got)
		}
	}
}

// doctor prints the notice on stderr, without changing its output or code.
func TestDoctorUpdateNotice(t *testing.T) {
	setVersion(t, "1.0.0")
	f := newCheckFixture(t, "v1.2.0")
	d := fakeDoctor(separatedSys())
	run := func(chk *updateCheckEnv) (int, string, string) {
		var out, errb bytes.Buffer
		e := env{stdout: &out, stderr: &errb, cwd: t.TempDir(), doc: &d, chk: chk}
		return runEnv(e, []string{"doctor"}), out.String(), errb.String()
	}
	off := f.env()
	off.getenv = func(k string) string { return map[string]string{noUpdateCheckEnv: "1"}[k] }
	code0, out0, err0 := run(off)
	if f.hits.Load() != 0 || err0 != "" {
		t.Fatalf("opt-out: hits %d, stderr %q", f.hits.Load(), err0)
	}
	code, out, errs := run(f.env())
	if f.hits.Load() != 1 || errs != "locksql v1.2.0 available (you run v1.0.0): locksql update\n" {
		t.Fatalf("hits %d, stderr %q", f.hits.Load(), errs)
	}
	if code != code0 || out != out0 {
		t.Errorf("the notice changed doctor: code %d/%d", code, code0)
	}
	// The server failing changes nothing either.
	f.latest = ""
	f.now = f.now.Add(25 * time.Hour)
	if code, out, errs := run(f.env()); code != code0 || out != out0 || errs != "" {
		t.Errorf("failed check: code %d, stderr %q", code, errs)
	}
}

// mcp and the other commands never check.
func TestUpdateCheckNotFromOtherCommands(t *testing.T) {
	setVersion(t, "1.0.0")
	f := newCheckFixture(t, "v1.2.0")
	dir := t.TempDir()
	for _, args := range [][]string{{"mcp"}, {"version"}, {"help"}, {"status"}, {"stats", "--log", filepath.Join(dir, "none")}} {
		var out bytes.Buffer
		e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &out, cwd: dir, chk: f.env()}
		runEnv(e, args)
	}
	// And through the MCP protocol.
	inR, inW := io.Pipe()
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runEnv(env{stdin: inR, stdout: &out, stderr: &out, cwd: dir, chk: f.env()}, []string{"mcp"})
	}()
	_, _ = inW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n"))
	inW.Close()
	<-done
	if n := f.hits.Load() + f.other.Load(); n != 0 {
		t.Errorf("%d requests", n)
	}
}

// The handoff passes the opt-out on to the console account as an argument,
// and the agent's account never checks before the exec.
func TestConsoleHandoffUpdateCheck(t *testing.T) {
	setVersion(t, "1.0.0")
	for _, optOut := range []bool{false, true} {
		f := newCheckFixture(t, "v1.2.0")
		if optOut {
			f.envv[noUpdateCheckEnv] = "1"
		}
		for _, helper := range []string{"sudo", "machinectl", "su"} {
			h, ran := fakeHandoff(1500, helper)
			var atExec int32 = -1
			exec := h.exec
			h.exec = func(argv []string) error {
				atExec = f.hits.Load()
				return exec(argv)
			}
			e, out := handoffTestEnv(t, h)
			e.chk = f.env()
			if code := runEnv(e, []string{"console"}); code != exitOK {
				t.Fatalf("code %d\n%s", code, out)
			}
			joined := strings.Join(*ran, " ")
			if has := strings.Contains(joined, noUpdateCheckFlag); has != optOut {
				t.Errorf("opt-out %v, %s: argv %q", optOut, helper, *ran)
			}
			if atExec != 0 || f.hits.Load() != 0 {
				t.Errorf("%s: checked in the agent's account (%d before exec, %d in all)", helper, atExec, f.hits.Load())
			}
			if strings.Contains(out.String(), "available") {
				t.Errorf("notice before the handoff:\n%s", out)
			}
		}
		// Refused in the agent's own account: no check either.
		h, _ := fakeHandoff(1000, "sudo")
		e, _ := handoffTestEnv(t, h)
		e.chk = f.env()
		runEnv(e, []string{"console"})
		if f.hits.Load() != 0 {
			t.Errorf("agent's account checked")
		}
	}
	// The printed command for the agent's account holds no internal flag.
	if strings.Contains((consoleArgs{project: "/p", noUpdateCheck: true}).command(), noUpdateCheckFlag) {
		t.Error("internal flag in the printed command")
	}
}
