package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/product"
)

// vaultEngineName is a test-only engine recording the login it is given.
const vaultEngineName = "fake-vault"

type loginEngine struct {
	users, passwords []string
	// err fails Connect, with the password in its message as a careless
	// driver would put it.
	err bool
}

var vaultEng = &loginEngine{}

func (e *loginEngine) Connect(_ context.Context, p config.Profile, secret []byte, _ engine.DialFunc) (engine.Session, error) {
	e.users, e.passwords = append(e.users, p.User), append(e.passwords, string(secret))
	if e.err {
		return nil, fmt.Errorf("access denied for %s using password %s", p.User, secret)
	}
	return &fakeSession{origin: true, dbs: []string{"app"}, plan: okPlan(), result: userResult()}, nil
}

func init() { engine.Register(vaultEngineName, vaultEng) }

// vaultTokens are the Vault tokens the fake CLI reads were given, in order.
var vaultTokens []string

// vaultStarter returns a starter whose profile reads its login from Vault
// through the fake CLI reads, handed out in order. The human answers the
// Vault token prompt with hvs.t1.
func vaultStarter(t *testing.T, user string, reads ...func() (*secrets.VaultCredentials, error)) (*starter, *fakeIO, *[]string) {
	t.Helper()
	keyring.MockInit()
	*vaultEng = loginEngine{}
	vaultTokens = nil
	var paths []string
	old := vaultRead
	vaultRead = func(_ context.Context, path string, token []byte) (*secrets.VaultCredentials, error) {
		paths = append(paths, path)
		vaultTokens = append(vaultTokens, string(token))
		if len(reads) == 0 {
			t.Fatal("unexpected vault read")
		}
		r := reads[0]
		reads = reads[1:]
		return r()
	}
	t.Cleanup(func() { vaultRead = old })
	p := uatProfile()
	p.Engine, p.User, p.Credentials, p.VaultPath = vaultEngineName, user, config.CredentialsVault, "database/creds/app-ro"
	io := &fakeIO{secrets: []string{"hvs.t1"}}
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	return &starter{o: Options{Now: func() time.Time { return now }}, io: io, profile: p, user: p.User}, io, &paths
}

func login(user, password string, lease time.Duration) func() (*secrets.VaultCredentials, error) {
	return func() (*secrets.VaultCredentials, error) {
		c := &secrets.VaultCredentials{User: user, Password: []byte(password), LeaseDuration: lease}
		if lease > 0 {
			c.LeaseID = "database/creds/app-ro/" + user
		}
		return c, nil
	}
}

// Every connection reads a fresh login from Vault: its user and password
// reach the engine; only the Vault token is asked, once; nothing is offered
// for the keychain or kept.
func TestConnectVaultReadsAFreshLoginEachTime(t *testing.T) {
	t.Setenv("VAULT_ADDR", "https://vault.example:8200")
	var first *secrets.VaultCredentials
	keep := func() (*secrets.VaultCredentials, error) {
		c, _ := login("v-app-ro-1", "pw-1", time.Hour)()
		first = c
		return c, nil
	}
	st, io, paths := vaultStarter(t, "", keep, login("v-app-ro-2", "pw-2", time.Hour))
	sess, err := st.connect(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	vs, ok := sess.(*vaultSession)
	if !ok {
		t.Fatalf("session %T, want *vaultSession", sess)
	}
	if want := st.now().Add(54 * time.Minute); !vs.CredentialsExpire().Equal(want) {
		t.Errorf("refresh at %s, want %s (90%% of the lease)", vs.CredentialsExpire(), want)
	}
	if vs.DBUser() != "v-app-ro-1" || st.user != "v-app-ro-1" {
		t.Errorf("user = %q / %q", vs.DBUser(), st.user)
	}
	if strings.Trim(string(first.Password), "\x00") != "" {
		t.Error("the password read from Vault is not wiped after the connection")
	}
	if _, err := st.reconnect(context.Background(), st.profile); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(vaultEng.users, ","); got != "v-app-ro-1,v-app-ro-2" {
		t.Errorf("engine users = %s", got)
	}
	if got := strings.Join(vaultEng.passwords, ","); got != "pw-1,pw-2" {
		t.Errorf("engine passwords = %s", got)
	}
	if len(*paths) != 2 || (*paths)[0] != "database/creds/app-ro" {
		t.Errorf("vault paths read = %q", *paths)
	}
	if len(io.prompts) != 1 || io.prompts[0] != "Vault token for https://vault.example:8200: " {
		t.Errorf("prompts %q: want the Vault token, once", io.prompts)
	}
	if got := strings.Join(vaultTokens, ","); got != "hvs.t1,hvs.t1" {
		t.Errorf("tokens given to vault = %s", got)
	}
	if !strings.Contains(io.output(), "credentials from Vault: database/creds/app-ro · user v-app-ro-1 · lease 1h0m0s") {
		t.Errorf("output %q", io.output())
	}
	for _, port := range []int{3306, 0} {
		if _, err := keyring.Get(product.P.KeychainService, secrets.KeychainAccount(st.profile.Name, st.profile.Host, port)); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("a Vault login reached the keychain: %v", err)
		}
	}
}

func TestConnectVaultUser(t *testing.T) {
	// A KV secret holding the password only: the profile names the user.
	st, _, _ := vaultStarter(t, "alice", login("", "pw", 0))
	sess, err := st.connect(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if vaultEng.users[0] != "alice" || !sess.(*vaultSession).CredentialsExpire().IsZero() {
		t.Errorf("user %q, refresh %s", vaultEng.users[0], sess.(*vaultSession).CredentialsExpire())
	}
	for name, c := range map[string]struct {
		profileUser, vaultUser, want string
	}{
		"no user anywhere": {"", "", "has no username field: set user in the profile"},
		"other user":       {"alice", "v-root", `is for user "v-root", the profile sets user "alice"`},
		"terminal escape":  {"", "v\x1b[2Jx", "control or formatting character"},
	} {
		st, _, _ := vaultStarter(t, c.profileUser, login(c.vaultUser, "pw", 0))
		_, err := st.connect(context.Background(), true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
		if len(vaultEng.users) != 0 {
			t.Errorf("%s: connected as %q", name, vaultEng.users)
		}
	}
}

// A Vault failure other than a refused token stops the connection with
// the CLI's error; the human is not asked for a password instead.
func TestConnectVaultFailure(t *testing.T) {
	st, io, _ := vaultStarter(t, "", func() (*secrets.VaultCredentials, error) {
		return nil, fmt.Errorf("%w: nothing at database/creds/app-ro", secrets.ErrVaultPath)
	})
	_, err := st.connect(context.Background(), true)
	if !errors.Is(err, secrets.ErrVaultPath) || !strings.Contains(err.Error(), "database/creds/app-ro") {
		t.Errorf("err = %v", err)
	}
	if io.promptCount() != 1 || len(vaultEng.users) != 0 {
		t.Errorf("prompts %q, connections %q", io.prompts, vaultEng.users)
	}
}

// refused is a read Vault refuses: the token is expired or revoked, or its
// policy may not read the path; the CLI's error does not tell which.
func refused() (*secrets.VaultCredentials, error) {
	return nil, fmt.Errorf("%w: the Vault token is invalid or expired, or its policy may not read database/creds/app-ro (permission denied)", secrets.ErrVaultAuth)
}

// A refused token is asked again, at start-up and mid-session (an expired
// token at a reconnect), not a hard failure; the refused token is wiped.
func TestConnectVaultAsksAgainForARefusedToken(t *testing.T) {
	var held []byte
	st, io, _ := vaultStarter(t, "", refused, login("v-1", "pw-1", time.Hour), refused, login("v-2", "pw-2", time.Hour))
	io.secrets = []string{"hvs.stale", "hvs.t1", "hvs.t2"}
	if _, err := st.connect(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	held = st.vaultToken
	if _, err := st.reconnect(context.Background(), st.profile); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(vaultTokens, ","); got != "hvs.stale,hvs.t1,hvs.t1,hvs.t2" {
		t.Errorf("tokens given to vault = %s", got)
	}
	if io.promptCount() != 3 {
		t.Errorf("prompts %q", io.prompts)
	}
	if strings.Trim(string(held), "\x00") != "" {
		t.Error("the refused token is not wiped")
	}
	if got := strings.Join(vaultEng.users, ","); got != "v-1,v-2" {
		t.Errorf("engine users = %s", got)
	}
	// Vault answers "permission denied" alike for a bad token and for a
	// policy that may not read the path: the warning blames neither alone.
	out := io.output()
	if !strings.Contains(out, "Vault refused the read") || !strings.Contains(out, "or a token whose policy may read database/creds/app-ro") ||
		strings.Contains(out, "refused the token") {
		t.Errorf("output %q", out)
	}
	for _, tok := range []string{"hvs.stale", "hvs.t1", "hvs.t2"} {
		if strings.Contains(out, tok) {
			t.Errorf("token %s in the output %q", tok, out)
		}
	}
}

// Three refused tokens in a row end the connection; so does an empty
// answer or Ctrl-C at the prompt.
func TestConnectVaultGivesUp(t *testing.T) {
	st, io, _ := vaultStarter(t, "", refused, refused, refused)
	io.secrets = []string{"hvs.a", "hvs.b", "hvs.c", "hvs.d"}
	_, err := st.connect(context.Background(), true)
	if !errors.Is(err, secrets.ErrVaultAuth) || io.promptCount() != 3 || len(vaultEng.users) != 0 {
		t.Errorf("err = %v, prompts %q, connections %q", err, io.prompts, vaultEng.users)
	}
	if st.vaultToken != nil {
		t.Error("a refused token is kept")
	}
	st, io, _ = vaultStarter(t, "")
	io.secrets = nil
	if _, err := st.connect(context.Background(), true); err == nil || len(vaultTokens) != 0 {
		t.Errorf("err = %v, vault read with %q", err, vaultTokens)
	}
}

// The token is wiped when the console ends.
func TestVaultTokenWiped(t *testing.T) {
	st, _, _ := vaultStarter(t, "", login("v-1", "pw-1", 0))
	if _, err := st.connect(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	tok := st.vaultToken
	st.wipeVaultToken()
	if st.vaultToken != nil || strings.Trim(string(tok), "\x00") != "" {
		t.Errorf("token kept: %q", tok)
	}
}

// A driver error quoting the password does not carry it further.
func TestConnectVaultSanitizesDriverError(t *testing.T) {
	st, _, _ := vaultStarter(t, "", login("v-1", "Sup3r-S3cret", 0))
	vaultEng.err = true
	_, err := st.connect(context.Background(), true)
	if err == nil || strings.Contains(err.Error(), "Sup3r-S3cret") || !strings.Contains(err.Error(), secrets.Redacted) {
		t.Errorf("err = %v", err)
	}
}

// Before the lease of the login ends, the server reconnects with a fresh
// one, and the audit log names the user of each login.
func TestVaultLeaseReconnects(t *testing.T) {
	p := uatProfile()
	p.User, p.Credentials, p.VaultPath = "", config.CredentialsVault, "database/creds/app-ro"
	var h *harness
	logins := 0
	next := func() engine.Session {
		logins++
		return &vaultSession{Session: h.sess, user: fmt.Sprintf("v-%d", logins), refreshAt: h.now.Add(54 * time.Minute)}
	}
	h = newHarness(t, p, func(c *ServerConfig) {
		c.Reconnect = func(context.Context, config.Profile) (engine.Session, error) { return next(), nil }
	})
	h.s.sess = next()
	run := func() {
		pr := h.plan(t, selectUsers, false)
		h.io.answers = append(h.io.answers, "y")
		h.ok(t, ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID}, nil)
	}
	run()
	if logins != 1 {
		t.Fatal("reconnected before the lease end")
	}
	h.now = h.now.Add(55 * time.Minute)
	run()
	if logins != 2 || !strings.Contains(h.io.output(), "Vault lease of the login is ending") {
		t.Fatalf("logins = %d\n%s", logins, h.io.output())
	}
	log := h.auditLog(t)
	if !strings.Contains(log, `"db_user":"v-1"`) || !strings.Contains(log, `"db_user":"v-2"`) {
		t.Errorf("audit users:\n%s", log)
	}
}

// The policy review shows where the login comes from.
func TestDescribePolicyShowsVaultPath(t *testing.T) {
	p := uatProfile()
	p.User, p.Credentials, p.VaultPath = "", config.CredentialsVault, "database/creds/app-ro"
	got := strings.Join(describePolicy(config.NewPolicy(p, nil, nil)), "\n")
	if !strings.Contains(got, "credentials vault") || !strings.Contains(got, "vault: database/creds/app-ro") {
		t.Errorf("policy:\n%s", got)
	}
}
