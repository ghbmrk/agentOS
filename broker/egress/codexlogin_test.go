package egress

// REQ: CRED-1, CRED-5, CRED-7, CRED-8, A14, W9

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// canaryLogin is a synthetic Codex token set. The id_token carries an
// email and plan claims the worker must never see.
type canaryLogin struct{ access, refresh, idToken, account, email string }

func newCanaryLogin(t *testing.T) canaryLogin {
	t.Helper()
	c := canaryLogin{
		access:  synthetic(t, "eyJcanaryaccess."),
		refresh: synthetic(t, "rt_canaryrefresh_"),
		account: synthetic(t, "acct-"),
		email:   synthetic(t, "u") + "@canary.invalid",
	}
	c.idToken = fakeJWT(map[string]any{
		"email": c.email,
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": c.account, "chatgpt_plan_type": "pro", "chatgpt_user_id": "user-canary",
		},
	}) + "." + synthetic(t, "sig")
	return c
}

func fakeJWT(claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(claims)
}

func (c canaryLogin) all() []string {
	return []string{c.access, c.refresh, c.idToken, c.email}
}

func (c canaryLogin) creds() map[string]string {
	return map[string]string{"access_token": c.access, "refresh_token": c.refresh, "id_token": c.idToken}
}

type loginRig struct {
	dir    string
	v      *vault.Vault
	locked bool
	logins *PlanLogins
}

func newLoginRig(t *testing.T) *loginRig {
	t.Helper()
	r := &loginRig{dir: t.TempDir()}
	v, err := vault.Create(filepath.Join(r.dir, "vault"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	r.v = v
	r.logins = NewPlanLogins(func() (LoginStore, error) {
		if r.locked {
			return nil, ErrVaultLocked
		}
		return r.v, nil
	}, map[string]string{"codex": "chatgpt.com, Settings, Security"})
	return r
}

// store lands c as the owner's sign-in does: through the sign-in swap.
func (r *loginRig) store(t *testing.T, worker string, c canaryLogin) map[string]string {
	t.Helper()
	phs, commit, err := r.logins.ForSignIn("codex", worker).Swap("codex", c.creds())
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return phs
}

func (r *loginRig) driveHolds(t *testing.T, needle string) []string {
	t.Helper()
	var hits []string
	filepath.Walk(r.dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(needle)) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

// CRED-8, A14: the token set is one vault entry; a canary of it is on the
// drive only as vault ciphertext.
func TestCodexLoginIsOneVaultEntryAndNotOnTheDrive(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	r.store(t, "pw-a", c)

	var names []string
	for _, e := range r.v.List() {
		names = append(names, e.Name+":"+e.Kind)
	}
	if len(names) != 1 || names[0] != "plan-login-codex:plan-login" {
		t.Fatalf("vault entries = %v, want one plan-login entry for codex", names)
	}
	sec, ok := r.v.Secret("plan-login-codex")
	if !ok {
		t.Fatal("no entry")
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(sec.Reveal()), &got); err != nil {
		t.Fatal(err)
	}
	if got["access_token"] != c.access || got["refresh_token"] != c.refresh || got["id_token"] != c.idToken || got["account_id"] != c.account {
		t.Fatalf("entry fields = %v", got)
	}
	for _, s := range append(c.all(), c.account) {
		if hits := r.driveHolds(t, s); len(hits) != 0 {
			t.Fatalf("canary on the drive outside ciphertext: %v", hits)
		}
	}
}

// CRED-5, CRED-1: the placeholder auth.json holds no real value, and its
// id_token carries the account ID alone.
func TestWorkerAuthJSONHoldsOnlyPlaceholders(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	r.store(t, "pw-a", c)

	b, err := r.logins.AuthJSON("codex", "pw-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range c.all() {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("auth.json holds a real value")
		}
	}
	var f struct {
		APIKey *string `json:"OPENAI_API_KEY"`
		Tokens map[string]string
		Last   string `json:"last_refresh"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.APIKey != nil || f.Last == "" {
		t.Fatalf("auth.json = %s", b)
	}
	for _, k := range []string{"access_token", "refresh_token", "id_token", "account_id"} {
		if f.Tokens[k] == "" {
			t.Fatalf("auth.json lacks %s", k)
		}
	}
	if f.Tokens["account_id"] != c.account {
		t.Fatalf("account_id = %q", f.Tokens["account_id"])
	}
	parts := strings.Split(f.Tokens["id_token"], ".")
	if len(parts) != 3 {
		t.Fatalf("id_token shape: %q", f.Tokens["id_token"])
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	auth, _ := claims["https://api.openai.com/auth"].(map[string]any)
	if auth["chatgpt_account_id"] != c.account || len(auth) != 1 {
		t.Fatalf("auth claim = %v, want the account ID alone", auth)
	}
	for k := range claims {
		if k != "exp" && k != "https://api.openai.com/auth" {
			t.Fatalf("id_token carries claim %q", k)
		}
	}
	for _, s := range []string{"pro", c.email, "user-canary"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("id_token leaks %q", s)
		}
	}
}

// CRED-5: a refresh leaves only placeholders in what the CLI writes back,
// and the vault entry holds the new login once commit returns, before the
// proxy releases the response.
func TestRefreshSwapsToPlaceholdersAndVaultFirst(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	r.store(t, "pw-a", old)
	fresh := newCanaryLogin(t)
	fresh.account, fresh.idToken = old.account, old.idToken // refresh keeps the account

	body := `{"access_token":"` + fresh.access + `","refresh_token":"` + fresh.refresh + `","id_token":"` + fresh.idToken + `"}`
	rr := httptest.NewRecorder()
	rr.Header().Set("Content-Type", "application/json")
	rr.WriteString(body)
	resp := rr.Result()

	rule := ResponseRule{Fields: []Field{
		{Name: "access_token", Kind: FieldCredential},
		{Name: "refresh_token", Kind: FieldCredential},
		{Name: "id_token", Kind: FieldCredential},
	}}
	out, commit, err := rule.swap(resp, "codex", r.logins.ForWorker("codex", "pw-a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range fresh.all() {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal("the swapped response holds a real value")
		}
	}
	if v := r.entry(t); v["refresh_token"] != old.refresh {
		t.Fatal("the vault changed before commit")
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if v := r.entry(t); v["refresh_token"] != fresh.refresh || v["access_token"] != fresh.access {
		t.Fatal("commit did not leave the new login in the vault")
	}
	// What the CLI writes back is the swapped response; it resolves to the
	// new login, and the placeholders the response carried are the live ones.
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if v, ok := r.logins.Resolve("codex", "pw-a", got["refresh_token"]); !ok || v != fresh.refresh {
		t.Fatal("new refresh placeholder does not resolve to the new refresh token")
	}
	if _, ok := r.logins.Resolve("codex", "pw-a", got["access_token"]); !ok {
		t.Fatal("new access placeholder does not resolve")
	}
	b, _ := r.logins.AuthJSON("codex", "pw-a")
	for _, s := range append(fresh.all(), old.access, old.refresh) {
		if bytes.Contains(b, []byte(s)) {
			t.Fatal("auth.json holds a real value after the refresh")
		}
	}
}

func (r *loginRig) entry(t *testing.T) map[string]string {
	t.Helper()
	sec, ok := r.v.Secret("plan-login-codex")
	if !ok {
		t.Fatal("no entry")
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(sec.Reveal()), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A vault that cannot take the write fails the commit, so the proxy drops
// the response; the placeholders do not move and no part of the refresh
// is stored (the single-use refresh token is then spent upstream, and the
// next refresh meets the provider's refusal, which stops the route).
func TestFailedVaultWriteStoresNothingAndKeepsPlaceholders(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	phs := r.store(t, "pw-a", old)
	fresh := newCanaryLogin(t)
	fresh.idToken, fresh.account = old.idToken, old.account

	_, commit, err := r.logins.ForWorker("codex", "pw-a").Swap("codex", fresh.creds())
	if err != nil {
		t.Fatal(err)
	}
	r.v.Close() // the write now fails
	if err := commit(); err == nil {
		t.Fatal("commit succeeded without a vault")
	}
	if v, ok := r.logins.Resolve("codex", "pw-a", phs["refresh_token"]); ok && v == fresh.refresh {
		t.Fatal("placeholder moved to the unstored login")
	}
}

// CRED-5 per worker: another worker's placeholder resolves to nothing for
// the first worker, and the first worker's to nothing for the second.
func TestPlaceholdersAreWorkerBound(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	phA := r.store(t, "pw-a", c)
	if _, err := r.logins.AuthJSON("codex", "pw-b"); err != nil {
		t.Fatal(err)
	}
	b, _ := r.logins.AuthJSON("codex", "pw-b")
	var f struct{ Tokens map[string]string }
	json.Unmarshal(b, &f)
	if f.Tokens["refresh_token"] == phA["refresh_token"] {
		t.Fatal("two workers hold the same placeholder")
	}
	if _, ok := r.logins.Resolve("codex", "pw-a", f.Tokens["refresh_token"]); ok {
		t.Fatal("worker B's placeholder resolves for worker A")
	}
	if v, ok := r.logins.Resolve("codex", "pw-b", f.Tokens["refresh_token"]); !ok || v != c.refresh {
		t.Fatal("worker B's own placeholder does not resolve")
	}
	if _, ok := r.logins.Resolve("codex", "pw-b", phA["refresh_token"]); ok {
		t.Fatal("worker A's placeholder resolves for worker B")
	}
	if _, ok := r.logins.Resolve("codex", "pw-b", ""); ok {
		t.Fatal("empty placeholder resolves")
	}
	r.logins.Forget("pw-b")
	if _, ok := r.logins.Resolve("codex", "pw-b", f.Tokens["refresh_token"]); ok {
		t.Fatal("a forgotten worker's placeholder still resolves")
	}
}

// A locked vault is no plan route: every path refuses with vault-locked.
func TestLockedVaultRefusesWithVaultLocked(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	r.store(t, "pw-a", c)
	r.locked = true
	if _, err := r.logins.AuthJSON("codex", "pw-a"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("AuthJSON = %v", err)
	}
	if _, _, err := r.logins.ForWorker("codex", "pw-a").Swap("codex", c.creds()); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Swap = %v", err)
	}
	if _, err := r.logins.Remove("codex"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Remove = %v", err)
	}
	if _, ok := r.logins.Resolve("codex", "pw-a", "x"); ok {
		t.Fatal("Resolve answered with the vault locked")
	}
	if ErrVaultLocked.Error() != "vault-locked" {
		t.Fatalf("reason = %q", ErrVaultLocked)
	}
}

// W9: removing the plan deletes the entry, drops every placeholder, leaves
// no canary on the drive, and returns where to revoke.
func TestRemovingThePlanLeavesNoEntryAndNoCanary(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	phs := r.store(t, "pw-a", c)
	where, err := r.logins.Remove("codex")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "chatgpt.com") {
		t.Fatalf("revoke location = %q", where)
	}
	if len(r.v.List()) != 0 {
		t.Fatalf("entries left: %v", r.v.List())
	}
	if _, ok := r.logins.Resolve("codex", "pw-a", phs["refresh_token"]); ok {
		t.Fatal("placeholder resolves after removal")
	}
	if _, err := r.logins.AuthJSON("codex", "pw-a"); !errors.Is(err, ErrNoLogin) {
		t.Fatalf("AuthJSON after removal = %v", err)
	}
	for _, s := range append(c.all(), c.account) {
		if hits := r.driveHolds(t, s); len(hits) != 0 {
			t.Fatalf("canary on the drive: %v", hits)
		}
	}
	if _, err := r.logins.Remove("nope"); err == nil {
		t.Fatal("removed an unknown provider")
	}
}

// A response that gives no account ID, with none stored, is not stored.
func TestSwapNeedsAnAccountID(t *testing.T) {
	r := newLoginRig(t)
	bare := map[string]string{"access_token": synthetic(t, "a"), "refresh_token": synthetic(t, "r"), "id_token": fakeJWT(map[string]any{"sub": "x"}) + ".s"}
	if _, _, err := r.logins.ForSignIn("codex", "pw-a").Swap("codex", bare); err == nil {
		t.Fatal("swap accepted a login with no account ID")
	}
	if len(r.v.List()) != 0 {
		t.Fatal("vault written")
	}
	// Error text never echoes a value.
	_, _, err := r.logins.ForSignIn("codex", "pw-a").Swap("codex", bare)
	for _, v := range bare {
		if strings.Contains(err.Error(), v) {
			t.Fatal("error echoes a credential")
		}
	}
}

func authTokens(t *testing.T, b []byte) map[string]string {
	t.Helper()
	var f struct{ Tokens map[string]string }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Tokens
}

// CRED-5: a worker's placeholders stand for login fields, so they outlive a
// refresh. The auth file the CLI already holds keeps working whether or not
// it writes the swapped response back, and a refresh that omits the refresh
// token leaves the old refresh placeholder resolving to the kept token.
func TestRefreshKeepsTheWorkersPlaceholders(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	r.store(t, "pw-a", old)
	file, err := r.logins.AuthJSON("codex", "pw-a")
	if err != nil {
		t.Fatal(err)
	}
	held := authTokens(t, file)

	fresh := newCanaryLogin(t)
	fresh.idToken = old.idToken // same account; no rotated refresh token
	phs, commit, err := r.logins.ForWorker("codex", "pw-a").Swap("codex", map[string]string{"access_token": fresh.access, "id_token": fresh.idToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if phs["access_token"] != held["access_token"] {
		t.Fatal("the refresh handed the worker a placeholder its auth file does not hold")
	}
	if v, ok := r.logins.Resolve("codex", "pw-a", held["access_token"]); !ok || v != fresh.access {
		t.Fatal("the held access placeholder does not resolve to the new access token")
	}
	if v, ok := r.logins.Resolve("codex", "pw-a", held["refresh_token"]); !ok || v != old.refresh {
		t.Fatal("a refresh without a refresh token broke the held refresh placeholder")
	}
	if v := r.entry(t); v["refresh_token"] != old.refresh || v["access_token"] != fresh.access {
		t.Fatal("the vault entry lost a field the refresh did not replace")
	}
}

// A new account (a sign-in to another plan) mints a new id_token
// placeholder: the old one names the old account.
func TestANewAccountMintsNewPlaceholders(t *testing.T) {
	r := newLoginRig(t)
	r.store(t, "pw-a", newCanaryLogin(t))
	before := authTokens(t, must(r.logins.AuthJSON("codex", "pw-a")))
	other := newCanaryLogin(t)
	r.store(t, "pw-a", other)
	after := authTokens(t, must(r.logins.AuthJSON("codex", "pw-a")))
	if after["id_token"] == before["id_token"] || after["account_id"] != other.account {
		t.Fatal("the worker's auth file still names the old account")
	}
	if accountOf(after["id_token"]) != other.account {
		t.Fatal("the id_token placeholder does not carry the new account")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// Threat (power lost between the upstream answer and the vault write): a
// swap whose commit never runs leaves the old login whole in the vault and
// the worker's placeholders on it. The consumed refresh token then fails
// upstream, which the route reports as a refused login (CRED-5b); nothing
// here retries.
func TestUncommittedRefreshLeavesTheOldLoginWhole(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	held := r.store(t, "pw-a", old)
	fresh := newCanaryLogin(t)
	fresh.idToken, fresh.account = old.idToken, old.account
	if _, _, err := r.logins.ForWorker("codex", "pw-a").Swap("codex", fresh.creds()); err != nil {
		t.Fatal(err)
	}
	if v := r.entry(t); v["refresh_token"] != old.refresh || v["access_token"] != old.access {
		t.Fatal("an uncommitted refresh changed the vault entry")
	}
	if v, ok := r.logins.Resolve("codex", "pw-a", held["refresh_token"]); !ok || v != old.refresh {
		t.Fatal("an uncommitted refresh moved the worker's placeholder")
	}
	for _, s := range fresh.all() {
		if hits := r.driveHolds(t, s); len(hits) > 0 {
			t.Fatalf("an uncommitted refresh reached the drive: %v", hits)
		}
	}
}

// The seed lands where the Codex CLI reads its login: CODEX_HOME as
// guest/codex/launch.json sets it.
func TestSeedLandsInCodexHome(t *testing.T) {
	r := newLoginRig(t)
	c := newCanaryLogin(t)
	r.store(t, "pw-a", c)
	seed, err := r.logins.Seed("codex", "pw-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 1 || seed[CodexAuthFile] == nil {
		t.Fatalf("seed paths = %v, want only %s", seed, CodexAuthFile)
	}
	for _, s := range c.all() {
		if bytes.Contains(seed[CodexAuthFile], []byte(s)) {
			t.Fatal("the seed holds a real value")
		}
	}
	b, err := os.ReadFile("../../guest/codex/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	var l struct{ Env []string }
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	want := "CODEX_HOME=/" + filepath.Dir(CodexAuthFile)
	for _, e := range l.Env {
		if e == want {
			return
		}
	}
	t.Fatalf("launch.json env %v lacks %s", l.Env, want)
}

// Threat (Security, #1747): a process in one provider worker signs in to
// its own account through the forwarder. A worker's swap only refreshes
// the stored login: with none stored it cannot create one, and a response
// naming another account cannot replace the owner's, so no other worker's
// placeholder ever resolves to the intruder's tokens.
func TestAWorkerCannotSetThePlanAccount(t *testing.T) {
	r := newLoginRig(t)
	intruder := newCanaryLogin(t)
	if _, _, err := r.logins.ForWorker("codex", "pw-evil").Swap("codex", intruder.creds()); !errors.Is(err, ErrNotRefresh) {
		t.Fatalf("a worker's sign-in with no login stored: err = %v, want ErrNotRefresh", err)
	}
	if len(r.v.List()) != 0 {
		t.Fatal("a worker's sign-in became the box's login")
	}

	owner := newCanaryLogin(t)
	held := r.store(t, "pw-owner", owner)
	if _, _, err := r.logins.ForWorker("codex", "pw-evil").Swap("codex", intruder.creds()); !errors.Is(err, ErrNotRefresh) {
		t.Fatalf("a worker's sign-in to another account: err = %v, want ErrNotRefresh", err)
	}
	if v := r.entry(t); v["account_id"] != owner.account || v["access_token"] != owner.access {
		t.Fatal("a worker replaced the owner's login")
	}
	if v, ok := r.logins.Resolve("codex", "pw-owner", held["access_token"]); !ok || v != owner.access {
		t.Fatal("the owner's worker no longer resolves to the owner's login")
	}
	for _, s := range intruder.all() {
		if strings.Contains(fmt.Sprint(r.entry(t)), s) {
			t.Fatal("the intruder's tokens reached the vault")
		}
	}
}

// Threat (L3, #1747): a worker's response that names no account (no
// id_token) could carry any account's tokens, so it is refused rather than
// filed under the stored account.
func TestAWorkerRefreshMustNameTheAccount(t *testing.T) {
	r := newLoginRig(t)
	owner := newCanaryLogin(t)
	held := r.store(t, "pw-owner", owner)
	intruder := newCanaryLogin(t)
	bare := map[string]string{"access_token": intruder.access, "refresh_token": intruder.refresh}
	if _, _, err := r.logins.ForWorker("codex", "pw-evil").Swap("codex", bare); err == nil {
		t.Fatal("a worker stored tokens that name no account")
	}
	if v := r.entry(t); v["access_token"] != owner.access || v["refresh_token"] != owner.refresh {
		t.Fatal("tokens naming no account replaced the owner's login")
	}
	if v, ok := r.logins.Resolve("codex", "pw-owner", held["access_token"]); !ok || v != owner.access {
		t.Fatal("the owner's worker no longer resolves to the owner's login")
	}
}
