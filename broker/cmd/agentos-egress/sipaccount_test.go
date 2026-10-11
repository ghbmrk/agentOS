package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, ADP-12, CRED-7, CH-12

var sipSettings = sipsign.Settings{Server: "sip.voip.test:5061", Domain: "voip.test", User: "acct1001", Number: "+15550000300"}

const sipRealm = "voip.test realm"

func sipChallenge(realm string) sipsign.Challenge {
	return sipsign.Challenge{Header: fmt.Sprintf(`Digest realm=%q, nonce="abc", qop="auth", algorithm=MD5`, realm), Method: "REGISTER", URI: "sip:voip.test"}
}

func openRig(t *testing.T) *fastRig {
	t.Helper()
	r := newFastRig(t, true)
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	return r
}

// The account password goes into the vault process at setup and stays
// there: it is its own vault entry (so the redactor matches it, CRED-7),
// the proxy cannot inject it upstream, the local UI's credential path
// cannot overwrite it, and the status the local page reads never carries
// it (CRED-1).
func TestTheCallingAccountIsSetUpInTheVault(t *testing.T) {
	r := newFastRig(t, true)
	pw := synthetic(t, "canary-sip-")
	if err := r.c.setSIP(sipSettings, pw); err != errLocked {
		t.Fatalf("set while locked: %v", err)
	}
	tk := r.unlock(t)
	if err := r.c.setSIP(sipSettings, pw); err != errLocked {
		t.Fatalf("set while pending: %v", err)
	}
	r.c.confirm(tk, r.code())
	if err := r.c.setSIP(sipSettings, pw); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.c.v.Secret(sipsign.PasswordName); !ok || s.Reveal() != pw {
		t.Fatal("password not stored as its own entry")
	}
	red, _ := r.c.v.Redactor()
	if got := string(red.Redact([]byte("x " + pw + " y"))); strings.Contains(got, pw) {
		t.Fatal("password not redacted")
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(sipsign.PasswordName); ok {
		t.Fatal("the proxy can inject the SIP password")
	}
	for _, name := range []string{sipsign.PasswordName, sipsign.SettingsName} {
		if err := r.c.put(name, []byte(synthetic(t, "sk-"))); err != errBadCredential {
			t.Fatalf("credential path wrote %s: %v", name, err)
		}
	}
	st, err := r.c.sipStatus()
	if err != nil || !st.Set || st.Settings != sipSettings || st.RealmRecorded || !st.WaitingForRegistration {
		t.Fatalf("status %+v, %v", st, err)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), pw) {
		t.Fatal("status carries the password")
	}

	// Refused settings and weak passwords change nothing.
	bad := sipSettings
	bad.User = "a@evil.test"
	if err := r.c.setSIP(bad, synthetic(t, "canary-sip-")); err != errSIPUser {
		t.Fatalf("bad settings: %v", err)
	}
	for _, p := range []string{"", "short-pw", strings.Repeat("x", 257), "bad\npassword-x"} {
		if err := r.c.setSIP(sipSettings, p); err != errWeakSIPPassword {
			t.Fatalf("password %q: %v", p, err)
		}
	}
	if s, _ := r.c.v.Secret(sipsign.PasswordName); s.Reveal() != pw {
		t.Fatal("a refused setup changed the password")
	}

	// An entry of another kind under the account's names is not replaced.
	if err := r.c.removeSIP(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.c.sipStatus(); st.Set {
		t.Fatal("still set after remove")
	}
	if err := r.c.v.Put(sipsign.PasswordName, vault.KindAPIKey, []byte(synthetic(t, "sk-"))); err != nil {
		t.Fatal(err)
	}
	if err := r.c.setSIP(sipSettings, pw); err != errSIPOtherKind {
		t.Fatalf("over another kind: %v", err)
	}
}

// The sign socket answers for the account only while the vault is open,
// records the realm from the first registration within the setup window
// (SL3), and refuses every other realm after that.
func TestTheSignSocketSignsOnlyForTheRecordedRealm(t *testing.T) {
	r := openRig(t)
	st := signStore{r.c}
	if _, _, err := st.Account(); !errors.Is(err, sipsign.ErrNoAccount) {
		t.Fatalf("no account: %v", err)
	}
	pw := synthetic(t, "canary-sip-")
	if err := r.c.setSIP(sipSettings, pw); err != nil {
		t.Fatal(err)
	}
	s, a, err := st.Account()
	if err != nil || s != sipSettings || a.Username != sipSettings.User || a.Password != pw || a.Realm != "" {
		t.Fatalf("account %v %v %v", s, a, err)
	}
	if _, err := st.LearnRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LearnRealm("other realm"); !errors.Is(err, sipsign.ErrRealm) {
		t.Fatalf("second realm: %v", err)
	}
	if _, a, _ := st.Account(); a.Realm != sipRealm {
		t.Fatalf("realm %q", a.Realm)
	}
	if s, _ := r.c.sipStatus(); !s.RealmRecorded || s.WaitingForRegistration {
		t.Fatalf("status after registration %+v", s)
	}

	// Setting up again (a new password) reopens the window.
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	r.clk.add(RealmWindow + time.Second)
	if _, err := st.LearnRealm(sipRealm); !errors.Is(err, sipsign.ErrRealm) {
		t.Fatalf("learned after the window: %v", err)
	}
	if s, _ := r.c.sipStatus(); s.WaitingForRegistration {
		t.Fatal("still waiting after the window")
	}

	// Locked: nothing is signed or read.
	r.c.lock()
	if _, _, err := st.Account(); !errors.Is(err, sipsign.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if _, err := st.LearnRealm(sipRealm); !errors.Is(err, sipsign.ErrLocked) {
		t.Fatalf("learn while locked: %v", err)
	}
}

// End to end over the sockets: the local UI sets the account up on the
// unlock socket, and the modem bridge reads the settings and signs on
// sign.sock, which admits only its uid.
func TestTheModemBridgeSignsOnItsOwnSocket(t *testing.T) {
	r := openRig(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	sign, err := serveSign(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sign.Close() })
	if fi, err := os.Stat(filepath.Join(run, SignSocket)); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("sign socket: %v", err)
	}

	ui := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", filepath.Join(run, UnlockSocket))
	}}}
	post := func(path, body string) (int, string) {
		resp, err := ui.Post("http://agentos-egress"+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	pw := synthetic(t, "canary-sip-")
	body, _ := json.Marshal(map[string]any{"server": sipSettings.Server, "domain": sipSettings.Domain, "user": sipSettings.User,
		"number": sipSettings.Number, "password": pw})
	if code, msg := post("/second-line", string(body)); code != http.StatusNoContent {
		t.Fatalf("setup: %d %s", code, msg)
	}
	if code, msg := post("/second-line", `{"server":"x","password":"`+pw+`"}`); code != http.StatusBadRequest || strings.Contains(msg, pw) {
		t.Fatalf("bad setup: %d %s", code, msg)
	}
	resp, err := ui.Get("http://agentos-egress/second-line/status")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(b), pw) || !strings.Contains(string(b), `"waiting_for_registration":true`) {
		t.Fatalf("status: %d %s", resp.StatusCode, b)
	}

	c := sipsign.NewClient(filepath.Join(run, SignSocket))
	ctx := context.Background()
	if s, err := c.Settings(ctx); err != nil || s != sipSettings {
		t.Fatalf("settings %v %v", s, err)
	}
	auth, err := c.Sign(ctx, sipChallenge(sipRealm))
	if err != nil || !strings.Contains(auth, `realm="voip.test realm"`) {
		t.Fatalf("first registration: %q %v", auth, err)
	}
	if _, err := c.Sign(ctx, sipChallenge("mail.example")); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("other realm: %v", err)
	}

	if code, _ := post("/second-line/remove", `{}`); code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	if _, err := c.Settings(ctx); !errors.Is(err, sipsign.ErrNoAccount) {
		t.Fatalf("after remove: %v", err)
	}

	// Another uid is closed unread.
	run2 := filepath.Join(t.TempDir(), "run2")
	other, err := serveSign(run2, r.c, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := sipsign.NewClient(filepath.Join(run2, SignSocket)).Settings(ctx); !errors.Is(err, sipsign.ErrDown) {
		t.Fatal("another uid was served")
	}
}

// UX-116-1: each refused field gets one fixed reason, and no reason
// carries what was entered.
func TestSetupRefusalsNameTheFieldAndNeverEchoTheValue(t *testing.T) {
	r := openRig(t)
	canary := synthetic(t, "canaryvalue")
	for want, f := range map[*unlockErr]func(*sipsign.Settings){
		errSIPServer: func(s *sipsign.Settings) { s.Server = canary + " x:5061" },
		errSIPDomain: func(s *sipsign.Settings) { s.Domain = canary + "@x" },
		errSIPUser:   func(s *sipsign.Settings) { s.User = canary + ";x" },
		errSIPNumber: func(s *sipsign.Settings) { s.Number = canary },
	} {
		s := sipSettings
		f(&s)
		err := r.c.setSIP(s, synthetic(t, "canary-sip-"))
		if err != want {
			t.Errorf("%q: got %v", want.msg, err)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("reason echoes the value: %q", err)
		}
	}
	pw := synthetic(t, "x")[:8]
	if err := r.c.setSIP(sipSettings, pw); err != errWeakSIPPassword || strings.Contains(err.Error(), pw) {
		t.Fatalf("short password: %v", err)
	}
	// A number typed with spaces and a server without its port are
	// filled in, not refused (UX R1).
	typed := sipSettings
	typed.Server, typed.Number = "sip.voip.test", "+1 555 000 0300"
	if err := r.c.setSIP(typed, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.c.sipStatus(); st.Settings != sipSettings {
		t.Fatalf("normalized to %+v", st.Settings)
	}
}

// The owner hears when the account is replaced or removed (S2 on #116);
// a first setup is the owner's own act on the page and says nothing.
func TestTheOwnerIsToldWhenTheAccountChanges(t *testing.T) {
	r := openRig(t)
	n := len(r.notes)
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if len(r.notes) != n {
		t.Fatalf("first setup noted: %q", r.notes[n:])
	}
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.removeSIP(); err != nil {
		t.Fatal(err)
	}
	if err := r.c.removeSIP(); err != nil {
		t.Fatal(err)
	}
	if got := r.notes[n:]; len(got) != 2 || got[0] != noteSIPReplaced || got[1] != noteSIPRemoved {
		t.Fatalf("notes %q", got)
	}
	// CH-12, CH-21: owner texts name "my Wi-Fi page".
	for _, s := range []string{noteSIPReplaced, noteSIPRemoved} {
		if !strings.HasSuffix(s, " on my Wi-Fi page.") {
			t.Errorf("note %q", s)
		}
	}
}

// Security R1 on #116: the recorded realm signs only REGISTER until the
// owner confirms it on the local page; a wrong realm confirms nothing.
func TestTextsAndCallsWaitForTheOwnerToConfirmTheRealm(t *testing.T) {
	r := openRig(t)
	st := signStore{r.c}
	if err := r.c.confirmRealm(sipRealm); err != errSIPRealm {
		t.Fatalf("confirmed with no account: %v", err)
	}
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.confirmRealm(""); err != errSIPRealm {
		t.Fatalf("confirmed before registration: %v", err)
	}
	a, err := st.LearnRealm(sipRealm)
	if err != nil || !a.RegisterOnly {
		t.Fatalf("learned %v %v", a, err)
	}
	msg := sipChallenge(sipRealm)
	msg.Method = "MESSAGE"
	if _, a, _ := st.Account(); !a.RegisterOnly {
		t.Fatal("unconfirmed realm signs everything")
	} else if _, err := a.Sign(context.Background(), msg); !errors.Is(err, sipsign.ErrMethod) {
		t.Fatalf("text signed before confirmation: %v", err)
	}
	if s, _ := r.c.sipStatus(); s.Realm != sipRealm || s.RealmConfirmed {
		t.Fatalf("status %+v", s)
	}
	if err := r.c.confirmRealm("other realm"); err != errSIPRealm {
		t.Fatalf("wrong realm confirmed: %v", err)
	}
	if err := r.c.confirmRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	if _, a, _ := st.Account(); a.RegisterOnly {
		t.Fatal("still register-only after confirmation")
	} else if _, err := a.Sign(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.c.sipStatus(); !s.RealmConfirmed {
		t.Fatalf("status %+v", s)
	}
	// Setting up again starts over.
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.c.sipStatus(); s.RealmRecorded || s.RealmConfirmed {
		t.Fatalf("status after a new setup %+v", s)
	}
}

// CRED-1 (MUST 1 on #116): the modem bridge's uid must be its own, so the
// sign socket can never be reached by this process, agentosd or the local
// UI.
func TestTheModemUIDMustBeTheBridgesOwn(t *testing.T) {
	self := os.Getuid()
	broker, ui := self+1, self+2
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.json")
	if err := os.WriteFile(rule, []byte(`{"default":[{"provider":"openai","model":"gpt-test"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The socket directory's parent is a file, so a guard that let a uid
	// through fails at serve with another error instead of serving.
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(modem int, owner ...string) error {
		if owner == nil {
			owner = []string{"-owner-number", "+15550000999"}
		}
		return serveCmd(append(owner, "-rule", rule, "-broker-uid", fmt.Sprint(broker), "-unlock-uid", fmt.Sprint(ui), "-modem-uid", fmt.Sprint(modem),
			"-run", filepath.Join(dir, "file", "run"), "-vault", filepath.Join(dir, "vault"), "-keys", filepath.Join(dir, "vault.keys"),
			"-tpm", filepath.Join(dir, "no-tpm")))
	}
	for _, m := range []int{self, broker, ui} {
		if err := run(m); err == nil || !strings.Contains(err.Error(), "-modem-uid") {
			t.Errorf("modem uid %d: %v", m, err)
		}
	}
	if err := run(self + 3); err == nil || strings.Contains(err.Error(), "-modem-uid") {
		t.Fatalf("a distinct modem uid: %v", err)
	}
	// Security C1 on the #142 design read: the second line needs the
	// owner's number, which it never texts or calls.
	for _, o := range [][]string{{}, {"-owner-number", "07700900123"}, {"-owner-number", "+1234"}} {
		if err := run(self+3, o...); err == nil || !strings.Contains(err.Error(), "-owner-number") {
			t.Errorf("owner %v: %v", o, err)
		}
	}
}

// Potency R1 on #139: agentosd learns, on the verify socket, when the
// second line waits on the owner (a realm to confirm) or never reached
// its provider, so STATUS and the digest can say so. It learns nothing
// else about the account.
func TestAgentosdLearnsWhenTheSecondLineWaitsOnTheOwner(t *testing.T) {
	r := newFastRig(t, true)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	ctx := context.Background()
	if _, err := v.SecondLine(ctx); err != modelroute.ErrVaultLocked {
		t.Fatalf("while locked: %v", err)
	}
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	want := func(step string, s modelroute.SecondLineState) {
		t.Helper()
		got, err := v.SecondLine(ctx)
		if err != nil || got != s {
			t.Fatalf("%s: %q %v, want %q", step, got, err, s)
		}
	}
	want("no account", modelroute.SecondLineOK)
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	want("waiting for registration", modelroute.SecondLineOK)
	r.clk.add(RealmWindow)
	want("window passed", modelroute.SecondLineUnreached)
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if _, err := (signStore{r.c}).LearnRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	want("realm recorded", modelroute.SecondLineConfirm)
	r.clk.add(RealmWindow)
	want("realm still unconfirmed", modelroute.SecondLineConfirm)
	if err := r.c.confirmRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	want("confirmed", modelroute.SecondLineOK)
}
