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

	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, ADP-12, CRED-7

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
	if err := r.c.setSIP(bad, synthetic(t, "canary-sip-")); err != errBadSIP {
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
	if err := r.c.setSIP(sipSettings, pw); err != errBadSIP {
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
