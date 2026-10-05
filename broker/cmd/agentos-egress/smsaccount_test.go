package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/smsapi"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: ADP-12, CRED-1, CRED-7

const ownerNumber = "+15550000999"

var smsSettings = smsapi.Settings{Provider: smsapi.Twilio, Account: "AC" + "0123456789abcdef" + "0123456789abcdef", Number: "+15550000400"}

// noProvider answers every provider call as unreachable, so a send spends
// the budget and goes nowhere.
type noProvider struct{}

func (noProvider) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}

// smsRig is an open vault with the owner's number and both sockets the
// modem bridge uses.
func smsRig(t *testing.T) (*fastRig, *smsapi.Client, *sipsign.Client, string) {
	t.Helper()
	r := openRig(t)
	r.c.owner = ownerNumber
	r.c.smsHTTP = &http.Client{Transport: noProvider{}}
	run := filepath.Join(t.TempDir(), "run")
	sms, err := serveSMS(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	sign, err := serveSign(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sms.Close(); sign.Close() })
	return r, smsapi.NewClient(filepath.Join(run, SMSSocket)), sipsign.NewClient(filepath.Join(run, SignSocket)), run
}

// The HTTP account's token goes into the vault process at setup and stays
// there: its own entry (so the redactor matches it, CRED-7), never
// injectable by the proxy, never overwritten by the credential path, and
// never in the status the local page reads (CRED-1).
func TestTheTextingAccountIsSetUpInTheVault(t *testing.T) {
	r := newFastRig(t, true)
	tok := synthetic(t, "canary-sms-")
	if err := r.c.setSMS(smsSettings, tok); err != errLocked {
		t.Fatalf("set while locked: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if err := r.c.setSMS(smsSettings, tok); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.c.v.Secret(smsapi.TokenName); !ok || s.Reveal() != tok {
		t.Fatal("token not stored as its own entry")
	}
	red, _ := r.c.v.Redactor()
	if got := string(red.Redact([]byte("x " + tok + " y"))); strings.Contains(got, tok) {
		t.Fatal("token not redacted")
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(smsapi.TokenName); ok {
		t.Fatal("the proxy can inject the texting token")
	}
	for _, name := range []string{smsapi.TokenName, smsapi.SettingsName} {
		if err := r.c.put(name, []byte(synthetic(t, "sk-"))); err != errBadCredential {
			t.Fatalf("credential path wrote %s: %v", name, err)
		}
	}
	st, err := r.c.smsStatus()
	if err != nil || !st.Set || st.Settings != smsSettings {
		t.Fatalf("status %+v %v", st, err)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), tok) {
		t.Fatal("status carries the token")
	}
	for _, c := range []struct {
		s    smsapi.Settings
		want error
	}{
		{smsapi.Settings{Provider: "other", Account: smsSettings.Account, Number: smsSettings.Number}, errSMSProvider},
		{smsapi.Settings{Provider: smsapi.SignalWire, Space: "evil.com/x", Account: "01234567-0123-4567-89ab-0123456789ab", Number: smsSettings.Number}, errSMSSpace},
		{smsapi.Settings{Provider: smsapi.Twilio, Account: "AC1", Number: smsSettings.Number}, errSMSAccount},
		{smsapi.Settings{Provider: smsapi.Twilio, Account: smsSettings.Account, Number: "5550000400"}, errSMSNumber},
	} {
		if err := r.c.setSMS(c.s, tok); err != c.want {
			t.Errorf("%+v: %v", c.s, err)
		}
	}
	for _, p := range []string{"", "short-token", strings.Repeat("x", 257), "two words-token"} {
		if err := r.c.setSMS(smsSettings, p); err != errWeakSMSToken {
			t.Errorf("token %q: %v", p, err)
		}
	}
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.removeSMS(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.c.smsStatus(); st.Set {
		t.Fatal("still set after remove")
	}
	if n := len(r.notes); n < 2 || r.notes[n-2] != noteSMSReplaced || r.notes[n-1] != noteSMSRemoved {
		t.Fatalf("owner told %q", r.notes)
	}
}

// Security C1, C5, C6: on sms.sock a locked vault and a missing account
// refuse, the owner's number and the line's own are refused, and another
// uid is never served.
func TestTheBridgeTextsOnlyThroughItsOwnSocket(t *testing.T) {
	r, sms, _, _ := smsRig(t)
	ctx := context.Background()
	if err := sms.Send(ctx, "+15550000777", "hi"); err != smsapi.ErrNoAccount {
		t.Fatalf("no account: %v", err)
	}
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{ownerNumber, smsSettings.Number, sipSettings.Number, "+1555123", "15550000777"} {
		if err := sms.Send(ctx, to, "hi"); err != smsapi.ErrRecipient {
			t.Errorf("to %s: %v", to, err)
		}
	}
	if err := sms.Send(ctx, "+15550000777", "hi"); err != smsapi.ErrUnreachable {
		t.Fatalf("a good send with no provider: %v", err)
	}
	r.c.lock()
	if err := sms.Send(ctx, "+15550000777", "hi"); err != smsapi.ErrLocked {
		t.Fatalf("locked: %v", err)
	}
	if _, err := sms.Poll(ctx); err != smsapi.ErrLocked {
		t.Fatalf("locked poll: %v", err)
	}

	run2 := filepath.Join(t.TempDir(), "run2")
	other, err := serveSMS(run2, r.c, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := smsapi.NewClient(filepath.Join(run2, SMSSocket)).Send(ctx, "+15550000777", "hi"); err != smsapi.ErrUnreachable {
		t.Fatalf("another uid was served: %v", err)
	}
}

// Security Q2 and C1: one budget for the whole line. Texts by SIP MESSAGE
// and over the HTTP account share 30 an hour; calls are held to the same
// recipients but spend nothing.
func TestOneBudgetForTheWholeSecondLine(t *testing.T) {
	r, sms, sign, _ := smsRig(t)
	ctx := context.Background()
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.setSIP(sipSettings, synthetic(t, "canary-sip-")); err != nil {
		t.Fatal(err)
	}
	if _, err := (signStore{r.c}).LearnRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	if err := r.c.confirmRealm(sipRealm); err != nil {
		t.Fatal(err)
	}
	ch := func(method, to string) sipsign.Challenge {
		c := sipChallenge(sipRealm)
		c.Method, c.URI = method, "sip:"+to+"@voip.test"
		return c
	}
	for _, to := range []string{ownerNumber, sipSettings.Number, smsSettings.Number, "+1555123"} {
		for _, m := range []string{"MESSAGE", "INVITE"} {
			if _, err := sign.Sign(ctx, ch(m, to)); !errors.Is(err, sipsign.ErrRecipient) {
				t.Errorf("%s to %s: %v", m, to, err)
			}
		}
	}
	sent := 0
	for i := 0; sent < smsapi.PerHour; i++ {
		to := fmt.Sprintf("+1555070%04d", i)
		if i%2 == 0 {
			if _, err := sign.Sign(ctx, ch("MESSAGE", to)); err != nil {
				t.Fatalf("MESSAGE %d: %v", sent, err)
			}
		} else if err := sms.Send(ctx, to, "hi"); err != smsapi.ErrUnreachable {
			t.Fatalf("text %d: %v", sent, err)
		}
		sent++
	}
	if _, err := sign.Sign(ctx, ch("MESSAGE", "+15550799999")); !errors.Is(err, sipsign.ErrLimited) {
		t.Fatalf("MESSAGE past the cap: %v", err)
	}
	if err := sms.Send(ctx, "+15550799999", "hi"); err != smsapi.ErrLimited {
		t.Fatalf("text past the cap: %v", err)
	}
	if _, err := sign.Sign(ctx, ch("INVITE", "+15550799999")); err != nil {
		t.Fatalf("a call past the texting cap: %v", err)
	}
	r.clk.add(time.Hour)
	if err := sms.Send(ctx, "+15550799999", "hi"); err != smsapi.ErrUnreachable {
		t.Fatalf("an hour later: %v", err)
	}
}

// Security C3: the first poll starts at setup, so the provider's older
// history is never handed on; the mark survives a restart of the vault
// process and a new setup starts it over.
func TestThePollMarkStartsAtSetup(t *testing.T) {
	r, _, _, _ := smsRig(t)
	st := smsStore{r.c}
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	set := r.clk.now().UTC()
	if m, err := st.Mark(); err != nil || !m.Since.Equal(time.Unix(set.Unix(), 0)) || len(m.IDs) != 0 {
		t.Fatalf("first mark %+v %v", m, err)
	}
	later := smsapi.Mark{Since: set.Add(time.Hour), IDs: []string{"SM1"}}
	if err := st.SetMark(later); err != nil {
		t.Fatal(err)
	}
	if m, _ := (smsStore{r.c}).Mark(); !m.Since.Equal(later.Since) || len(m.IDs) != 1 {
		t.Fatalf("kept mark %+v", m)
	}
	r.clk.add(2 * time.Hour)
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	if m, _ := st.Mark(); !m.Since.Equal(time.Unix(r.clk.now().Unix(), 0)) || len(m.IDs) != 0 {
		t.Fatalf("mark after a new setup %+v", m)
	}
}

// Security C4 and C6: the token never appears in a reply on either socket
// or in the log.
func TestTheTextingTokenNeverLeaves(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	r, sms, _, run := smsRig(t)
	ctx := context.Background()
	tok := synthetic(t, "canary-sms-")
	if err := r.c.setSMS(smsSettings, tok); err != nil {
		t.Fatal(err)
	}
	sms.Send(ctx, "+15550000777", "hi")
	sms.Poll(ctx)
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	for _, sock := range []string{SMSSocket, UnlockSocket} {
		hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", filepath.Join(run, sock))
		}}}
		for _, p := range []string{"/send", "/poll", "/second-line/sms/status", "/", "/token"} {
			for _, m := range []string{http.MethodGet, http.MethodPost} {
				req, _ := http.NewRequest(m, "http://agentos-egress"+p, strings.NewReader(`{"to":"+15550000777","text":"hi"}`))
				resp, err := hc.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(b), tok) || strings.Contains(string(b), smsSettings.Account) && p != "/second-line/sms/status" {
					t.Fatalf("%s %s on %s: %s", m, p, sock, b)
				}
			}
		}
	}
	if strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), smsSettings.Account) {
		t.Fatal("the log carries the account or token")
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(smsapi.TokenName); ok || hasKind(r.c.v, smsapi.TokenName, vault.KindAPIKey) {
		t.Fatal("the token is an API key")
	}
}

// stubProvider answers every provider call with status, or as
// unreachable while it is zero.
type stubProvider struct{ status *atomic.Int32 }

func (p stubProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	st := int(p.status.Load())
	if st == 0 {
		return nil, errors.New("no network in tests")
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader(`{"messages":[]}`)), Header: http.Header{}, Request: r}, nil
}

// UX-159-1: when the texting account's polls have failed at the provider
// for five minutes, agentosd learns on the verify socket whether the
// provider refused the account or did not answer; the next good poll,
// a new setup or removal clears it, and it says nothing while locked.
func TestAgentosdLearnsWhenTextsStopArriving(t *testing.T) {
	r := openRig(t)
	r.c.owner = ownerNumber
	var status atomic.Int32
	r.c.smsHTTP = &http.Client{Transport: stubProvider{&status}}
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	sms, err := serveSMS(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sms.Close()
		for _, s := range srvs {
			s.Close()
		}
	})
	bridge := smsapi.NewClient(filepath.Join(run, SMSSocket))
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	ctx := context.Background()
	want := func(step string, s modelroute.TextsState) {
		t.Helper()
		got, err := v.SecondLineTexts(ctx)
		if err != nil || got != s {
			t.Fatalf("%s: %q %v, want %q", step, got, err, s)
		}
	}
	poll := func() {
		r.clk.add(smsapi.MinPollGap)
		bridge.Poll(ctx)
	}
	want("no account", modelroute.TextsOK)
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	poll()
	want("first failure", modelroute.TextsOK)
	r.clk.add(modelroute.TextsQuiet)
	poll()
	want("unreached for five minutes", modelroute.TextsUnreached)
	status.Store(http.StatusUnauthorized)
	poll()
	want("refused", modelroute.TextsSignIn)
	status.Store(http.StatusOK)
	poll()
	want("a good poll", modelroute.TextsOK)
	status.Store(http.StatusUnauthorized)
	poll()
	r.clk.add(modelroute.TextsQuiet)
	poll()
	want("refused again", modelroute.TextsSignIn)
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	want("set up again", modelroute.TextsOK)
	poll()
	r.clk.add(modelroute.TextsQuiet)
	poll()
	r.c.lock()
	if _, err := v.SecondLineTexts(ctx); err != modelroute.ErrVaultLocked {
		t.Fatalf("while locked: %v", err)
	}
}

// endlessPages answers every listing with a full page of new texts and a
// next page, so a poll reads smsapi.MaxPages and stops.
type endlessPages struct{ at time.Time }

func (e endlessPages) RoundTrip(r *http.Request) (*http.Response, error) {
	n, _ := strconv.Atoi(r.URL.Query().Get("Page"))
	var msgs []map[string]string
	for i := 0; i < smsapi.PageSize; i++ {
		msgs = append(msgs, map[string]string{"sid": fmt.Sprintf("SM%d-%d", n, i), "from": "+15550200001", "to": smsSettings.Number,
			"body": "hi", "direction": "inbound", "date_sent": e.at.UTC().Format(time.RFC1123Z)})
	}
	b, _ := json.Marshal(map[string]any{"messages": msgs, "next_page_uri": fmt.Sprintf("/x?Page=%d&PageToken=PT%d", n+1, n+1)})
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}, Request: r}, nil
}

// Security F1 on #159: when a poll stops at its page bound with more to
// read, the owner is told some texts may have been missed.
func TestTheOwnerIsToldWhenTextsMayBeMissed(t *testing.T) {
	r := openRig(t)
	r.c.owner = ownerNumber
	r.c.smsHTTP = &http.Client{Transport: endlessPages{r.clk.now().Add(time.Minute)}}
	var mu sync.Mutex
	var notes []string
	r.c.notify = func(s string) { mu.Lock(); notes = append(notes, s); mu.Unlock() }
	if err := r.c.setSMS(smsSettings, synthetic(t, "canary-sms-")); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(t.TempDir(), "run")
	sms, err := serveSMS(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sms.Close() })
	got, err := smsapi.NewClient(filepath.Join(run, SMSSocket)).Poll(context.Background())
	if err != nil || len(got) != smsapi.MaxPages*smsapi.PageSize {
		t.Fatalf("poll: %d %v", len(got), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notes) != 1 || notes[0] != noteSMSMissed {
		t.Fatalf("owner told %q", notes)
	}
}
