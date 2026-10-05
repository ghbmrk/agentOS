package smsapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: ADP-12, CRED-1

const (
	tokenCanary = "canary-sms-token-5d1e7a90"
	twilioSID   = "AC" + "0123456789abcdef" + "0123456789abcdef"
	lineNum     = "+15550104477"
	ownerNum    = "+15550109999"
	shopNum     = "+15550200001"
)

// provider is a fake Twilio-compatible Messages API.
type provider struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	sent     []map[string]string
	inbox    []apiMessage
	status   int  // non-zero: every request answers this
	big      bool // answer with more than MaxResponse bytes
	redirect bool // answer 302 to another host
	hosts    []string
	queries  []string
}

func newProvider(t *testing.T) *provider {
	p := &provider{t: t}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hosts = append(p.hosts, r.Host)
	user, pass, ok := r.BasicAuth()
	if !ok || user != twilioSID || pass != tokenCanary {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"code":20003,"message":"Authenticate %s"}`, tokenCanary)
		return
	}
	switch {
	case p.redirect:
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		return
	case p.big:
		w.Write(bytes.Repeat([]byte("x"), MaxResponse+1))
		return
	case p.status != 0:
		w.WriteHeader(p.status)
		fmt.Fprintf(w, `{"message":"no, %s"}`, tokenCanary)
		return
	}
	if r.URL.Path != "/2010-04-01/Accounts/"+twilioSID+"/Messages.json" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		r.ParseForm()
		p.sent = append(p.sent, map[string]string{"To": r.PostForm.Get("To"), "From": r.PostForm.Get("From"), "Body": r.PostForm.Get("Body")})
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"sid":"SM1"}`))
		return
	}
	p.queries = append(p.queries, r.URL.RawQuery)
	// Pages as the API serves them: Page and a PageToken after the
	// first, and next_page_uri while more remain.
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("Page"))
	if n > 0 && q.Get("PageToken") != "PT"+strconv.Itoa(n) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	lo, hi := min(n*PageSize, len(p.inbox)), min((n+1)*PageSize, len(p.inbox))
	page := map[string]any{"messages": p.inbox[lo:hi]}
	if hi < len(p.inbox) {
		page["next_page_uri"] = fmt.Sprintf("%s?To=x&PageSize=%d&Page=%d&PageToken=PT%d", r.URL.Path, PageSize, n+1, n+1)
	}
	json.NewEncoder(w).Encode(page)
}

func (p *provider) receive(sid, from, to, body string, at time.Time, dir string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Newest first, as the API lists them.
	p.inbox = append([]apiMessage{{SID: sid, From: from, To: to, Body: body, Direction: dir, DateSent: at.Format(time.RFC1123Z)}}, p.inbox...)
}

// client reaches the fake provider for every host, trusting only its
// certificate; everything else is NewHTTPClient's.
func (p *provider) client() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(p.srv.Certificate())
	addr := p.srv.Listener.Addr().String()
	return newHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "example.com"},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		})
}

// memStore is the vault process's side, in memory.
type memStore struct {
	mu     sync.Mutex
	set    Settings
	token  string
	locked bool
	budget Budget
	now    func() time.Time
	mark   Mark
}

func (m *memStore) SMSAccount() (Settings, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.locked:
		return Settings{}, "", ErrLocked
	case m.token == "":
		return Settings{}, "", ErrNoAccount
	}
	return m.set, m.token, nil
}

func (m *memStore) AllowText(to string) error {
	if err := CheckRecipient(to, ownerNum, lineNum); err != nil {
		return err
	}
	return m.budget.Take(to, m.now())
}

func (m *memStore) Mark() (Mark, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.mark, nil }
func (m *memStore) SetMark(k Mark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mark = k
	return nil
}

type rig struct {
	p   *provider
	st  *memStore
	svc *Service
	cl  *Client
	mu  sync.Mutex
	at  time.Time
}

func newRig(t *testing.T) *rig {
	r := &rig{p: newProvider(t), at: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	r.st = &memStore{set: Settings{Provider: Twilio, Account: twilioSID, Number: lineNum}, token: tokenCanary, now: r.now,
		mark: Mark{Since: r.at.Add(-time.Minute)}}
	r.svc = &Service{Store: r.st, HTTP: r.p.client(), Now: r.now}
	// The bridge's side over a real socket.
	dir, err := os.MkdirTemp("", "sms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sms.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: Handler(r.svc)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	r.cl = NewClient(sock)
	return r
}

func (r *rig) now() time.Time          { r.mu.Lock(); defer r.mu.Unlock(); return r.at }
func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.at = r.at.Add(d); r.mu.Unlock() }

// The bridge sends a text through the vault process, which alone holds
// the token: the provider sees the line's own number as From and the
// account's Basic credentials; the bridge chooses only To and the text.
func TestATextGoesOutThroughTheVaultProcess(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.cl.Send(ctx, shopNum, "Table for two at 7?"); err != nil {
		t.Fatal(err)
	}
	if len(r.p.sent) != 1 || r.p.sent[0]["From"] != lineNum || r.p.sent[0]["To"] != shopNum || r.p.sent[0]["Body"] != "Table for two at 7?" {
		t.Fatalf("sent %v", r.p.sent)
	}
	if r.p.hosts[0] != "api.twilio.com" {
		t.Fatalf("host %q", r.p.hosts[0])
	}
}

// Security C1 and C2: the vault process refuses the owner's number, the
// line's own, short or premium codes and anything but E.164, and texts
// over ten segments; none reaches the provider.
func TestRecipientsAndLengthAreTheVaultProcesssRules(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for _, to := range []string{ownerNum, lineNum, "+1234567", "+44123", "15550200001", "sip:+15550200001@x", "", "+1555020000a"} {
		if err := r.cl.Send(ctx, to, "hi"); err != ErrRecipient {
			t.Errorf("to %q: %v", to, err)
		}
	}
	long := strings.Repeat("a", 153*MaxParts+1)
	if err := r.cl.Send(ctx, shopNum, long); err != ErrTooLong {
		t.Fatalf("eleven segments: %v", err)
	}
	if err := r.cl.Send(ctx, shopNum, strings.Repeat("é", 67*MaxParts)); err != nil {
		t.Fatalf("ten UCS-2 segments: %v", err)
	}
	for _, bad := range []string{"", "\xff\xfe"} {
		if err := r.svc.Send(ctx, shopNum, bad); err != ErrTooLong {
			t.Fatalf("text %q: %v", bad, err)
		}
	}
	if len(r.p.sent) != 1 {
		t.Fatalf("%d texts reached the provider", len(r.p.sent))
	}
}

// Security Q2: 10 an hour to one recipient, 30 an hour and 200 a day in
// all.
func TestTheBudgetBoundsTheLine(t *testing.T) {
	var b Budget
	at := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for i := 0; i < PerRecipientHour; i++ {
		if err := b.Take(shopNum, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Take(shopNum, at); err != ErrLimited {
		t.Fatalf("11th to one recipient: %v", err)
	}
	for i := 0; i < PerHour-PerRecipientHour; i++ {
		if err := b.Take(fmt.Sprintf("+1555030%04d", i), at); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Take("+15550399999", at); err != ErrLimited {
		t.Fatalf("31st in an hour: %v", err)
	}
	n := PerHour
	for h := 1; n < PerDay; h++ {
		for i := 0; i < PerHour && n < PerDay; i++ {
			if err := b.Take(fmt.Sprintf("+1555%03d%04d", h, i), at.Add(time.Duration(h)*time.Hour)); err != nil {
				t.Fatalf("text %d: %v", n, err)
			}
			n++
		}
	}
	if err := b.Take("+15559990000", at.Add(23*time.Hour)); err != ErrLimited {
		t.Fatalf("201st in a day: %v", err)
	}
	if err := b.Take("+15559990000", at.Add(24*time.Hour)); err != nil {
		t.Fatalf("a day later: %v", err)
	}
}

// Security C4: the provider's own text, the token and the account never
// reach the bridge or the log; a redirect is not followed and a reply
// over MaxResponse is refused.
func TestProviderRepliesAreFixedCodes(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	type upset struct {
		status        int
		redirect, big bool
		token         string
	}
	for _, c := range []struct {
		up   upset
		want error
	}{
		{upset{status: 400}, ErrRefused},
		{upset{status: 429}, ErrLimited},
		{upset{status: 503}, ErrUnreachable},
		{upset{redirect: true}, ErrUnreachable},
		{upset{big: true}, ErrUnreachable},
		{upset{token: "canary-sms-wrong-0000"}, ErrRefused},
	} {
		r.p.mu.Lock()
		r.p.status, r.p.redirect, r.p.big = c.up.status, c.up.redirect, c.up.big
		r.p.mu.Unlock()
		r.st.mu.Lock()
		r.st.token = tokenCanary
		if c.up.token != "" {
			r.st.token = c.up.token
		}
		r.st.mu.Unlock()
		if err := r.cl.Send(ctx, shopNum, "hi"); err != c.want {
			t.Errorf("%+v send: %v, want %v", c.up, err, c.want)
		}
		r.advance(MinPollGap)
		if _, err := r.cl.Poll(ctx); err != c.want {
			t.Errorf("%+v poll: %v, want %v", c.up, err, c.want)
		}
	}
	if len(r.p.hosts) == 0 || strings.Contains(strings.Join(r.p.hosts, ","), "elsewhere") {
		t.Fatalf("hosts %v", r.p.hosts)
	}
	for _, leak := range []string{tokenCanary, twilioSID} {
		if strings.Contains(logs.String(), leak) {
			t.Fatalf("log carries %q", leak)
		}
	}
}

// Security C3: each inbound text to the line is delivered once, oldest
// first, from a number or a short printable name; outbound messages,
// other numbers' messages and malformed ones are not.
func TestPollsDeliverEachInboundTextOnce(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	t0 := r.at
	r.p.receive("SMa", shopNum, lineNum, "first", t0, "inbound")
	r.p.receive("SMb", "ShopCo", lineNum, "named", t0, "inbound")
	r.p.receive("SMc", shopNum, lineNum, "second", t0.Add(time.Second), "inbound")
	r.p.receive("SMd", lineNum, shopNum, "ours", t0.Add(time.Second), "outbound-api")
	r.p.receive("SMe", shopNum, "+15550300000", "not ours", t0.Add(time.Second), "inbound")
	r.p.receive("SMf", "Shop‮Co", lineNum, "bidi name", t0.Add(time.Second), "inbound")
	r.p.receive("SMg", shopNum, lineNum, strings.Repeat("x", MaxText+1), t0.Add(time.Second), "inbound")
	r.p.receive("SMh", shopNum, lineNum, "old", t0.Add(-2*time.Minute), "inbound")
	got, err := r.cl.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, in := range got {
		texts = append(texts, in.Text)
	}
	if strings.Join(texts, ",") != "first,named,second" {
		t.Fatalf("delivered %q", texts)
	}
	if got[1].From != "ShopCo" || !got[1].Named || got[0].Named {
		t.Fatalf("senders %+v", got)
	}
	if _, err := r.cl.Poll(ctx); err != ErrTooSoon {
		t.Fatalf("a poll within the gap: %v", err)
	}
	r.advance(MinPollGap)
	if again, err := r.cl.Poll(ctx); err != nil || len(again) != 0 {
		t.Fatalf("delivered twice: %+v %v", again, err)
	}
	r.p.receive("SMi", shopNum, lineNum, "third", t0.Add(time.Second), "inbound")
	r.advance(MinPollGap)
	if more, err := r.cl.Poll(ctx); err != nil || len(more) != 1 || more[0].Text != "third" {
		t.Fatalf("a late text in the same second: %+v %v", more, err)
	}
	if q := r.p.queries[0]; !strings.Contains(q, "DateSent%3E=2026-10-05") || !strings.Contains(q, "To=%2B15550104477") {
		t.Fatalf("query %q", q)
	}
}

// Security C5: a locked vault fails sends and polls, and nothing is kept
// to send after the unlock.
func TestALockedVaultSendsNothingLater(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.st.mu.Lock()
	r.st.locked = true
	r.st.mu.Unlock()
	if err := r.cl.Send(ctx, shopNum, "hi"); err != ErrLocked {
		t.Fatalf("send while locked: %v", err)
	}
	if _, err := r.cl.Poll(ctx); err != ErrLocked {
		t.Fatalf("poll while locked: %v", err)
	}
	r.st.mu.Lock()
	r.st.locked = false
	r.st.mu.Unlock()
	r.advance(MinPollGap)
	r.cl.Poll(ctx)
	if len(r.p.sent) != 0 {
		t.Fatal("a send made while locked went out later")
	}
}

// Security Q1: only the closed provider list, with its account shapes.
func TestSettingsAreTheClosedProviderList(t *testing.T) {
	ok := []Settings{
		{Provider: "Twilio", Account: twilioSID, Number: "+1 555 010 4477"},
		{Provider: SignalWire, Space: "My-Space", Account: "0123ABCD-0123-4567-89ab-0123456789ab", Number: lineNum},
		{Provider: SignalWire, Space: "a", Account: "01234567-0123-4567-89ab-0123456789ab", Number: lineNum},
	}
	for _, s := range ok {
		if err := s.Normalize().Check(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	if h := ok[1].Normalize().Host(); h != "my-space.signalwire.com" {
		t.Fatalf("host %q", h)
	}
	if p := ok[1].Normalize().MessagesPath(); p != "/api/laml/2010-04-01/Accounts/0123abcd-0123-4567-89ab-0123456789ab/Messages.json" {
		t.Fatalf("path %q", p)
	}
	sw := func(space string) Settings {
		return Settings{Provider: SignalWire, Space: space, Account: "01234567-0123-4567-89ab-0123456789ab", Number: lineNum}
	}
	for s, want := range map[*Settings]error{
		{Provider: "nexmo", Account: twilioSID, Number: lineNum}:                 ErrProvider,
		{Provider: Twilio, Space: "x", Account: twilioSID, Number: lineNum}:      ErrSpace,
		{Provider: Twilio, Account: "AC0123", Number: lineNum}:                   ErrAccount,
		{Provider: Twilio, Account: strings.ToUpper(twilioSID), Number: lineNum}: ErrAccount,
		{Provider: Twilio, Account: twilioSID, Number: "5550104477"}:             ErrNumber,
		ptr(sw("evil.com/x")):            ErrSpace,
		ptr(sw("a.b")):                   ErrSpace,
		ptr(sw("-a")):                    ErrSpace,
		ptr(sw("a-")):                    ErrSpace,
		ptr(sw("")):                      ErrSpace,
		ptr(sw(strings.Repeat("a", 64))): ErrSpace,
		ptr(sw("a@b")):                   ErrSpace,
		{Provider: SignalWire, Space: "a", Account: twilioSID, Number: lineNum}: ErrAccount,
	} {
		if err := s.Normalize().Check(); !errors.Is(err, want) || !errors.Is(err, ErrSettings) {
			t.Errorf("%+v: %v, want %v", *s, err, want)
		}
	}
}

func ptr(s Settings) *Settings { return &s }

// UX-159-1: the vault process hears each poll's outcome at the provider,
// so failing polls can reach STATUS; polls that never reach the provider
// are not reported.
func TestPollOutcomesAreReported(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var mu sync.Mutex
	var heard []error
	r.svc.Polled = func(err error) { mu.Lock(); heard = append(heard, err); mu.Unlock() }
	r.cl.Poll(ctx)
	r.cl.Poll(ctx) // too soon: not reported
	for _, st := range []int{401, 503} {
		r.p.mu.Lock()
		r.p.status = st
		r.p.mu.Unlock()
		r.advance(MinPollGap)
		r.cl.Poll(ctx)
	}
	r.st.mu.Lock()
	r.st.locked = true
	r.st.mu.Unlock()
	r.advance(MinPollGap)
	r.cl.Poll(ctx) // locked: not reported
	mu.Lock()
	defer mu.Unlock()
	if len(heard) != 3 || heard[0] != nil || heard[1] != ErrRefused || heard[2] != ErrUnreachable {
		t.Fatalf("heard %v", heard)
	}
}

// Security F1 on #159: a burst of texts between polls is read page by
// page on the fixed path, each delivered once, oldest first; a full page
// of the longest texts fits the reply cap; past MaxPages the older texts
// are passed over and the owner is told.
func TestABurstOfTextsIsReadPageByPage(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var missed int
	r.svc.Missed = func() { missed++ }
	t0 := r.at
	for i := 0; i < 120; i++ {
		r.p.receive(fmt.Sprintf("SM%03d", i), shopNum, lineNum, fmt.Sprintf("t%03d", i), t0.Add(time.Duration(i)*time.Second), "inbound")
	}
	got, err := r.cl.Poll(ctx)
	if err != nil || len(got) != 120 {
		t.Fatalf("burst: %d %v", len(got), err)
	}
	for i, in := range got {
		if in.Text != fmt.Sprintf("t%03d", i) {
			t.Fatalf("order at %d: %q", i, in.Text)
		}
	}
	r.advance(MinPollGap)
	if again, err := r.cl.Poll(ctx); err != nil || len(again) != 0 {
		t.Fatalf("delivered twice: %d %v", len(again), err)
	}
	for _, q := range r.p.queries {
		if strings.Contains(q, "elsewhere") || strings.Contains(q, "To=x") {
			t.Fatalf("followed the provider's URI: %q", q)
		}
	}

	// A full page of the longest texts, every byte escaped in the JSON
	// ("<" is sent as \u003c), far past the old 64 KiB cap.
	r = newRig(t)
	long := strings.Repeat("<", MaxText)
	for i := 0; i < PageSize; i++ {
		r.p.receive(fmt.Sprintf("SL%03d", i), shopNum, lineNum, long, t0.Add(time.Duration(i)*time.Second), "inbound")
	}
	if got, err := r.cl.Poll(ctx); err != nil || len(got) != PageSize {
		t.Fatalf("long page: %d %v", len(got), err)
	}

	// More than MaxPages pages: the newest are delivered, the mark moves
	// past them, and the owner is told some may be missed.
	r = newRig(t)
	r.svc.Missed = func() { missed++ }
	total := (MaxPages + 1) * PageSize
	for i := 0; i < total; i++ {
		r.p.receive(fmt.Sprintf("SB%04d", i), shopNum, lineNum, fmt.Sprintf("b%04d", i), t0.Add(time.Duration(i)*time.Second), "inbound")
	}
	got, err = r.cl.Poll(ctx)
	if err != nil || len(got) != MaxPages*PageSize || missed != 1 || got[len(got)-1].Text != fmt.Sprintf("b%04d", total-1) {
		t.Fatalf("past the bound: %d %v missed=%d", len(got), err, missed)
	}
	r.advance(MinPollGap)
	if again, err := r.cl.Poll(ctx); err != nil || len(again) != 0 || missed != 1 {
		t.Fatalf("after the bound: %d %v missed=%d", len(again), err, missed)
	}
}
