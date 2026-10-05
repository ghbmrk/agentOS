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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
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
	// delay holds each answer back, outside mu; endless streams a body
	// without end; overfull answers that many messages on one page.
	delay    time.Duration
	endless  bool
	overfull int
	inflight atomic.Int32
	most     atomic.Int32
}

func newProvider(t *testing.T) *provider {
	p := &provider{t: t}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) serve(w http.ResponseWriter, r *http.Request) {
	if n := p.inflight.Add(1); n > p.most.Load() {
		p.most.Store(n)
	}
	defer p.inflight.Add(-1)
	p.mu.Lock()
	d, endless := p.delay, p.endless
	p.mu.Unlock()
	time.Sleep(d)
	if endless {
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
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
	if p.overfull > 0 {
		json.NewEncoder(w).Encode(map[string]any{"messages": p.inbox[:p.overfull]})
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
	// gen is the setup generation; failMark makes SetMark fail.
	gen      uint64
	failMark bool
	// allowErr, when set, is what AllowText returns.
	allowErr error
	budget   Budget
	now      func() time.Time
	mark     Mark
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
	m.mu.Lock()
	ae := m.allowErr
	m.mu.Unlock()
	if ae != nil {
		return ae
	}
	if err := CheckRecipient(to, ownerNum, lineNum); err != nil {
		return err
	}
	return m.budget.Take(to, m.now())
}

func (m *memStore) Mark() (Mark, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mark, m.gen, nil
}

func (m *memStore) SetMark(k Mark, gen uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failMark || gen != m.gen {
		return errors.New("mark not kept")
	}
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

// L3 MUST-1 on #159: national and international-prefix forms of a number
// match it; other numbers and short forms do not.
func TestSameNumberCatchesNationalForms(t *testing.T) {
	for _, c := range []struct {
		dialed, number string
		want           bool
	}{
		{"15550109999", "+15550109999", true},
		{"5550109999", "+15550109999", true},
		{"0115550109999", "+15550109999", true},
		{"07700900123", "+447700900123", true},
		{"00447700900123", "+447700900123", true},
		{"5550109998", "+15550109999", false},
		{"0109999", "+15550109999", false},
		{"447700900124", "+447700900123", false},
	} {
		if got := SameNumber(c.dialed, c.number); got != c.want {
			t.Errorf("%s vs %s: %v", c.dialed, c.number, got)
		}
	}
}

// L3 on #159: polls run one at a time, so a slow poll cannot write its
// mark over a later one's.
func TestPollsRunOneAtATime(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.p.mu.Lock()
	r.p.delay = 100 * time.Millisecond
	r.p.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.svc.Poll(ctx) }()
		time.Sleep(20 * time.Millisecond)
		r.advance(MinPollGap)
	}
	wg.Wait()
	if n := r.p.most.Load(); n != 1 {
		t.Fatalf("%d polls at the provider at once", n)
	}
}

// L3 on #159 (surviving mutants): each inbound check, the page cap, the
// reply cap, a lost mark and an unknown refusal, each held by a test.
func TestEachInboundCheckHolds(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	t0 := r.at
	cjk := strings.Repeat("字", 670) // 10 segments, but 2010 bytes
	r.p.receive("SMo", shopNum, lineNum, "outbound", t0, "outbound-api")
	r.p.receive("SMc", shopNum, lineNum, cjk, t0, "inbound")
	r.p.receive("SMk", shopNum, lineNum, "kept", t0, "inbound")
	if n, _ := modem.Segments(cjk); n > MaxParts {
		t.Fatalf("the CJK text takes %d segments", n)
	}
	got, err := r.cl.Poll(ctx)
	if err != nil || len(got) != 1 || got[0].Text != "kept" {
		t.Fatalf("delivered %+v %v", got, err)
	}

	// Invalid UTF-8 cannot come through JSON, so fresh is held directly.
	at := t0.Add(time.Minute).Format(time.RFC1123Z)
	in, _ := fresh([]apiMessage{{SID: "SMu", From: shopNum, To: lineNum, Body: "a\xffb", Direction: "inbound", DateSent: at}}, Mark{Since: t0}, lineNum)
	if len(in) != 0 {
		t.Fatalf("invalid UTF-8 delivered: %+v", in)
	}

	// A page longer than PageSize is cut to it.
	r = newRig(t)
	for i := 0; i < PageSize+10; i++ {
		r.p.receive(fmt.Sprintf("SO%03d", i), shopNum, lineNum, "x", t0.Add(time.Duration(i)*time.Second), "inbound")
	}
	r.p.mu.Lock()
	r.p.overfull = PageSize + 10
	r.p.mu.Unlock()
	if got, err := r.cl.Poll(ctx); err != nil || len(got) != PageSize {
		t.Fatalf("overfull page: %d %v", len(got), err)
	}

	// A mark that cannot be kept delivers nothing; the next poll does.
	r = newRig(t)
	r.p.receive("SMm", shopNum, lineNum, "once", t0, "inbound")
	r.st.mu.Lock()
	r.st.failMark = true
	r.st.mu.Unlock()
	if got, err := r.cl.Poll(ctx); err != ErrUnreachable || len(got) != 0 {
		t.Fatalf("lost mark: %+v %v", got, err)
	}
	r.st.mu.Lock()
	r.st.failMark = false
	r.st.mu.Unlock()
	r.advance(MinPollGap)
	if got, err := r.cl.Poll(ctx); err != nil || len(got) != 1 {
		t.Fatalf("after the lost mark: %+v %v", got, err)
	}

	// A reply without end is cut at MaxResponse, not read to the
	// client's timeout.
	r.p.mu.Lock()
	r.p.endless = true
	r.p.mu.Unlock()
	r.advance(MinPollGap)
	start := time.Now()
	if _, err := r.cl.Poll(ctx); err != ErrUnreachable || time.Since(start) > 5*time.Second {
		t.Fatalf("endless reply: %v after %v", err, time.Since(start))
	}
}

// The production client is TLS 1.2 or later, with no proxy and no
// redirects followed.
func TestTheProductionClientIsPinned(t *testing.T) {
	c := NewHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.Proxy != nil || tr.TLSClientConfig.RootCAs != nil {
		t.Fatalf("transport %+v", tr)
	}
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse || c.Timeout == 0 {
		t.Fatal("redirects or timeout")
	}
}

// A refusal the socket has no code for goes out as "unreachable", never
// as its own text.
func TestUnknownRefusalsAreUnreachable(t *testing.T) {
	r := newRig(t)
	r.st.mu.Lock()
	r.st.allowErr = errors.New("detail-canary-7f3a")
	r.st.mu.Unlock()
	w := httptest.NewRecorder()
	Handler(r.svc).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(`{"to":"+15550200001","text":"hi"}`)))
	if b := w.Body.String(); w.Code != http.StatusConflict || !strings.Contains(b, `"unreachable"`) || strings.Contains(b, "detail-canary") {
		t.Fatalf("%d %s", w.Code, b)
	}
	// A request past the socket's limit is refused unread.
	w = httptest.NewRecorder()
	big := `{"to":"+15550200001","text":"` + strings.Repeat("x", 8<<10) + `"}`
	Handler(r.svc).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(big)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized request: %d %s", w.Code, w.Body.String())
	}
}

// Security F1 on #159: only the expected page number and a short
// printable token are taken from the provider's next_page_uri.
func TestOnlyTheNextPageIsAskedFor(t *testing.T) {
	for _, c := range []struct {
		uri  string
		want bool
	}{
		{"/x?Page=1&PageToken=PASM1", true},
		{"https://elsewhere.example/x?Page=1&PageToken=PASM1", true}, // the host is never used
		{"/x?Page=5&PageToken=PASM1", false},
		{"/x?Page=1", false},
		{"/x?Page=1&PageToken=" + strings.Repeat("a", 129), false},
		{"/x?Page=1&PageToken=a%20b", false},
		{"", false},
	} {
		tok, ok := nextPage(c.uri, 1)
		if ok != c.want || ok && tok != "PASM1" {
			t.Errorf("%q: %q %v", c.uri, tok, ok)
		}
	}
}

// SR2-5 (ADP-12: "a short or premium-rate code needs an owner-created
// contact"): premium-rate numbers are refused like short codes.
func TestPremiumRateNumbersAreRefused(t *testing.T) {
	for _, n := range []string{"+19005550123", "+19765550123", "+449098790123", "+448712345678", "+499001234567", "+491371234567", "+33899123456", "+61190012345"} {
		if !Premium(n) {
			t.Errorf("%s is premium-rate", n)
		}
		if err := CheckRecipient(n, ownerNum, lineNum); err != ErrRecipient {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{shopNum, "+447700900123", "+4930123456", "+33612345678", "+61212345678", "+18005550123"} {
		if Premium(n) {
			t.Errorf("%s is not premium-rate", n)
		}
	}
}

// SR2-5 (L3 SHOULD-1 on #159): a call spends the line's one budget like a
// text, and calls have a lower cap of their own.
func TestCallsSpendTheBudgetAndHaveTheirOwnCap(t *testing.T) {
	var b Budget
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < CallsPerHour; i++ {
		if err := b.TakeCall(fmt.Sprintf("+1555070%04d", i), now); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := b.TakeCall("+15550799999", now); err != ErrLimited {
		t.Fatalf("call past the cap: %v", err)
	}
	for i := CallsPerHour; i < PerHour; i++ {
		if err := b.Take(fmt.Sprintf("+1555070%04d", i), now); err != nil {
			t.Fatalf("text %d: %v", i, err)
		}
	}
	if err := b.Take("+15550799999", now); err != ErrLimited {
		t.Fatalf("calls and texts share the hour: %v", err)
	}
	// Calls to one number share its hourly cap with texts.
	var c Budget
	for i := 0; i < PerRecipientHour; i++ {
		if err := c.TakeCall(shopNum, now.Add(time.Duration(i)*7*time.Hour)); err != nil {
			t.Fatalf("spread call %d: %v", i, err)
		}
	}
	var d Budget
	for i := 0; i < PerRecipientHour-1; i++ {
		d.Take(shopNum, now)
	}
	if err := d.TakeCall(shopNum, now); err != nil {
		t.Fatal(err)
	}
	if err := d.TakeCall(shopNum, now); err != ErrLimited {
		t.Fatalf("per recipient: %v", err)
	}
	// The daily call cap.
	var e Budget
	for i := 0; i < CallsPerDay; i++ {
		if err := e.TakeCall(fmt.Sprintf("+1555080%04d", i), now.Add(time.Duration(i)*20*time.Minute)); err != nil {
			t.Fatalf("day call %d: %v", i, err)
		}
	}
	if err := e.TakeCall("+15550899999", now.Add(CallsPerDay*20*time.Minute)); err != ErrLimited {
		t.Fatalf("call past the day: %v", err)
	}
}
