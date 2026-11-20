package inbox

// MUT-kill-inbox-gmail (#6329): Gmail's handling of answers the fake in
// gmailtest does not give (a page token, an id outside Gmail's form, a busy
// or refused call, a read-back for another message), each over a scripted
// fake, so that deleting any statement that reads them fails a test here.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// scriptedGmail is a Gmail over a TLS fake that redeems any refresh grant
// and answers each Gmail request with what route returns. The second result
// lists the Gmail requests made so far, as "METHOD path?query".
func scriptedGmail(t *testing.T, route func(r *http.Request) (int, string)) (*Gmail, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"scripted-access","expires_in":3599,"token_type":"Bearer"}`))
			return
		}
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		code, body := route(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	guard := netguard.New(netguard.Config{Resolver: scriptedResolver{},
		Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}})
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	origin := "https://" + gmailtest.Host + ":" + addr[strings.LastIndex(addr, ":")+1:]
	g, err := OpenGmail(origin+"/gmail/v1/users/me", origin+"/token", gmailtest.Grant(), guard, roots)
	if err != nil {
		t.Fatal(err)
	}
	return g, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(seen) }
}

// scriptedResolver names a public address for every host, as gmailtest's.
type scriptedResolver struct{}

func (scriptedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

const scriptedRoot = "/gmail/v1/users/me"

// scriptedRaw is a get raw answer for id carrying a small mail.
func scriptedRaw(id string) string {
	raw := base64.URLEncoding.EncodeToString([]byte(crlfMail("<"+id+"@x.test>", "a@x.test", "hi")))
	return `{"id":"` + id + `","raw":"` + raw + `"}`
}

// scriptedRead is a Gmail that has read one inbox mail, Gmail id "m1"
// (the clerk's "gmail-m1"); route answers every request but the listing
// and the raw get Read makes.
func scriptedRead(t *testing.T, route func(r *http.Request) (int, string)) (*Gmail, func() []string) {
	t.Helper()
	g, seen := scriptedGmail(t, func(r *http.Request) (int, string) {
		switch {
		case r.URL.Path == scriptedRoot+"/messages" && r.URL.Query().Get("labelIds") == "INBOX":
			return 200, `{"messages":[{"id":"m1"}]}`
		case r.URL.Path == scriptedRoot+"/messages/m1" && r.URL.Query().Get("format") == "raw":
			return 200, scriptedRaw("m1")
		}
		return route(r)
	})
	if ms, err := g.Read(context.Background()); err != nil || len(ms) != 1 || ms[0].ID != "gmail-m1" {
		t.Fatalf("Read = %v, %v", ms, err)
	}
	return g, seen
}

// Read follows the listing's page token to the next page, and reads each
// listed mail once.
func TestGmailReadFollowsThePageToken(t *testing.T) {
	g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == scriptedRoot+"/messages" && !q.Has("pageToken"):
			return 200, `{"messages":[{"id":"m1"}],"nextPageToken":"p2"}`
		case r.URL.Path == scriptedRoot+"/messages" && q.Get("pageToken") == "p2":
			return 200, `{"messages":[{"id":"m2"}]}`
		case strings.HasPrefix(r.URL.Path, scriptedRoot+"/messages/") && q.Get("format") == "raw":
			return 200, scriptedRaw(strings.TrimPrefix(r.URL.Path, scriptedRoot+"/messages/"))
		}
		return 400, ""
	})
	ms, err := g.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range ms {
		ids = append(ids, m.ID)
	}
	if !slices.Equal(ids, []string{"gmail-m1", "gmail-m2"}) {
		t.Fatalf("Read = %v; want both pages' mails once", ids)
	}
}

// Read refuses a listed id outside Gmail's form, and a raw answer that names
// another message, rather than reading either.
func TestGmailReadRefusesABadIDOrAnotherMessage(t *testing.T) {
	for _, tc := range []struct{ listed, answered string }{{"m.1", "m.1"}, {"m1", "m2"}} {
		g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
			if r.URL.Path == scriptedRoot+"/messages" {
				return 200, `{"messages":[{"id":"` + tc.listed + `"}]}`
			}
			return 200, scriptedRaw(tc.answered)
		})
		if ms, err := g.Read(context.Background()); err == nil || ms != nil {
			t.Fatalf("listed %s, answered %s: Read = %v, %v", tc.listed, tc.answered, ms, err)
		}
	}
}

// sizedReader hands out bytes and keeps the size of each read.
type sizedReader struct{ sizes []int }

func (k *sizedReader) Read(b []byte) (int, error) {
	k.sizes = append(k.sizes, len(b))
	return len(b), nil
}

// OpenGmail draws its 32-byte sealing key from crypto/rand before it seals
// the grant; a declaration NewAPI refuses fails the open.
func TestOpenGmailDrawsItsKey(t *testing.T) {
	srv := gmailtest.New()
	defer srv.Close()
	k := &sizedReader{}
	defer func(r io.Reader) { rand.Reader = r }(rand.Reader)
	rand.Reader = k
	if _, err := OpenGmail(srv.Base(), srv.Token(), gmailtest.Grant(), srv.Guard(), srv.Roots()); err != nil {
		t.Fatal(err)
	}
	if len(k.sizes) == 0 || k.sizes[0] != 32 {
		t.Fatalf("OpenGmail read %v random bytes; want its 32-byte key first", k.sizes)
	}
	if g, err := OpenGmail(srv.Base(), srv.Token(), gmailtest.Grant(), nil, srv.Roots()); err == nil || g != nil {
		t.Fatalf("OpenGmail with no home-network policy = %v, %v", g, err)
	}
}

// An answer past a call's bound is an error, even for a call whose body is
// not read (trash) and whatever its read-back shows; for a read mail's
// headers it says so.
func TestGmailAnswerPastItsBoundFails(t *testing.T) {
	big := `{"pad":"` + strings.Repeat("x", gSmallMax) + `"}`
	g, _ := scriptedRead(t, func(r *http.Request) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/trash") {
			return 200, big
		}
		return 200, `{"id":"m1","labelIds":["TRASH"]}`
	})
	if err := g.Trash(context.Background(), "gmail-m1"); err == nil {
		t.Fatal("Trash over an answer past its bound succeeded")
	}
	g, _ = scriptedGmail(t, func(r *http.Request) (int, string) {
		if r.URL.Path == scriptedRoot+"/messages" {
			return 200, `{"messages":[{"id":"m1"}]}`
		}
		return 200, big
	})
	if _, _, err := g.Opened(context.Background(), "2026-10-19", SeenLog{}); err == nil || !strings.Contains(err.Error(), clerk.DTooLarge) {
		t.Fatalf("Opened over headers past their bound: %v", err)
	}
}

// A mail the clerk never read is refused before any request.
func TestGmailUnknownMailMakesNoRequest(t *testing.T) {
	g, seen := scriptedGmail(t, func(*http.Request) (int, string) { return 200, `{}` })
	ctx := context.Background()
	for name, err := range map[string]error{
		"Label":   g.Label(ctx, "gmail-m9", labelPrefix+"x"),
		"Trash":   g.Trash(ctx, "gmail-m9"),
		"Untrash": g.Untrash(ctx, "gmail-m9"),
	} {
		if err != nUnknown {
			t.Errorf("%s of an unknown mail = %v; want %v", name, err, nUnknown)
		}
	}
	if s := seen(); len(s) != 0 {
		t.Fatalf("requests for an unknown mail: %v", s)
	}
}

// A label is listed and created once; later labels use the id kept.
func TestGmailLabelIDIsKept(t *testing.T) {
	name := labelPrefix + "x"
	g, seen := scriptedRead(t, func(r *http.Request) (int, string) {
		switch {
		case r.URL.Path == scriptedRoot+"/labels" && r.Method == "GET":
			return 200, `{"labels":[]}`
		case r.URL.Path == scriptedRoot+"/labels":
			return 200, `{"id":"Label_1","name":"` + name + `","type":"user"}`
		}
		return 200, `{"id":"m1","labelIds":["INBOX","Label_1"]}`
	})
	for range 2 {
		if err := g.Label(context.Background(), "gmail-m1", name); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, s := range seen() {
		if strings.Contains(s, "/labels") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d label requests for two labels; want one list and one create: %v", n, seen())
	}
}

// Each effect's own refusal is its error, whatever the read-back shows: a
// busy label create, label, trash or untrash is busy (nothing was done),
// and an untrash the read-back does not show is unconfirmed.
func TestGmailEffectRefusalsAreTheirOwn(t *testing.T) {
	name := labelPrefix + "x"
	ctx := context.Background()
	for _, tc := range []struct {
		what   string
		busy   string // the path suffix answered 429
		labels string // the read-back's labels
		create bool   // the label is not listed, so it is created
		want   error
		do     func(g *Gmail) error
	}{
		{"label create", "/labels", `["Label_1"]`, true, nBusy, func(g *Gmail) error { return g.Label(ctx, "gmail-m1", name) }},
		{"label", "/modify", `["Label_1"]`, false, nBusy, func(g *Gmail) error { return g.Label(ctx, "gmail-m1", name) }},
		{"trash", "/trash", `["TRASH"]`, false, nBusy, func(g *Gmail) error { return g.Trash(ctx, "gmail-m1") }},
		{"untrash", "/untrash", `["INBOX"]`, false, nBusy, func(g *Gmail) error { return g.Untrash(ctx, "gmail-m1") }},
		{"unconfirmed untrash", "/none", `["TRASH"]`, false, errUnconfirmed, func(g *Gmail) error { return g.Untrash(ctx, "gmail-m1") }},
	} {
		g, _ := scriptedRead(t, func(r *http.Request) (int, string) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, tc.busy):
				return 429, ""
			case r.URL.Path == scriptedRoot+"/labels" && tc.create:
				if r.Method == "GET" {
					return 200, `{"labels":[]}`
				}
				return 200, `{"id":"Label_1","name":"` + name + `","type":"user"}`
			case r.URL.Path == scriptedRoot+"/labels":
				return 200, `{"labels":[{"id":"Label_1","name":"` + name + `","type":"user"}]}`
			case r.Method == "POST":
				return 200, `{}`
			}
			return 200, `{"id":"m1","labelIds":` + tc.labels + `}`
		})
		if err := tc.do(g); !errors.Is(err, tc.want) {
			t.Errorf("%s = %v; want %v", tc.what, err, tc.want)
		}
	}
}

// A refused read-back is the effect's error: not a NotDone, since the effect
// before it may have been made, nor an unconfirmed effect.
func TestGmailRefusedReadBackIsTheError(t *testing.T) {
	name := labelPrefix + "x"
	ctx := context.Background()
	for what, do := range map[string]func(g *Gmail) error{
		"label":   func(g *Gmail) error { return g.Label(ctx, "gmail-m1", name) },
		"trash":   func(g *Gmail) error { return g.Trash(ctx, "gmail-m1") },
		"untrash": func(g *Gmail) error { return g.Untrash(ctx, "gmail-m1") },
	} {
		g, _ := scriptedRead(t, func(r *http.Request) (int, string) {
			switch {
			case r.URL.Path == scriptedRoot+"/labels":
				return 200, `{"labels":[{"id":"Label_1","name":"` + name + `","type":"user"}]}`
			case r.Method == "POST":
				return 200, `{}`
			}
			return 403, ""
		})
		err := do(g)
		if err == nil || errors.As(err, new(NotDone)) || errors.Is(err, errUnconfirmed) || !strings.Contains(err.Error(), "read-back") {
			t.Errorf("%s with its read-back refused = %v; want the read-back's error", what, err)
		}
	}
}

// Owner keeps a busy read's reason, and refuses an answer for another
// message.
func TestGmailOwnerBusyOrAnotherMessage(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
		busy bool
	}{{429, "", true}, {200, `{"id":"m2","labelIds":["INBOX"]}`, false}} {
		g, _ := scriptedGmail(t, func(*http.Request) (int, string) { return tc.code, tc.body })
		got, err := g.Owner(context.Background(), "gmail-m1")
		if err == nil || got != "" || errors.Is(err, nBusy) != tc.busy {
			t.Errorf("Owner over %d %s = %q, %v", tc.code, tc.body, got, err)
		}
	}
}

// Auto-forwarding on to an address the API does not name reads as "?".
func TestGmailDoorsAutoForwardWithoutAnAddress(t *testing.T) {
	g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/autoForwarding") {
			return 200, `{"enabled":true}`
		}
		return 200, `{}`
	})
	d, err := g.Doors(context.Background())
	if err != nil || d.AutoForward != "?" {
		t.Fatalf("Doors = %+v, %v; want auto-forwarding as ?", d, err)
	}
}

// A busy profile read keeps its reason, and a profile with no history id is
// an error.
func TestGmailProfileBusyOrWithoutHistory(t *testing.T) {
	g, _ := scriptedGmail(t, func(*http.Request) (int, string) { return 429, "" })
	if a, err := g.Address(context.Background()); a != "" || !errors.Is(err, nBusy) {
		t.Fatalf("Address over a busy profile = %q, %v", a, err)
	}
	if h, err := g.History(context.Background()); h != "" || !errors.Is(err, nBusy) {
		t.Fatalf("History over a busy profile = %q, %v", h, err)
	}
	g, _ = scriptedGmail(t, func(*http.Request) (int, string) { return 200, `{"emailAddress":"a@x.test"}` })
	if h, err := g.History(context.Background()); h != "" || err == nil {
		t.Fatalf("History of a profile with none = %q, %v", h, err)
	}
}

// Changed: no mark is changed with no request; a mark Gmail has no history
// for is changed with no error; a busy history read keeps its reason.
func TestGmailChangedWithoutHistory(t *testing.T) {
	g, seen := scriptedGmail(t, func(*http.Request) (int, string) { return 404, "" })
	ctx := context.Background()
	if c, err := g.Changed(ctx, ""); !c || err != nil || len(seen()) != 0 {
		t.Fatalf("Changed with no mark = %v, %v, requests %v", c, err, seen())
	}
	if c, err := g.Changed(ctx, "1000"); !c || err != nil {
		t.Fatalf("Changed past Gmail's history = %v, %v", c, err)
	}
	g, _ = scriptedGmail(t, func(*http.Request) (int, string) { return 429, "" })
	if c, err := g.Changed(ctx, "1000"); !c || !errors.Is(err, nBusy) {
		t.Fatalf("Changed over a busy history = %v, %v", c, err)
	}
}

// A metadata answer's header keeps From and Message-ID only, ends with the
// blank line, and an other field across lines is not read.
func TestGmailHeaderKeepsFromAndMessageIDOnly(t *testing.T) {
	var h gHeaders
	for _, f := range [][2]string{{"Subject", "hi"}, {"From", "a@x.test"}, {"X-Bad", "a\r\nb"}, {"message-id", "<1@x.test>"}} {
		h.Payload.Headers = append(h.Payload.Headers, struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}{f[0], f[1]})
	}
	b, _, err := h.header()
	if err != nil || string(b) != "From: a@x.test\r\nmessage-id: <1@x.test>\r\n\r\n" {
		t.Fatalf("header = %q, %v", b, err)
	}
}

// scriptedOpened answers Opened's listing of read mail, in two pages, and
// each mail's metadata; ids are listed as they are.
func scriptedOpened(t *testing.T, pages ...[]string) (*Gmail, func() []string) {
	t.Helper()
	return scriptedGmail(t, func(r *http.Request) (int, string) {
		if r.URL.Path == scriptedRoot+"/messages" {
			n := 0
			fmt.Sscan(r.URL.Query().Get("pageToken"), &n)
			var ms []string
			for _, id := range pages[n] {
				ms = append(ms, `{"id":"`+id+`"}`)
			}
			next := ""
			if n+1 < len(pages) {
				next = fmt.Sprintf(`,"nextPageToken":"%d"`, n+1)
			}
			return 200, `{"messages":[` + strings.Join(ms, ",") + `]` + next + `}`
		}
		id := strings.TrimPrefix(r.URL.Path, scriptedRoot+"/messages/")
		return 200, `{"id":"` + id + `","internalDate":"1790812800000","payload":{"headers":[{"name":"From","value":"` +
			id + `@x.test"},{"name":"Message-ID","value":"<` + id + `@x.test>"}]}}`
	})
}

// Opened follows the read listing's page token.
func TestGmailOpenedFollowsThePageToken(t *testing.T) {
	g, _ := scriptedOpened(t, []string{"m1"}, []string{"m2"})
	got, _, err := g.Opened(context.Background(), "2026-10-19", SeenLog{})
	if err != nil || got["m1@x.test"] == "" || got["m2@x.test"] == "" || len(got) != 2 {
		t.Fatalf("Opened = %v, %v; want both pages' senders", got, err)
	}
}

// Opened refuses a listed id outside Gmail's form.
func TestGmailOpenedRefusesABadID(t *testing.T) {
	g, _ := scriptedOpened(t, []string{"m.1"})
	if got, _, err := g.Opened(context.Background(), "2026-10-19", SeenLog{}); err == nil || got != nil {
		t.Fatalf("Opened over a bad id = %v, %v", got, err)
	}
}

// A log past openedMax fails before any request, and a read that fills
// openedMax fails as too much read mail.
func TestGmailOpenedPastItsBound(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	openedMax = 1
	g, seen := scriptedOpened(t, []string{"m1"})
	old := SeenLog{Since: "2026-01-01", Seen: []Seen{{ID: "x", From: "old@x.test", Date: "2026-01-02"}}}
	if got, _, err := g.Opened(context.Background(), "2026-10-19", old); err == nil || got != nil || len(seen()) != 0 {
		t.Fatalf("Opened over a log past its bound = %v, %v, requests %v", got, err, seen())
	}
	if got, _, err := g.Opened(context.Background(), "2026-10-19", SeenLog{}); !errors.Is(err, ErrTooMuchReadMail) || got != nil {
		t.Fatalf("Opened past its bound = %v, %v", got, err)
	}
}

// scriptedSenders answers SendersStep's listing, pages of ids, and each
// mail's headers: arrival ms[id], From id@x.test, in INBOX; an id ms does
// not name is gone (404).
func scriptedSenders(t *testing.T, ms map[string]uint64, pages ...[]string) *Gmail {
	t.Helper()
	g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
		if r.URL.Path == scriptedRoot+"/messages" {
			n := 0
			fmt.Sscan(r.URL.Query().Get("pageToken"), &n)
			var out []string
			for _, id := range pages[n] {
				out = append(out, `{"id":"`+id+`"}`)
			}
			next := ""
			if n+1 < len(pages) {
				next = fmt.Sprintf(`,"nextPageToken":"%d"`, n+1)
			}
			return 200, `{"messages":[` + strings.Join(out, ",") + `]` + next + `}`
		}
		id := strings.TrimPrefix(r.URL.Path, scriptedRoot+"/messages/")
		at, ok := ms[id]
		if !ok {
			return 404, ""
		}
		if id == "other" {
			id = "m9"
		}
		return 200, fmt.Sprintf(`{"id":"%s","internalDate":"%d","labelIds":["INBOX"],"payload":{"headers":[{"name":"From","value":"%s@x.test"}]}}`, id, at, id)
	})
	return g
}

// SendersStep keeps only Gmail's source, passes over a mail gone before its
// get, records the pass's newest arrival when it ends, and ends its page.
func TestGmailSendersStepRecordsItsPass(t *testing.T) {
	g := scriptedSenders(t, map[string]uint64{"m1": 5000, "m3": 3000}, []string{"m1"}, []string{"m2", "m3"})
	r := SendersRecord{Sources: map[string]SendersSource{"INBOX": {Through: true}}}
	if more, err := g.SendersStep(context.Background(), &r, 1); !more || err != nil {
		t.Fatalf("first step = %v, %v", more, err)
	}
	if _, ok := r.Sources["INBOX"]; ok || r.Sources[gmailSource].Page != "1" {
		t.Fatalf("sources after a step %+v; want Gmail's alone, on its next page", r.Sources)
	}
	if more, err := g.SendersStep(context.Background(), &r, 10); more || err != nil {
		t.Fatalf("second step = %v, %v", more, err)
	}
	src := r.Sources[gmailSource]
	if src != (SendersSource{Through: true, High: 5000}) {
		t.Fatalf("source after the pass %+v; want through, at 5000, with no page", src)
	}
	if r.Senders["m1@x.test"] == 0 || r.Senders["m3@x.test"] == 0 || len(r.Senders) != 2 {
		t.Fatalf("senders %v", r.Senders)
	}
}

// A later pass stops at gmailSlack before the last pass's newest mail, and
// reads no page after it.
func TestGmailSendersStepStopsBeforeTheLastPass(t *testing.T) {
	high := 10 * gmailSlack
	g := scriptedSenders(t, map[string]uint64{"m1": high + 1, "m2": high - gmailSlack - 1, "m3": high + 2},
		[]string{"m1", "m2"}, []string{"m3"})
	r := SendersRecord{Sources: map[string]SendersSource{gmailSource: {Through: true, High: high}}}
	if more, err := g.SendersStep(context.Background(), &r, 10); more || err != nil {
		t.Fatalf("step = %v, %v", more, err)
	}
	if r.Senders["m1@x.test"] == 0 || len(r.Senders) != 1 || r.Sources[gmailSource].Page != "" {
		t.Fatalf("senders %v, source %+v; want the mail before the stop only, the pass ended", r.Senders, r.Sources[gmailSource])
	}
}

// SendersStep refuses an id outside Gmail's form and headers for another
// mail.
func TestGmailSendersStepRefusesABadIDOrAnotherMessage(t *testing.T) {
	for _, id := range []string{"m.1", "other"} {
		g := scriptedSenders(t, map[string]uint64{id: 5000}, []string{id})
		var r SendersRecord
		if more, err := g.SendersStep(context.Background(), &r, 10); more || err == nil {
			t.Fatalf("%s: step = %v, %v", id, more, err)
		}
	}
}

// readMail is one read mail scriptedReadMail lists: its From and
// Message-ID ("" leaves the field out) and its arrival in seconds.
type readMail struct {
	id, from, mid string
	at            int64
}

// scriptedReadMail answers Opened's one page of read mail with mails.
func scriptedReadMail(t *testing.T, mails ...readMail) *Gmail {
	t.Helper()
	g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
		var ids []string
		for _, m := range mails {
			ids = append(ids, `{"id":"`+m.id+`"}`)
			if r.URL.Path != scriptedRoot+"/messages/"+m.id {
				continue
			}
			var hs []string
			if m.from != "" {
				hs = append(hs, `{"name":"From","value":"`+m.from+`"}`)
			}
			if m.mid != "" {
				hs = append(hs, `{"name":"Message-ID","value":"`+m.mid+`"}`)
			}
			return 200, fmt.Sprintf(`{"id":"%s","internalDate":"%d","payload":{"headers":[%s]}}`, m.id, m.at*1000, strings.Join(hs, ","))
		}
		return 200, `{"messages":[` + strings.Join(ids, ",") + `]}`
	})
	return g
}

// A read mail with no From opens no one and is not logged.
func TestGmailOpenedPassesOverAMailWithoutFrom(t *testing.T) {
	g := scriptedReadMail(t, readMail{"m1", "", "<1@x.test>", 1790812800})
	got, kept, err := g.Opened(context.Background(), "2026-10-19", SeenLog{})
	if err != nil || len(got) != 0 || len(kept.Seen) != 0 {
		t.Fatalf("Opened over a mail without From = %v, %+v, %v", got, kept, err)
	}
}

// A read that a sender's charge fills drops what it logged, oldest arrival
// first, until it is back within openedMax: three logged mails fit, a fourth
// sender (on a mail with no Message-ID, so nothing more is logged) does not,
// and the full read hands back the two newest.
func TestGmailOpenedFullDropsTheOldestFirst(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	from := func(i int) string { return fmt.Sprintf("m%d@x.test", i) }
	// Each logged mail is charged its entry and its sender's cost.
	openedMax = 3 * (2*len(from(1)) + entryCost + senderCost)
	for range 20 { // the log is a map: drop order must not hang on it
		mails := []readMail{{"m4", from(4), "", 1790812804}}
		for _, i := range []int{3, 1, 2} {
			mails = append(mails, readMail{fmt.Sprintf("m%d", i), from(i), fmt.Sprintf("<%d@x.test>", i), 1790812800 + int64(i)})
		}
		g := scriptedReadMail(t, append(mails[1:], mails[0])...)
		got, kept, err := g.Opened(context.Background(), "2026-10-19", SeenLog{})
		var froms []string
		for _, s := range kept.Seen {
			froms = append(froms, s.From)
		}
		if !errors.Is(err, ErrTooMuchReadMail) || got != nil || !slices.Equal(froms, []string{from(2), from(3)}) {
			t.Fatalf("full Opened = %v, %v, kept %v; want the two newest kept", got, err, froms)
		}
	}
}

// evict with nothing left to drop stops, whatever it was charged.
func TestOpenedEvictStopsWithNothingToDrop(t *testing.T) {
	o := &opened{kept: openedMax + 1, log: map[[16]byte]logged{}}
	o.evict()
	if o.kept != openedMax+1 {
		t.Fatalf("evict changed the charge to %d", o.kept)
	}
}

// A senders mail with no From counts for no one.
func TestGmailSendersStepPassesOverAMailWithoutFrom(t *testing.T) {
	g, _ := scriptedGmail(t, func(r *http.Request) (int, string) {
		if r.URL.Path == scriptedRoot+"/messages" {
			return 200, `{"messages":[{"id":"m1"}]}`
		}
		return 200, `{"id":"m1","internalDate":"5000","labelIds":["INBOX"],"payload":{"headers":[{"name":"To","value":"a@x.test"}]}}`
	})
	var r SendersRecord
	if more, err := g.SendersStep(context.Background(), &r, 10); more || err != nil || len(r.Senders) != 0 {
		t.Fatalf("step over a mail without From = %v, %v, senders %v", more, err, r.Senders)
	}
}
