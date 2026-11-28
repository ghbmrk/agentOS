package localui

// REQ: OSS-10, CH-7
//
// MUT-kill-localui-7 (#6771): tests that fail when a statement of
// setuphooks.go or follow.go that mutgate saw survive is deleted.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// mut7Owner records each call and answers it with answer (nil: a nil error).
type mut7Owner struct {
	mu     sync.Mutex
	ops    []string
	ctxs   []context.Context
	answer func(n int, op string, args, out any) error
}

func (o *mut7Owner) Call(ctx context.Context, op string, args, out any) error {
	o.mu.Lock()
	o.ops = append(o.ops, op)
	o.ctxs = append(o.ctxs, ctx)
	n, f := len(o.ops), o.answer
	o.mu.Unlock()
	if f == nil {
		return nil
	}
	return f(n, op, args, out)
}

func (o *mut7Owner) count(op string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, x := range o.ops {
		if x == op {
			n++
		}
	}
	return n
}

func (o *mut7Owner) ctx(i int) context.Context {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ctxs[i]
}

// mut7Vault is HostTrust keeping the context it was called with.
type mut7Vault struct{ ctx context.Context }

func (v *mut7Vault) SetupTrust(ctx context.Context, _ bool) (string, error) {
	v.ctx = ctx
	return "pc", nil
}

func TestMut7EnrollRefusalsAreNamed(t *testing.T) {
	for code, want := range map[string]error{
		localapi.ErrEnrolled:          ErrCodesEnrolled,
		localapi.ErrNoEnrollment:      ErrNoCodeEnrollment,
		localapi.ErrLimited:           ErrCodesLimited,
		localapi.ErrEnrollUnavailable: ErrCodesUnavailable,
	} {
		o := &mut7Owner{answer: func(_ int, _ string, _, out any) error {
			if c, ok := out.(*localapi.Confirmed); ok {
				c.OK = true // a refusal's answer is never read
			}
			return Refused(code)
		}}
		ok, err := AgentosdSetup{Owner: o}.ConfirmCode("123456")
		if ok || !errors.Is(err, want) {
			t.Fatalf("%s: ConfirmCode = %v, %v; want false, %v", code, ok, err, want)
		}
		if _, err := (AgentosdSetup{Owner: o}).EnrollCode(); !errors.Is(err, want) {
			t.Fatalf("%s: EnrollCode = %v; want %v", code, err, want)
		}
	}
}

func TestMut7SetupCallsReleaseTheirContext(t *testing.T) {
	o := &mut7Owner{}
	a := AgentosdSetup{Owner: o}
	if err := a.ConnectAPIKey("anthropic", "sk-synthetic-canary"); err != nil {
		t.Fatal(err)
	}
	if err := a.Send("+15550000001", "hello"); err != nil {
		t.Fatal(err)
	}
	for i, op := range []string{"ConnectAPIKey", "Send"} {
		if o.ctx(i).Err() != context.Canceled {
			t.Fatalf("%s's context after it returned: %v", op, o.ctx(i).Err())
		}
	}
	v := &mut7Vault{}
	if err := (AgentosdSetup{Owner: o, Vault: v}).TrustHost(true); err != nil {
		t.Fatal(err)
	}
	if v.ctx == nil || v.ctx.Err() != context.Canceled {
		t.Fatalf("TrustHost's context after it returned: %v", v.ctx)
	}
}

func mut7Write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMut7HostInfoReadsTheRootFileSystemByDefault(t *testing.T) {
	if _, err := os.ReadFile("/proc/meminfo"); err != nil {
		t.Skip("no /proc/meminfo here")
	}
	// A working directory holding its own sys and proc: Root "" must not
	// read them as paths relative to it.
	dir := t.TempDir()
	mut7Write(t, filepath.Join(dir, "sys/class/dmi/id/sys_vendor"), "Mut7Vendor\n")
	mut7Write(t, filepath.Join(dir, "sys/class/dmi/id/product_name"), "Mut7Product\n")
	mut7Write(t, filepath.Join(dir, "proc/meminfo"), "MemTotal: 1 kB\n")
	if got := (AgentosdSetup{Root: dir}).HostInfo(); got != "Mut7Vendor Mut7Product, 1 GB" {
		t.Fatalf("HostInfo at the rig's root: %q", got)
	}
	t.Chdir(dir)
	got, want := AgentosdSetup{}.HostInfo(), (AgentosdSetup{Root: "/"}).HostInfo()
	if got != want || strings.Contains(got, "Mut7") || !strings.HasSuffix(got, " GB") {
		t.Fatalf("HostInfo with Root unset: %q; at /: %q", got, want)
	}
}

func TestMut7MemGBReadsOnlyMemTotal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "meminfo")
	mut7Write(t, p, "MemFree: 1 kB\nMemTotal: 16000000 kB\n")
	if got := memGB(p); got != 16 {
		t.Fatalf("memGB past another line: %d", got)
	}
	mut7Write(t, p, "MemTotal: 99999999999999999999999 kB\n")
	if got := memGB(p); got != 0 {
		t.Fatalf("memGB of a MemTotal past uint64: %d", got)
	}
}

func TestMut7MemGBClosesTheFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/self/fd")
	}
	p := filepath.Join(t.TempDir(), "meminfo-mut7")
	mut7Write(t, p, "MemTotal: 2000000 kB\n")
	if got := memGB(p); got != 2 {
		t.Fatalf("memGB = %d", got)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	for _, fd := range fds {
		if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); l == p {
			t.Fatalf("memGB left %s open as fd %s", p, fd.Name())
		}
	}
}

func TestMut7BoxNumberWithoutAPhoneNumberTexts(t *testing.T) {
	o := &mut7Owner{answer: func(_ int, _ string, _, out any) error {
		*out.(*localapi.SetupLine) = localapi.SetupLine{Ready: true, Number: "not-a-number"}
		return nil
	}}
	if n, ok := (AgentosdSetup{Owner: o}).BoxNumber(); n != "" || !ok {
		t.Fatalf("BoxNumber = %q, %v; want \"\", true", n, ok)
	}
}

// mut7PairServer is a setup page whose clock counts its reads: OfferText
// reads it first, so an unchanged count means no text was offered.
func mut7PairServer(t *testing.T) (*Server, *atomic.Int64) {
	t.Helper()
	var reads atomic.Int64
	s, err := New(Config{Page: testPage(), Hooks: AgentosdSetup{Owner: InProcess{}}, Store: &MemStore{},
		Now: func() time.Time { reads.Add(1); return time.Now() }})
	if err != nil {
		t.Fatal(err)
	}
	return s, &reads
}

func TestMut7PairTextsSkipsAnEmptyAnswerAndReleasesEachCall(t *testing.T) {
	s, reads := mut7PairServer(t)
	o := &mut7Owner{answer: func(n int, _ string, _, _ any) error {
		if n < 3 {
			return nil // no text came in
		}
		return Refused(localapi.ErrSetupClosed)
	}}
	before := reads.Load()
	AgentosdSetup{Owner: o}.PairTexts(context.Background(), s, time.Hour)
	if got := o.count(localapi.OpSetupInbound); got != 3 {
		t.Fatalf("inbound calls: %d", got)
	}
	if reads.Load() != before {
		t.Fatal("an empty inbound answer was offered as a text")
	}
	for i := 0; i < 3; i++ {
		if o.ctx(i).Err() != context.Canceled {
			t.Fatalf("inbound call %d's context after it returned: %v", i, o.ctx(i).Err())
		}
	}
}

func TestMut7PairTextsRetriesAFailedCallAfterRetry(t *testing.T) {
	s, reads := mut7PairServer(t)
	o := &mut7Owner{answer: func(n int, _ string, _, _ any) error {
		if n == 1 {
			return errors.New("agentosd is restarting")
		}
		return Refused(localapi.ErrSetupClosed)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	before := reads.Load()
	start := time.Now()
	AgentosdSetup{Owner: o}.PairTexts(ctx, s, time.Millisecond)
	if el := time.Since(start); el > 3*time.Second || o.count(localapi.OpSetupInbound) != 2 {
		t.Fatalf("after %v, %d inbound calls; want a second call after retry", el, o.count(localapi.OpSetupInbound))
	}
	if reads.Load() != before {
		t.Fatal("a failed call's answer was offered as a text")
	}
}

func TestMut7PairTextsWaitsOutRetryUntilItsContextEnds(t *testing.T) {
	s, _ := mut7PairServer(t)
	o := &mut7Owner{answer: func(n int, _ string, _, _ any) error {
		if n == 1 {
			return errors.New("agentosd is restarting")
		}
		return Refused(localapi.ErrSetupClosed)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	AgentosdSetup{Owner: o}.PairTexts(ctx, s, 4*time.Second)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("PairTexts returned %v after its context ended", el)
	}
	if got := o.count(localapi.OpSetupInbound); got != 1 {
		t.Fatalf("inbound calls before retry passed: %d", got)
	}
}

func TestMut7SendTwiceStopsWhenItsContextEnds(t *testing.T) {
	o := &mut7Owner{answer: func(int, string, any, any) error { return errors.New("the bridge is down") }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	AgentosdSetup{Owner: o}.sendTwice(ctx, "+15550000001", "reply", 4*time.Second)
	if el := time.Since(start); el > 2*time.Second || o.count(localapi.OpSetupSend) != 1 {
		t.Fatalf("after %v, %d sends; want one, at once", el, o.count(localapi.OpSetupSend))
	}
}

// The Update source page, served straight to its handler (sign-in is the
// mount's, which these tests leave out).

const mut7Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mut7Summary(out any, ids ...string) {
	*out.(*localapi.RootSummary) = localapi.RootSummary{Version: 2, Digest: mut7Digest,
		Keys: map[string][]string{"root": ids}, Thresholds: map[string]int{"root": 1}}
}

// mut7FollowServer is a page on owner o (nil: no owner yet).
func mut7FollowServer(t *testing.T, o Owner) *Server {
	t.Helper()
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		s.SetOwner(o)
	}
	return s
}

func mut7Serve(s *Server, path, ctype, body string) *httptest.ResponseRecorder {
	method := http.MethodGet
	if ctype != "" {
		method = http.MethodPost
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	s.follow(w, r)
	return w
}

// mut7Part is one raw multipart part named name.
func mut7Part(name, headers, body string) string {
	return "--B\r\nContent-Disposition: form-data; name=\"" + name + "\"; filename=\"root.json\"\r\n" + headers + "\r\n" + body + "\r\n"
}

const mut7Root = `{"signed":{"version":2}}`

func mut7Upload(t *testing.T, s *Server, body string) string {
	t.Helper()
	w := mut7Serve(s, "/", "multipart/form-data; boundary=B", body)
	if w.Code != 200 {
		t.Fatalf("upload: %d", w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

func mut7ShowsAskForm(page string) bool { return strings.Contains(page, `name="digest"`) }

func TestMut7FollowServesOnlyItsRootWithAnOwner(t *testing.T) {
	if w := mut7Serve(mut7FollowServer(t, &mut7Owner{}), "/other", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("another path: %d", w.Code)
	}
	w := mut7Serve(mut7FollowServer(t, nil), "/", "", "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/status" {
		t.Fatalf("no owner yet: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestMut7FollowSendsAnUnknownSessionToUnlock(t *testing.T) {
	o := &mut7Owner{answer: func(int, string, any, any) error { return Refused(localapi.ErrUnauthorized) }}
	s := mut7FollowServer(t, o)
	w := mut7Serve(s, "/", "multipart/form-data; boundary=B", mut7Part("root", "", mut7Root)+"--B--\r\n")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock?next=/follow/" {
		t.Fatalf("show with an unknown session: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = mut7Serve(s, "/", "application/x-www-form-urlencoded", mut7Ask(s, "Fork", "").Encode())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock?next=/follow/" {
		t.Fatalf("ask with an unknown session: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestMut7FollowRefusesUploadsItCannotRead(t *testing.T) {
	o := &mut7Owner{answer: func(_ int, _ string, _, out any) error { mut7Summary(out, "k1"); return nil }}
	s := mut7FollowServer(t, o)
	for _, c := range []struct{ name, ctype, body string }{
		{"no boundary", "multipart/form-data", mut7Part("root", "", mut7Root) + "--B--\r\n"},
		{"past the body limit", "multipart/form-data; boundary=B",
			mut7Part("pad", "", strings.Repeat("x", (localapi.MaxRootChain+2)*localapi.MaxRoot)) + mut7Part("root", "", mut7Root) + "--B--\r\n"},
		{"a malformed part after a root", "multipart/form-data; boundary=B",
			mut7Part("root", "", mut7Root) + "--B\r\nno colon here\r\n\r\nx\r\n--B--\r\n"},
		// A quoted-printable root that does not decode, then one too big:
		// the first failure is the answer.
		{"a root that does not decode", "multipart/form-data; boundary=B",
			mut7Part("root", "Content-Transfer-Encoding: quoted-printable\r\n", "\x00"+mut7Root) +
				mut7Part("root", "", strings.Repeat("y", localapi.MaxRoot+1)) + "--B--\r\n"},
	} {
		w := mut7Serve(s, "/", c.ctype, c.body)
		page := html.UnescapeString(w.Body.String())
		if w.Code != 200 || !strings.Contains(page, rootUnreadText) || mut7ShowsAskForm(page) {
			t.Fatalf("%s: %d %s", c.name, w.Code, page)
		}
	}
	if n := o.count(localapi.OpFollowRoot); n != 0 {
		t.Fatalf("%d unreadable uploads were sent to agentosd", n)
	}
	page := mut7Upload(t, s, mut7Part("other", "", mut7Root)+"--B--\r\n")
	if !strings.Contains(page, "Choose the source's root file first.") || o.count(localapi.OpFollowRoot) != 0 {
		t.Fatalf("no root part: %s", page)
	}
	// The rig's own check: the same root, read, is shown.
	if page := mut7Upload(t, s, mut7Part("root", "", mut7Root)+"--B--\r\n"); !mut7ShowsAskForm(page) {
		t.Fatalf("a readable root: %s", page)
	}
}

func TestMut7FollowShowsNoRootItWasRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		ref  string
		want string
	}{
		{"follow off", Refused(localapi.ErrFailed), "", followOffText},
		{"agentosd unreachable", errors.New("no socket"), "", followUnreachable},
		{"a refused root", nil, localapi.RootExpired, rootExpiredText},
	} {
		o := &mut7Owner{answer: func(_ int, _ string, _, out any) error {
			mut7Summary(out, "k1")
			out.(*localapi.RootSummary).Refusal, out.(*localapi.RootSummary).Reason = c.ref, c.ref
			return c.err
		}}
		page := mut7Upload(t, mut7FollowServer(t, o), mut7Part("root", "", mut7Root)+"--B--\r\n")
		if !strings.Contains(page, c.want) || mut7ShowsAskForm(page) {
			t.Fatalf("%s: %s", c.name, page)
		}
	}
}

func TestMut7FollowMarksAnOddRootKey(t *testing.T) {
	const odd = "A key has an unusual character"
	for _, ids := range [][]string{{"ké", "k2"}, {"k1", "ké"}} {
		o := &mut7Owner{answer: func(_ int, _ string, _, out any) error { mut7Summary(out, ids...); return nil }}
		if page := mut7Upload(t, mut7FollowServer(t, o), mut7Part("root", "", mut7Root)+"--B--\r\n"); !strings.Contains(page, odd) {
			t.Fatalf("keys %q: %s", ids, page)
		}
	}
	o := &mut7Owner{answer: func(_ int, _ string, _, out any) error { mut7Summary(out, "k1"); return nil }}
	if page := mut7Upload(t, mut7FollowServer(t, o), mut7Part("root", "", mut7Root)+"--B--\r\n"); strings.Contains(page, odd) {
		t.Fatalf("plain keys: %s", page)
	}
}

// mut7Ask is the ask form for mut7Digest under name, bound to the page's
// session (no cookie), with an extra pad field.
func mut7Ask(s *Server, name, pad string) url.Values {
	v := url.Values{"step": {"ask"}, "digest": {mut7Digest}, "name": {name},
		"tok": {s.followToken(tokenKey(""), mut7Digest, false)}}
	if pad != "" {
		v.Set("pad", pad)
	}
	return v
}

func mut7AskPage(t *testing.T, s *Server, v url.Values) string {
	t.Helper()
	w := mut7Serve(s, "/", "application/x-www-form-urlencoded", v.Encode())
	if w.Code != 200 {
		t.Fatalf("ask: %d", w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

func TestMut7FollowAskRefusesBeforeAsking(t *testing.T) {
	o := &mut7Owner{answer: func(_ int, _ string, _, out any) error {
		out.(*localapi.Text).Text = "Asked. Approve it on the Approvals page."
		return nil
	}}
	s := mut7FollowServer(t, o)
	if page := mut7AskPage(t, s, mut7Ask(s, "Fork", strings.Repeat("p", 16<<10))); !strings.Contains(page, followStale) {
		t.Fatalf("an ask past 16 KiB: %s", page)
	}
	long := strings.Repeat("a", localapi.MaxFollowName+1)
	if page := mut7AskPage(t, s, mut7Ask(s, long, "")); !strings.Contains(page, fmt.Sprintf("Use a name of at most %d characters.", localapi.MaxFollowName/4)) {
		t.Fatalf("a name past the limit: %s", page)
	}
	if n := o.count(localapi.OpFollow); n != 0 {
		t.Fatalf("%d refused asks reached agentosd", n)
	}
	// The rig's own check: the same ask, in bounds, is asked.
	if page := mut7AskPage(t, s, mut7Ask(s, "Fork", "short")); !strings.Contains(page, "Asked. Approve it") || o.count(localapi.OpFollow) != 1 {
		t.Fatalf("an ask in bounds: %s", page)
	}
}

func TestMut7FollowAskNamesEachRefusal(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{Refused(localapi.ErrFailed), followOffText},
		{Refused(localapi.ErrBadArgs), followStale},
		{errors.New("no socket"), followUnreachable},
	} {
		o := &mut7Owner{answer: func(int, string, any, any) error { return c.err }}
		s := mut7FollowServer(t, o)
		if page := mut7AskPage(t, s, mut7Ask(s, "Fork", "")); !strings.Contains(page, `class="err"`) || !strings.Contains(page, c.want) {
			t.Fatalf("%v: %s", c.err, page)
		}
	}
}
