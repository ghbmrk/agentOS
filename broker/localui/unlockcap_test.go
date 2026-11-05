package localui

// REQ: CH-9

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// bodyMeter yields limit bytes of filler and counts how many were read.
type bodyMeter struct{ n, limit int64 }

func (m *bodyMeter) Read(p []byte) (int, error) {
	if m.n >= m.limit {
		return 0, io.EOF
	}
	if int64(len(p)) > m.limit-m.n {
		p = p[:m.limit-m.n]
	}
	for i := range p {
		p[i] = 'a'
	}
	m.n += int64(len(p))
	return len(p), nil
}

const unlockCap = 16 << 10

// #5017: /unlock caps its body at 16 KiB before any form parse, by GET and
// by POST. A multipart body with a 64 MiB file part was read in full and
// spooled to disk before sign-in.
func TestUnlockReadsNoMoreThanItsCap(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	for _, method := range []string{"GET", "POST"} {
		m := &bodyMeter{limit: 64 << 20}
		body := io.MultiReader(strings.NewReader("--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n"),
			m, strings.NewReader("\r\n--B--\r\n"))
		r.do(method, "/unlock", nil, func(q *http.Request) {
			q.Body, q.ContentLength = io.NopCloser(body), -1
			q.Header.Set("Content-Type", "multipart/form-data; boundary=B")
		})
		if m.n > unlockCap {
			t.Errorf("%s multipart: read %d bytes, cap %d", method, m.n, unlockCap)
		}
	}
	// An oversized urlencoded form is refused even with a valid code.
	m := &bodyMeter{limit: 32 << 20}
	form := url.Values{"code": {r.code()}, "next": {"/approvals/"}}.Encode() + "&pad="
	w := r.do("POST", "/unlock", nil, func(q *http.Request) {
		q.Body, q.ContentLength = io.NopCloser(io.MultiReader(strings.NewReader(form), m)), -1
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if m.n > unlockCap {
		t.Errorf("urlencoded: read %d bytes, cap %d", m.n, unlockCap)
	}
	if w.Code != http.StatusBadRequest || w.Body.String() != "Bad request\n" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("oversized sign-in not refused: %d %q %v", w.Code, w.Body.String(), w.Result().Cookies())
	}
	// next still comes from the URL on GET and from the form on POST.
	if !strings.Contains(r.get("/unlock?next=/approvals/"), `name="next" value="/approvals/"`) {
		t.Fatal("GET lost next")
	}
	if w := r.post("/unlock", url.Values{"code": {r.code()}, "next": {"/approvals/"}}); w.Header().Get("Location") != "/approvals/" {
		t.Fatalf("sign-in under the cap: %d %s", w.Code, w.Header().Get("Location"))
	}
}
