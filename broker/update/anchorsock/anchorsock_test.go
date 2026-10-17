package anchorsock

// REQ: SR3-6f-2c, SR3-6-f5b
// The client maps the vault process's answers: a count, no TPM
// (update.ErrNoAnchor), a locked vault, a missing counter, a counter on a
// chip this PC lacks (SR3-6-f5b), and anything else as an error the store
// fails closed on.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ghbmrk/agentos/broker/update"
)

func TestSocketAnchorAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		answer string // the Anchor-Answer header
		body   string
		want   uint64
		err    error // nil: no error; a sentinel errors.Is matches; errAny: some other error
	}{
		{"count", 200, "", `{"anchored":true,"count":3}`, 3, nil},
		{"zero", 200, "", `{"anchored":true}`, 0, nil},
		{"no TPM", 200, "", `{"anchored":false}`, 0, update.ErrNoAnchor},
		{"missing", 409, AnswerMissing, "anchor missing", 0, update.ErrAnchorMissing},
		{"elsewhere", 409, AnswerElsewhere, "anchor elsewhere", 0, update.ErrAnchorElsewhere},
		{"conflict unnamed", 409, "", "anchor missing", 0, errAny},
		{"conflict unknown", 409, "synthetic", "anchor missing", 0, errAny},
		{"locked", 503, "", "the vault is locked", 0, update.ErrAnchorLocked},
		{"malformed", 200, "", `{"anchored":`, 0, errAny},
		{"count without anchor", 200, "", `{"anchored":false,"count":1}`, 0, errAny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raised int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == AnchorPath:
				case r.Method == http.MethodPost && r.URL.Path == AnchorRaisePath:
					raised++
				default:
					http.Error(w, "no", http.StatusMethodNotAllowed)
					return
				}
				if tc.answer != "" {
					w.Header().Set(AnswerHeader, tc.answer)
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			a := NewAnchorClient(&http.Client{Transport: rewrite{srv.URL}})
			n, err := a.Read()
			checkAnchorErr(t, "Read", err, tc.err)
			if err == nil && n != tc.want {
				t.Fatalf("Read = %d, want %d", n, tc.want)
			}
			checkAnchorErr(t, "Raise", a.Raise(), tc.err)
			if raised != 1 {
				t.Fatalf("Raise sent %d requests", raised)
			}
		})
	}
}

func TestSocketAnchorDownIsAnError(t *testing.T) {
	a := NewSocketAnchor(t.TempDir() + "/none.sock")
	if _, err := a.Read(); err == nil || errors.Is(err, update.ErrNoAnchor) {
		t.Fatalf("Read with the vault process down = %v; want an error, not update.ErrNoAnchor", err)
	}
}

var errAny = errors.New("any error but update.ErrNoAnchor")

func checkAnchorErr(t *testing.T, op string, got, want error) {
	t.Helper()
	typed := []error{update.ErrNoAnchor, update.ErrAnchorLocked, update.ErrAnchorMissing, update.ErrAnchorElsewhere}
	switch {
	case want == nil && got != nil, want != nil && want != errAny && !errors.Is(got, want):
		t.Fatalf("%s = %v, want %v", op, got, want)
	case want == errAny && got == nil:
		t.Fatalf("%s = nil, want an error", op)
	}
	for _, e := range typed {
		if e != want && errors.Is(got, e) {
			t.Fatalf("%s = %v, which is also %v", op, got, e)
		}
	}
}

// rewrite sends every request to the test server.
type rewrite struct{ base string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := req.URL.Parse(r.base + req.URL.Path)
	req = req.Clone(req.Context())
	req.URL, req.Host = u, u.Host
	return http.DefaultTransport.RoundTrip(req)
}
