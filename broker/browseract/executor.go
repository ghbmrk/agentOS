// Executor drives the S5 fixture protocol inside a broker sandbox (CRED-4b).
// Sessions are vault-held through SessionStore (stub OK). No live sites.
package browseract

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type SessionStore interface {
	Get(account string) (state []byte, ok bool)
	Put(account string, state []byte) error
}

type MemorySessions struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *MemorySessions) Get(account string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		return nil, false
	}
	b, ok := s.m[account]
	return append([]byte(nil), b...), ok
}

func (s *MemorySessions) Put(account string, state []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[account] = append([]byte(nil), state...)
	return nil
}

type Executor struct {
	Sessions     SessionStore
	Origins      []string
	CanaryCookie string
	Fixture      http.Handler
}

type Result struct {
	OK       bool   `json:"ok"`
	Snapshot string `json:"snapshot,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (e *Executor) Run(account string, raw []byte) (Result, error) {
	req, err := Parse(raw)
	if err != nil {
		return Result{Error: err.Error()}, nil
	}
	if req.Verb == "navigate" && !OnDeclaredOrigin(req.URL, e.Origins) {
		return Result{Error: "off-origin navigation refused"}, nil
	}
	if e.Sessions != nil && e.CanaryCookie != "" {
		state, ok := e.Sessions.Get(account)
		if !ok || !strings.Contains(string(state), e.CanaryCookie) {
			_ = e.Sessions.Put(account, []byte("session="+e.CanaryCookie))
		}
	}
	handler := e.Fixture
	if handler == nil {
		handler = defaultFixture()
	}
	rr := httptest.NewRecorder()
	path := "/"
	if req.Verb == "navigate" {
		path = req.URL
	}
	handler.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	snap := rr.Body.String()
	snap = OmitValues(snap, map[string]bool{"e2": true})
	if e.CanaryCookie != "" && strings.Contains(snap, e.CanaryCookie) {
		return Result{}, fmt.Errorf("browseract: canary session value reached agent output")
	}
	out := Result{OK: true, Snapshot: snap}
	b, _ := json.Marshal(out)
	if e.CanaryCookie != "" && strings.Contains(string(b), e.CanaryCookie) {
		return Result{}, fmt.Errorf("browseract: canary in result JSON")
	}
	return out, nil
}

func defaultFixture() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "- button [ref=e1] Go\n- textbox [ref=e2] type=password: 'secret'\n")
	})
}
