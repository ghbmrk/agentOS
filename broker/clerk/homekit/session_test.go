package homekit

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// REQ: DEV-1, DEV-4, KRN-2, RES-1

// within fails the test if fn does not return in time: a deadlock or a
// blocked read shows as this failure, not as a hung test run.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// An OnEvent callback runs after the session's lock is released, so a
// callback that calls back into the session does not deadlock (#3325 item 1).
func TestEventCallbackMayCallBackIntoTheSession(t *testing.T) {
	var s *Session
	var mu sync.Mutex
	var seen []Characteristic
	opt := Options{OnEvent: func(vs []Value) {
		for _, v := range vs {
			c, ok := s.Characteristic(v.ID)
			if !ok {
				t.Errorf("event for unresolved %v", v.ID)
			}
			mu.Lock()
			seen = append(seen, c)
			mu.Unlock()
		}
	}}
	s, _ = hostilePeer(t, opt, func(req *http.Request, n int) string {
		return hapEvent(valuesBody(idEv)) + hapResp(200, valuesBody(idEv))
	})
	within(t, 5*time.Second, "a read whose event callback calls back into the session", func() {
		if _, err := s.Read(idEv); err != nil {
			t.Error(err)
		}
	})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].ID != idEv || seen[0].Type != CharCurrentTemperature {
		t.Fatalf("events %+v", seen)
	}
}

const twoThermostats = `{"accessories":[` +
	`{"aid":1,"services":[{"type":"4A","characteristics":[{"iid":2,"type":"11","perms":["pr","ev"],"format":"float"}]}]},` +
	`{"aid":2,"services":[{"type":"4A","characteristics":[{"iid":2,"type":"11","perms":["pr","ev"],"format":"float"}]}]},` +
	`{"aid":3,"services":[{"type":"4A","characteristics":[{"iid":2,"type":"11","perms":["pr"],"format":"float"}]},` +
	`{"type":"4A","characteristics":[{"iid":3,"type":"11","perms":["pr"],"format":"float"}]}]}]}`

// Find resolves by aid as well as by service and type, so a bridge with two
// thermostats gives each its own; an aid with two such services is
// ambiguous and finds nothing (#3325 item 2).
func TestFindResolvesByAid(t *testing.T) {
	s, _ := peerWith(t, Options{}, twoThermostats, func(*http.Request, int) string { return hapResp(200, "{}") })
	for _, aid := range []uint64{1, 2} {
		for range 20 { // map order varies: an arbitrary pick would show
			c, ok := s.Find(aid, ServiceThermostat, CharCurrentTemperature)
			if !ok || c.ID != (ID{aid, 2}) {
				t.Fatalf("aid %d found %v %v", aid, c.ID, ok)
			}
		}
	}
	if c, ok := s.Find(3, ServiceThermostat, CharCurrentTemperature); ok {
		t.Fatalf("ambiguous aid 3 found %v", c.ID)
	}
	if _, ok := s.Find(4, ServiceThermostat, CharCurrentTemperature); ok {
		t.Fatal("found a characteristic on an absent aid")
	}
}

// blockingPeer receives requests and never answers them; asked is signalled
// once per request.
func blockingPeer(t *testing.T, opt Options) (*Session, <-chan struct{}) {
	t.Helper()
	asked, stop := make(chan struct{}, 8), make(chan struct{})
	t.Cleanup(func() { close(stop) })
	s, _ := hostilePeer(t, opt, func(*http.Request, int) string {
		asked <- struct{}{}
		<-stop
		return ""
	})
	return s, asked
}

// Close returns while a read is blocked on the accessory, and the blocked
// read ends with ErrClosed (#3325 item 3).
func TestCloseReturnsWhileAReadIsBlocked(t *testing.T) {
	s, asked := blockingPeer(t, Options{})
	readErr := make(chan error, 1)
	go func() { _, err := s.Read(idEv); readErr <- err }()
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("the read never reached the accessory")
	}
	within(t, 2*time.Second, "Close during a blocked read", func() { s.Close() })
	select {
	case err := <-readErr:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("blocked read ended with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked read did not end after Close")
	}
	if _, err := s.Read(idEv); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after Close: %v", err)
	}
}

// With Options.Timeout, an accessory that never answers ends the session at
// the deadline instead of holding it (HK-11).
func TestTimeoutEndsAnUnansweredRequest(t *testing.T) {
	s, _ := blockingPeer(t, Options{Timeout: 100 * time.Millisecond})
	within(t, 5*time.Second, "a read the accessory never answers", func() {
		if _, err := s.Read(idEv); err == nil {
			t.Error("unanswered read succeeded")
		}
	})
	if _, err := s.Read(idEv); !errors.Is(err, ErrClosed) {
		t.Fatalf("session still open after the timeout: %v", err)
	}
}

// A 1xx interim reply is refused, ending the session, instead of being
// taken as the answer and knocking the stream out of step (#3325 item 7).
func TestInterimReplyIsRefused(t *testing.T) {
	s, _ := hostilePeer(t, Options{}, func(*http.Request, int) string {
		return "HTTP/1.1 100 Continue\r\n\r\n" + hapResp(200, valuesBody(idEv))
	})
	if _, err := s.Read(idEv); !errors.Is(err, ErrProtocol) {
		t.Fatalf("1xx reply: %v", err)
	}
	if _, err := s.Read(idEv); !errors.Is(err, ErrClosed) {
		t.Fatalf("session open after a 1xx reply: %v", err)
	}
}
