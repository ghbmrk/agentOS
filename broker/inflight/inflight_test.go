package inflight

// REQ: RES-5, OP-8

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, file, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupLimitIsLeastOnPathToRoot(t *testing.T) {
	d := t.TempDir()
	self := filepath.Join(d, "self")
	fs := filepath.Join(d, "fs")
	write(t, self, "0::/system.slice/agentosd.service\n")
	write(t, filepath.Join(fs, "system.slice/agentosd.service/memory.max"), "max\n")
	write(t, filepath.Join(fs, "system.slice/agentosd.service/memory.high"), "3000000000\n")
	write(t, filepath.Join(fs, "system.slice/memory.max"), "2000000000\n")
	n, ok := cgroupLimit(self, fs)
	if !ok || n != 2000000000 {
		t.Fatalf("cgroupLimit = %d, %v; want the ancestor's 2000000000", n, ok)
	}
	write(t, filepath.Join(fs, "system.slice/memory.max"), "max\n")
	if n, _ := cgroupLimit(self, fs); n != 3000000000 {
		t.Fatalf("cgroupLimit = %d; want memory.high's 3000000000", n)
	}
	write(t, filepath.Join(fs, "system.slice/agentosd.service/memory.high"), "max\n")
	if _, ok := cgroupLimit(self, fs); ok {
		t.Fatal("no limit anywhere should report none")
	}
	if _, ok := cgroupLimit(filepath.Join(d, "missing"), fs); ok {
		t.Fatal("no cgroup file should report none")
	}
}

func TestMemTotal(t *testing.T) {
	f := filepath.Join(t.TempDir(), "meminfo")
	write(t, f, "MemFree:  10 kB\nMemTotal:       4194304 kB\n")
	if n, ok := memTotal(f); !ok || n != 4<<30 {
		t.Fatalf("memTotal = %d, %v; want 4 GiB", n, ok)
	}
	if m := MemoryLimit(); m <= 0 {
		t.Fatalf("MemoryLimit = %d", m)
	}
}

func TestCostOfSaturates(t *testing.T) {
	if got := Model.Of(1 << 62); got <= 0 {
		t.Fatalf("Of overflowed to %d", got)
	}
	if got := (Cost{Floor: 10, PerByte: 3}).Of(5); got != 25 {
		t.Fatalf("Of = %d", got)
	}
}

// A request that does not fit waits, in arrival order, and runs once room
// frees; one that could never fit gets 413 unread; past its wait, 503.
func TestRouteWaitsInOrderAndRefusesOnlyTheImpossible(t *testing.T) {
	g := New(1000).Gate(time.Second)
	held, err := g.acquire(context.Background(), 400)
	if err != nil {
		t.Fatal(err)
	}
	ran := make(chan string, 3)
	h := g.Route(100, Cost{PerByte: 1}, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran <- r.URL.Path
	}))
	serve := func(p string, n int64) chan int {
		code := make(chan int, 1)
		go func() {
			r := httptest.NewRequest("POST", p, strings.NewReader(strings.Repeat("a", int(n))))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			code <- w.Code
		}()
		return code
	}
	first := serve("/first", 100)
	if c := <-first; c != 200 || <-ran != "/first" {
		t.Fatalf("a request that fits = %d", c)
	}
	// The share is 500; 400 is held, so a 100-byte request needs 100 and
	// fits, but two waiters behind a larger hold wait.
	held2, _ := g.acquire(context.Background(), 100)
	a := serve("/a", 100)
	time.Sleep(20 * time.Millisecond)
	b := serve("/b", 10)
	time.Sleep(20 * time.Millisecond)
	select {
	case p := <-ran:
		t.Fatalf("%s ran with no room", p)
	default:
	}
	held2()
	if p := <-ran; p != "/a" {
		t.Fatalf("first to run = %s; want arrival order", p)
	}
	if p := <-ran; p != "/b" {
		t.Fatalf("second to run = %s", p)
	}
	<-a
	<-b

	// Declared longer than the route reads: 413 unread.
	r := httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("a", 101)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over max = %d", w.Code)
	}
	// Costing more than the guest's share: 413.
	big := g.Route(1000, Cost{PerByte: 1}, 0, http.NotFoundHandler())
	r = httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("a", 600)))
	w = httptest.NewRecorder()
	big.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over share = %d", w.Code)
	}
	// No room within the wait: 503 with Retry-After.
	held3, _ := g.acquire(context.Background(), 100)
	r = httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("a", 50)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("past the wait = %d", w.Code)
	}
	held3()
	held()
}

// A guest holds at most half the budget, so a second guest still runs.
func TestGuestShare(t *testing.T) {
	b := New(1000)
	g1, g2 := b.Gate(50*time.Millisecond), b.Gate(time.Second)
	r1, err := g1.acquire(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if _, err := g1.acquire(ctx, 1); err == nil {
		t.Fatal("a guest got more than its share")
	}
	cancel()
	r2, err := g2.acquire(context.Background(), 500)
	if err != nil {
		t.Fatalf("second guest starved: %v", err)
	}
	r1()
	r1() // releasing twice is harmless
	r2()
	if _, err := g1.acquire(context.Background(), 500); err != nil {
		t.Fatalf("share not returned: %v", err)
	}
}

// Each open connection holds ConnCost until it closes; past the share,
// Accept waits; closing the listener ends a waiting Accept.
func TestListenChargesConnections(t *testing.T) {
	g := New(4 * ConnCost).Gate(time.Second) // a share of two connections
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := g.Limit(l)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	var dialed []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		dialed = append(dialed, c)
	}
	c1, c2 := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted past the share")
	case <-time.After(50 * time.Millisecond):
	}
	c1.Close()
	select {
	case c3 := <-accepted:
		c3.Close()
	case <-time.After(time.Second):
		t.Fatal("closing a connection did not admit the next")
	}
	c2.Close()
	// Fill the share again, then close the listener under a waiting Accept.
	for range 3 {
		c, _ := net.Dial("tcp", l.Addr().String())
		dialed = append(dialed, c)
	}
	<-accepted
	<-accepted
	ll.Close()
	select {
	case _, ok := <-accepted:
		if ok {
			t.Fatal("accepted after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not end a waiting Accept")
	}
	for _, c := range dialed {
		c.Close()
	}
}

// A waiting Accept never holds back a request that fits: connections take
// room only when no request waits for it.
func TestAWaitingAcceptDoesNotBlockRequests(t *testing.T) {
	g := New(2 * (2*ConnCost + 1000)).Gate(time.Second) // two connections and 1000 bytes
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := g.Limit(l)
	defer ll.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 3 {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	c1, c2 := <-accepted, <-accepted
	defer c1.Close()
	defer c2.Close()
	time.Sleep(3 * connPoll) // the third Accept is waiting
	h := g.Route(1000, Cost{PerByte: 1}, 0, http.NotFoundHandler())
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("a", 1000))))
		done <- w.Code
	}()
	select {
	case c := <-done:
		if c != http.StatusNotFound {
			t.Fatalf("request = %d", c)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a waiting Accept held back a request that fits")
	}
}
