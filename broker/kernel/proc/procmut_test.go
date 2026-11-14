package proc

// REQ: KRN-6, KRN-7, LOG-1
//
// KRN-proc-mut (#5273): the kernel process's failure paths, each checked by
// what it does, so the mutation gate's survivors on them die: a log write
// that fails, a stalled or vanished peer on either end of a socket, a flood
// of failed accepts, and a Tick that never runs out of calls.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var errFault = errors.New("test: the disk refused the write")

// faultFile is a log file whose writes fail once failAfter of them have
// landed (never while failAfter is negative), and which counts its syncs.
type faultFile struct {
	*os.File
	mu        sync.Mutex
	failAfter int
	writes    int
	syncs     int
}

func (f *faultFile) WriteAt(b []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAfter >= 0 && f.writes >= f.failAfter {
		return 0, errFault
	}
	f.writes++
	return f.File.WriteAt(b, off)
}

func (f *faultFile) Sync() error {
	f.mu.Lock()
	f.syncs++
	f.mu.Unlock()
	return f.File.Sync()
}

// failAfterNext arms f to take n more writes, then fail every later one.
func (f *faultFile) failAfterNext(n int) {
	f.mu.Lock()
	f.failAfter = f.writes + n
	f.mu.Unlock()
}

// faultLog swaps h's log file for a faultFile over it that fails nothing yet.
func faultLog(h *Kernel) *faultFile {
	f := &faultFile{File: h.store.f.(*os.File), failAfter: -1}
	h.store.f = f
	return f
}

// Append returns only once the bytes are synced, and a write the disk refuses
// is an error, never a success (LOG-1; store.go's write check).
func TestAppendSyncsAndAFailedWriteIsAnError(t *testing.T) {
	s, err := OpenFileStore(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f := &faultFile{File: s.f.(*os.File), failAfter: -1}
	s.f = f
	if err := s.Append([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if f.syncs != 1 {
		t.Fatalf("append synced %d times, want once", f.syncs)
	}
	f.failAfterNext(0)
	if err := s.Append([]byte("def")); !errors.Is(err, errFault) {
		t.Fatalf("append with the write refused: %v, want the refusal", err)
	}
	if b, _ := s.ReadAll(); string(b) != "abc" {
		t.Fatalf("log holds %q, want abc", b)
	}
}

// A kernel.Open that refuses the log closes it, so its lock is free for the
// next start (LOG-1; kernel.go's Close on that path).
func TestARefusedLogIsClosed(t *testing.T) {
	cfg := KernelConfig{Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{H: kernel.Head{Seq: 5}, Ok: true}, Pub: headPub, Sign: headPriv}
	if _, err := OpenKernel(cfg, 0); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("got %v, want %v", err, kernel.ErrCorrupt)
	}
	s, err := OpenFileStore(cfg.Log)
	if err != nil {
		t.Fatalf("the refused start kept the log: %v", err)
	}
	s.Close()
}

// A log write that fails while Tick takes the calls due is Tick's error,
// never swallowed (KRN-6: a broken log is reported, not run past).
func TestTickReturnsAFailedLogWriteInCalls(t *testing.T) {
	sock := serveFake(t, fakeClerk{do: func() kernel.Result { return kernel.Result{Outcome: "ok"} }})
	b := newBox(t, sock)
	id := b.submit("dave")
	faultLog(b.h).failAfterNext(0)
	if err := b.h.Tick(b.now); !errors.Is(err, errFault) {
		t.Fatalf("tick over a refused write: %v, want the refusal", err)
	}
	if st := b.step(id); st.Phase != kernel.PQueued {
		t.Fatalf("step is %s, want queued: nothing was logged", st.Phase)
	}
}

// A log write that fails in the last check before a send is Tick's error:
// a STOP logged while the first call hangs makes the second step's check
// log it unsent, and that write fails (KRN-6, KRN-7).
func TestTickReturnsAFailedLogWriteInSend(t *testing.T) {
	sock := filepath.Join(shortDir(t), "first.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	c := &first{in: make(chan struct{}), release: make(chan struct{})}
	go ServeClerk(ln, c, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBox(t, sock)
	a, z := b.submit("dave"), b.submit("erin")
	f := faultLog(b.h)
	ticked := make(chan error, 1)
	go func() { ticked <- b.h.Tick(b.now) }()
	<-c.in
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }); err != nil {
		t.Fatal(err)
	}
	// The first answer's one entry lands; the second step's unsent answer
	// does not.
	f.failAfterNext(1)
	close(c.release)
	if err := <-ticked; !errors.Is(err, errFault) {
		t.Fatalf("tick over a refused write: %v, want the refusal", err)
	}
	if b.step(a).Phase != kernel.PDone || b.step(z).Phase != kernel.PInflight {
		t.Fatalf("steps %s and %s, want done and still in flight", b.step(a).Phase, b.step(z).Phase)
	}
}

// feeder is a clerk that, while each call is out, submits one more plan, as
// an owner side could, until it has made max calls.
type feeder struct {
	mu  sync.Mutex
	b   *box
	n   int
	max int
	err error
}

func (f *feeder) Do(kernel.Request, kernel.View) kernel.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n < f.max {
		p := kernel.SignPlan(kernel.Plan{ID: fmt.Sprintf("f%d", f.n), Key: f.b.key, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "dave", "msg": fmt.Sprint("hello ", f.n)}, Content: "text", Labels: []string{"public"}}}}, holderPriv)
		if err := f.b.h.With(func(k *kernel.Kernel) error { return k.Submit(f.b.now, p) }); err != nil && f.err == nil {
			f.err = err
		}
	}
	return kernel.Result{Outcome: "ok"}
}

func (*feeder) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "notdone"}
}

// Tick ends after 4*MaxSteps rounds even when every round leaves a call due,
// so plans submitted as fast as they are sent cannot keep it from returning
// (KRN-7: the loop has a bound, and it is that bound).
func TestTickEndsAfterItsRoundCap(t *testing.T) {
	sock := filepath.Join(shortDir(t), "feed.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	f := &feeder{max: 1000}
	go ServeClerk(ln, f, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBox(t, sock)
	f.b = b
	b.submit("dave")
	ticked := make(chan error, 1)
	go func() { ticked <- b.h.Tick(b.now) }()
	select {
	case err := <-ticked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("tick did not end")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		t.Fatal(f.err)
	}
	if want := 4 * kernel.MaxSteps; f.n != want {
		t.Fatalf("one tick made %d calls, want %d (one a round)", f.n, want)
	}
}

// fast is a connection whose deadlines run a thousand times faster than
// asked, and which records any it was asked that is not 30 seconds out.
type fast struct {
	net.Conn
	mu  sync.Mutex
	bad []string
}

func (c *fast) scale(t time.Time, which string) time.Time {
	if t.IsZero() {
		return t
	}
	d := time.Until(t)
	if d < 29*time.Second || d > 30*time.Second {
		c.mu.Lock()
		c.bad = append(c.bad, fmt.Sprintf("%s deadline %v out", which, d))
		c.mu.Unlock()
	}
	return time.Now().Add(d / 1000)
}

func (c *fast) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(c.scale(t, "read"))
}

func (c *fast) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.scale(t, "write"))
}

func (c *fast) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.bad = append(c.bad, "a deadline for both directions")
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// servers are the kernel's and a clerk's one-call servers.
var servers = map[string]func(net.Conn){
	"kernel": func(c net.Conn) {
		ServeOne(c, func(string, json.RawMessage) (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	},
	"clerk": func(c net.Conn) { serve(c, fakeClerk{probe: "done"}, anchors) },
}

// returnsWithin runs f and fails t unless it returns within d.
func returnsWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// closed fails t unless c's peer has closed: a read ends at once with EOF.
func closed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1<<16)); !errors.Is(err, io.EOF) {
		t.Fatalf("the server left the connection open: %v", err)
	}
}

// A caller that never sends, or never reads the answer, holds a socket's
// slot (the owner socket's, or a clerk's only one) for 30 seconds at most,
// and the server closes the connection when it is done (KRN-7).
func TestAStalledPeerHoldsAServerFor30Seconds(t *testing.T) {
	call := map[string]any{"kernel": kernelCall{Op: "status"}, "clerk": call{Op: opProbe}}
	for name, srv := range servers {
		t.Run(name+"/never sends", func(t *testing.T) {
			s, c := net.Pipe()
			defer c.Close()
			f := &fast{Conn: s}
			returnsWithin(t, 5*time.Second, "a server with a silent caller", func() { srv(f) })
			closed(t, c)
			if len(f.bad) != 0 {
				t.Fatal(f.bad)
			}
		})
		t.Run(name+"/never reads", func(t *testing.T) {
			s, c := net.Pipe()
			defer c.Close()
			f := &fast{Conn: s}
			go json.NewEncoder(c).Encode(call[name])
			returnsWithin(t, 5*time.Second, "a server with a caller that never reads", func() { srv(f) })
			closed(t, c)
			if len(f.bad) != 0 {
				t.Fatal(f.bad)
			}
		})
		t.Run(name+"/answers", func(t *testing.T) {
			s, c := net.Pipe()
			defer c.Close()
			go srv(&fast{Conn: s})
			json.NewEncoder(c).Encode(call[name])
			var a map[string]any
			if err := json.NewDecoder(c).Decode(&a); err != nil {
				t.Fatalf("no answer: %v", err)
			}
		})
	}
}

// peerServer listens on a fresh socket for the test's uid and hands each
// connection to handle.
func peerServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	sock := filepath.Join(shortDir(t), "peer.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return sock
}

// The kernel's client (Conn) and its clerk client (remote) as one call each:
// ok is whether the call got its answer.
var clients = map[string]func(sock string, timeout time.Duration) (ok bool){
	"kernel": func(sock string, d time.Duration) bool {
		return Conn{Socket: sock, UID: os.Getuid(), Timeout: d}.Call("status", nil, nil) == nil
	},
	"clerk": func(sock string, d time.Duration) bool {
		r := remote{Remote: Remote{Socket: sock, UID: os.Getuid(), Timeout: d}}
		return r.Probe(kernel.Request{}, kernel.NewState(nil)).Outcome == "done"
	},
}

// answerOnce reads one line and answers it as a server on either side
// would, then reports on gone whether the caller closed its end.
func answerOnce(gone chan<- error) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 1<<16)
		n, _ := c.Read(buf)
		if n == 0 {
			gone <- errors.New("no call")
			return
		}
		c.Write([]byte(`{"outcome":"done"}` + "\n"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(buf)
		gone <- err
	}
}

// A call with no timeout set takes the default, not none, and the client
// closes its connection once it has the answer (KRN-7).
func TestACallTakesTheDefaultTimeoutAndCloses(t *testing.T) {
	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			gone := make(chan error, 1)
			sock := peerServer(t, answerOnce(gone))
			if !client(sock, 0) {
				t.Fatal("a call with the default timeout got no answer")
			}
			if err := <-gone; !errors.Is(err, io.EOF) {
				t.Fatalf("the client left the connection open: %v", err)
			}
		})
	}
}

// A server that never answers holds a call for its timeout and no longer:
// the call reads as lost (KRN-7).
func TestACallToAStalledServerEndsAtItsTimeout(t *testing.T) {
	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			hold := make(chan struct{})
			defer close(hold)
			sock := peerServer(t, func(c net.Conn) { <-hold; c.Close() })
			returnsWithin(t, 5*time.Second, "a call to a stalled server", func() {
				if client(sock, 100*time.Millisecond) {
					t.Error("a stalled server answered")
				}
			})
		})
	}
}

// A unix dial never waits: a socket whose backlog is full refuses at once
// (EAGAIN), so the clients dial with no timeout, and such a call reads as
// never sent (Conn: ErrUnreachable; remote: unreached).
func TestAUnixDialNeverWaits(t *testing.T) {
	sock := filepath.Join(shortDir(t), "full.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			break
		}
		defer c.Close()
		if i > 64 {
			t.Fatal("the backlog never filled")
		}
	}
	returnsWithin(t, time.Second, "a call to a full socket", func() {
		if err := (Conn{Socket: sock, UID: os.Getuid()}).Call("status", nil, nil); !errors.Is(err, ErrUnreachable) {
			t.Errorf("call to a full socket: %v, want %v", err, ErrUnreachable)
		}
		r := remote{Remote: Remote{Socket: sock, UID: os.Getuid()}}
		if got := r.Probe(kernel.Request{}, kernel.NewState(nil)).Outcome; got != kernel.OUnreached {
			t.Errorf("probe of a full socket: %q, want %s", got, kernel.OUnreached)
		}
	})
}

// script is a listener whose accepts follow its steps: an error fails that
// accept, nil hands out a connection, and past the last step it is closed.
type script struct {
	mu    sync.Mutex
	steps []error
}

func (s *script) Accept() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.steps) == 0 {
		return nil, net.ErrClosed
	}
	err := s.steps[0]
	s.steps = s.steps[1:]
	if err != nil {
		return nil, err
	}
	c, _ := net.Pipe()
	return c, nil
}

func (*script) Close() error   { return nil }
func (*script) Addr() net.Addr { return &net.UnixAddr{Name: "script", Net: "unix"} }

// A failed accept frees its slot and is waited out with a backoff from 5ms
// that doubles to at most a second and starts again after an accept that
// succeeds, so STOP still lands after a descriptor flood (KRN-7).
func TestFailedAcceptsBackOffAndFreeTheirSlot(t *testing.T) {
	e := errors.New("accept: too many open files")
	ln := &script{steps: []error{e, e, e, nil, e, e, e, e, e, e, e, e, e, e}}
	var waits []time.Duration
	handled := 0
	returnsWithin(t, 5*time.Second, "serving one slot through failed accepts", func() {
		if err := serveConns(ln, 1, func(c net.Conn) { handled++; c.Close() }, func(d time.Duration) { waits = append(waits, d) }); err != nil {
			t.Error(err)
		}
	})
	ms := time.Millisecond
	want := []time.Duration{5 * ms, 10 * ms, 20 * ms, 5 * ms, 10 * ms, 20 * ms, 40 * ms, 80 * ms, 160 * ms, 320 * ms, 640 * ms, time.Second, time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
	if handled != 1 {
		t.Fatalf("handled %d connections, want 1", handled)
	}
}
