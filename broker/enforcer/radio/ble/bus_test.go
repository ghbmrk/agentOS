package ble

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: NET-2

// stubBus is a bus on a socket in a fresh directory, for one peer: it
// answers AUTH with auth, then each method call with answer's reply (an
// empty return where answer is nil or gives nil), until the peer goes. A
// silent stub answers nothing at all. ended is closed when the peer's
// connection ends.
type stubBus struct {
	path  string
	ended chan struct{}

	mu    sync.Mutex
	conn  net.Conn
	calls []call // the methods called, in order
}

func newStubBus(t *testing.T, auth string, silent bool, answer func(*Message) *Message) *stubBus {
	t.Helper()
	sb := &stubBus{path: filepath.Join(t.TempDir(), "bus"), ended: make(chan struct{})}
	ln, err := net.Listen("unix", sb.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); sb.drop() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sb.mu.Lock()
		sb.conn = c
		sb.mu.Unlock()
		defer close(sb.ended)
		defer c.Close()
		r := bufio.NewReader(c)
		if silent {
			io.Copy(io.Discard, r)
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		io.WriteString(c, auth)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if l == "BEGIN\r\n" {
				break
			}
		}
		serial := uint32(0)
		for {
			m, err := readMessage(r, all)
			if errors.Is(err, errSkipped) {
				continue
			}
			if err != nil {
				return
			}
			sb.mu.Lock()
			sb.calls = append(sb.calls, call{m.Path, m.Interface, m.Member, m.Body})
			sb.mu.Unlock()
			reply := &Message{Type: typeReturn}
			if answer != nil {
				if a := answer(m); a != nil {
					reply = a
				}
			}
			serial++
			reply.Serial, reply.ReplySerial = serial, m.Serial
			b, err := reply.Encode()
			if err != nil {
				panic(err)
			}
			c.Write(b)
		}
	}()
	return sb
}

// drop ends the peer's connection, as a bus that went away.
func (sb *stubBus) drop() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.conn != nil {
		sb.conn.Close()
	}
}

func (sb *stubBus) called() []call {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return slices.Clone(sb.calls)
}

const authOK = "OK 0123456789abcdef0123456789abcdef\r\n"

// TestDialRefusesWhatIsNotABus: a missing socket, and a bus that refuses
// the authentication even when it then answers like a bus, fail Dial; a
// bus that never answers fails it within its 5 s handshake bound.
func TestDialRefusesWhatIsNotABus(t *testing.T) {
	t.Parallel()
	if _, err := Dial(filepath.Join(t.TempDir(), "none"), allSignals(func(*Message) {})); err == nil {
		t.Error("dialled a missing socket")
	}
	refused := newStubBus(t, "REJECTED EXTERNAL\r\n", false, nil)
	if b, err := Dial(refused.path, allSignals(func(*Message) {})); err == nil || !strings.Contains(err.Error(), "refused authentication") {
		if b != nil {
			b.Close()
		}
		t.Errorf("a bus that refused the authentication: %v", err)
	}
	select {
	case <-refused.ended:
	case <-time.After(5 * time.Second):
		t.Error("Dial kept the connection the bus refused")
	}
	began := time.Now()
	if b, err := Dial(newStubBus(t, "", true, nil).path, allSignals(func(*Message) {})); err == nil {
		b.Close()
		t.Error("dialled a bus that never answered")
	}
	if d := time.Since(began); d > 7*time.Second {
		t.Errorf("a silent bus held Dial %v", d)
	}
}

// TestBusOutlivesItsHandshakeBound: the handshake's 5 s deadline is
// cleared once the bus is up, so a call after it still gets its reply,
// and Close ends the connection at the bus's end too.
func TestBusOutlivesItsHandshakeBound(t *testing.T) {
	t.Parallel()
	sb := newStubBus(t, authOK, false, nil)
	b, err := Dial(sb.path, allSignals(func(*Message) {}))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5500 * time.Millisecond)
	if _, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "GetId", "", 5*time.Second); err != nil {
		t.Errorf("a call after 5.5 s: %v", err)
	}
	b.Close()
	select {
	case <-sb.ended:
	case <-time.After(5 * time.Second):
		t.Error("the bus still holds the connection after Close")
	}
}

// recConn is a bus connection that takes every write, even after Close,
// so a write after the end shows.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	wrote  bytes.Buffer
	closed bool
}

func (c *recConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrote.Write(b)
}

func (c *recConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (*recConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recConn) state() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrote.Len(), c.closed
}

func memBus(conn net.Conn) *Bus {
	return &Bus{conn: conn, sigs: allSignals(func(*Message) {}), calls: map[uint32]chan *Message{}, done: make(chan struct{})}
}

// returned is what a call came back with.
type returned struct {
	body []any
	err  error
}

// TestBusEnds: a call waiting when the bus ends returns ErrBusClosed at
// once, not at its timeout; the end closes the connection, may come
// twice, and leaves the bus answering ErrBusClosed without writing a
// byte; a reply to a call the end dropped is read past, never handed on.
func TestBusEnds(t *testing.T) {
	c := &recConn{}
	b := memBus(c)
	got := make(chan returned, 1)
	go func() {
		body, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", time.Hour)
		got <- returned{body, err}
	}()
	for n, _ := c.state(); n == 0; n, _ = c.state() {
		time.Sleep(time.Millisecond)
	}
	b.Close()
	select {
	case r := <-got:
		if !errors.Is(r.err, ErrBusClosed) {
			t.Errorf("the waiting call: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting call outlived the bus")
	}
	if _, closed := c.state(); !closed {
		t.Error("the end left the connection open")
	}
	b.Close()
	n, _ := c.state()
	done := make(chan error, 1)
	go func() {
		_, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", 50*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBusClosed) {
			t.Errorf("a call after the end: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a call after the end hangs")
	}
	if m, _ := c.state(); m != n {
		t.Errorf("a call after the end wrote %d bytes", m-n)
	}
	// The call the end dropped had serial 1: its late reply is not wanted.
	late := mustEncode(t, &Message{Type: typeReturn, Serial: 7, ReplySerial: 1})
	if _, err := readMessage(bytes.NewReader(late), b.wants); !errors.Is(err, errSkipped) {
		t.Errorf("a late reply after the end: %v", err)
	}
	// A call still registered when the end comes (its Call not yet
	// returned): the end closes its channel and drops it, so a reply the
	// read loop meets after the end is read past, not sent on the closed
	// channel.
	b = memBus(&recConn{})
	b.calls[5] = make(chan *Message, 1)
	b.end(ErrBusClosed)
	b.readLoop(bufio.NewReader(bytes.NewReader(mustEncode(t, &Message{Type: typeReturn, Serial: 7, ReplySerial: 5}))))
}

// TestBusCallFaults: a call whose message does not encode fails as
// such, a write the bus does not take within the timeout ends the bus,
// and a call that timed out leaves no reply wanted.
func TestBusCallFaults(t *testing.T) {
	b := memBus(&recConn{})
	if _, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "y", time.Second); !errors.Is(err, ErrWire) {
		t.Errorf("a call whose body lacks its signature's value: %v", err)
	}
	if _, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", 10*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Errorf("an unanswered call: %v", err)
	}
	if b.wants(&Message{Type: typeReturn, ReplySerial: b.serial}) {
		t.Error("the timed-out call's reply is still wanted")
	}

	us, them := net.Pipe() // takes no write until the other end reads
	defer them.Close()
	b = memBus(us)
	done := make(chan error, 1)
	go func() {
		_, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", 50*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBusClosed) {
			t.Errorf("a write nobody takes: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write nobody takes holds the call")
	}
	select {
	case <-b.Done():
	default:
		t.Error("a write nobody takes left the bus up")
	}
}

// TestBusCallFailedWriteIgnoresReply: a call whose write fails returns
// ErrBusClosed even when a peer, having read only the call's header (the
// serial is in it), already answered it: a reply to a call never fully
// sent is not taken as its result.
func TestBusCallFailedWriteIgnoresReply(t *testing.T) {
	us, them := net.Pipe()
	b := memBus(us)
	go b.readLoop(bufio.NewReader(us))
	go func() {
		io.ReadFull(them, make([]byte, 16))
		them.Write(mustEncode(t, &Message{Type: typeReturn, Serial: 1, ReplySerial: 1, Sig: "s", Body: []any{"forged"}}))
		time.Sleep(300 * time.Millisecond)
		them.Close()
	}()
	body, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "s", 3*time.Second, "arg")
	if !errors.Is(err, ErrBusClosed) {
		t.Errorf("a call whose write failed: %v, %v", body, err)
	}
}

// TestBusReadLoop: the read loop hands a reply to its call once, so a
// second reply with the same serial is read past and the loop goes on,
// and the stream's end ends the bus.
func TestBusReadLoop(t *testing.T) {
	var sigs []*Message
	b := memBus(&recConn{})
	b.sigs = allSignals(func(m *Message) { sigs = append(sigs, m) })
	ch := make(chan *Message, 1) // nobody takes from it: a second hand-off would block
	b.calls[5] = ch
	stream := slices.Concat(
		mustEncode(t, &Message{Type: typeReturn, Serial: 1, ReplySerial: 5}),
		mustEncode(t, &Message{Type: typeReturn, Serial: 2, ReplySerial: 5}),
		mustEncode(t, &Message{Type: typeSignal, Serial: 3, Path: "/", Interface: "a.b", Member: "C"}),
	)
	ended := make(chan struct{})
	go func() {
		b.readLoop(bufio.NewReader(bytes.NewReader(stream)))
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop stuck on a second reply")
	}
	if len(ch) != 1 || len(sigs) != 1 || sigs[0].Serial != 3 {
		t.Errorf("replies %d, signals %+v", len(ch), sigs)
	}
	select {
	case <-b.Done():
	default:
		t.Error("the stream ended and the bus is up")
	}
	// A clean end of the stream reads as io.EOF; one inside a header as
	// io.ErrUnexpectedEOF, never as a malformed message.
	if _, err := readMessage(bytes.NewReader(nil), all); err != io.EOF {
		t.Errorf("an empty stream: %v", err)
	}
	if _, err := readMessage(bytes.NewReader(stream[:20]), all); err != io.ErrUnexpectedEOF {
		t.Errorf("a stream ending in a header: %v", err)
	}
}
