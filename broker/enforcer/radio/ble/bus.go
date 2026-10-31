package ble

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bus is one connection to a D-Bus message bus over a Unix socket,
// authenticated as this process's uid (SASL EXTERNAL), with no unix fd
// passing. Calls wait for their reply; signals go to Signals.
type Bus struct {
	conn net.Conn
	sigs Signals

	wmu sync.Mutex

	mu     sync.Mutex
	serial uint32
	calls  map[uint32]chan *Message
	err    error

	done chan struct{}
}

var (
	ErrBusClosed = errors.New("ble: bus connection ended")
	ErrTimeout   = errors.New("ble: no reply in time")
)

// CallError is an error reply.
type CallError struct{ Name string }

func (e *CallError) Error() string { return "ble: bus error " + e.Name }

const busDriver = "org.freedesktop.DBus"

// Signals takes a bus's signals. wants reads a signal's header, its body
// not yet decoded; only a signal it wants is decoded and goes to signal.
// Both run on the read loop and must not call back into Bus.
type Signals interface {
	wants(*Message) bool
	signal(*Message)
}

// Dial connects to the bus at the socket path, authenticates and says
// Hello.
func Dial(path string, sigs Signals) (*Bus, error) {
	c, err := net.Dial("unix", path) // a Unix socket connects at once or fails
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReaderSize(c, 4096)
	uid := hex.EncodeToString([]byte(strconv.Itoa(os.Getuid())))
	if _, err := io.WriteString(c, "\x00AUTH EXTERNAL "+uid+"\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	line, err := r.ReadSlice('\n')
	if err != nil || !strings.HasPrefix(string(line), "OK ") {
		c.Close()
		return nil, fmt.Errorf("ble: bus refused authentication (%v)", err)
	}
	if _, err := io.WriteString(c, "BEGIN\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	b := &Bus{conn: c, sigs: sigs, calls: map[uint32]chan *Message{}, done: make(chan struct{})}
	go b.readLoop(r)
	if _, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "Hello", "", 5*time.Second); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

// Done is closed when the connection ends.
func (b *Bus) Done() <-chan struct{} { return b.done }

// Close ends the connection.
func (b *Bus) Close() { b.end(ErrBusClosed) }

// Call sends a method call and waits up to timeout for its reply's body;
// an error reply is a *CallError.
func (b *Bus) Call(dest string, path ObjectPath, iface, member string, sig Signature, timeout time.Duration, args ...any) ([]any, error) {
	m := &Message{Type: typeCall, Path: path, Interface: iface, Member: member, Destination: dest, Sig: sig, Body: args}
	ch := make(chan *Message, 1)
	b.mu.Lock()
	if b.err != nil {
		b.mu.Unlock()
		return nil, b.err
	}
	b.serial++
	m.Serial = b.serial
	b.calls[m.Serial] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.calls, m.Serial)
		b.mu.Unlock()
	}()
	raw, err := m.Encode()
	if err != nil {
		return nil, err
	}
	b.wmu.Lock()
	b.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = b.conn.Write(raw)
	b.wmu.Unlock()
	if err != nil {
		b.end(err)
		return nil, ErrBusClosed
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r, ok := <-ch:
		if !ok {
			return nil, ErrBusClosed
		}
		if r.Type == typeError {
			return nil, &CallError{Name: r.ErrorName}
		}
		return r.Body, nil
	case <-t.C:
		return nil, ErrTimeout
	}
}

// readLoop takes messages until the connection ends. A message is decoded
// only when its header shows it is wanted: a reply some call still waits
// for, or a signal Signals wants. Anything else, and a message that is too
// long or does not decode, is skipped, so a bus peer that sends one (any
// peer may send this process a signal, unless the bus policy stops it)
// can neither end the stack nor make it decode a body; a caller whose
// reply was skipped times out. A method call to this process is never
// answered, since it serves nothing on the bus.
func (b *Bus) readLoop(r *bufio.Reader) {
	for {
		m, err := readMessage(r, b.wants)
		if errors.Is(err, errSkipped) {
			continue
		}
		if err != nil {
			b.end(err)
			return
		}
		switch m.Type {
		case typeReturn, typeError:
			b.mu.Lock()
			ch := b.calls[m.ReplySerial]
			delete(b.calls, m.ReplySerial)
			b.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case typeSignal:
			b.sigs.signal(m)
		}
	}
}

// wants reads a message's header.
func (b *Bus) wants(m *Message) bool {
	switch m.Type {
	case typeReturn, typeError:
		b.mu.Lock()
		_, ok := b.calls[m.ReplySerial]
		b.mu.Unlock()
		return ok
	case typeSignal:
		return b.sigs.wants(m)
	}
	return false
}

// readMessage reads one message, decoding its body only if keep takes its
// header; a message keep refuses is read past and skipped.
func readMessage(r io.Reader, keep func(*Message) bool) (*Message, error) {
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	head, n, err := frameLen(h[:])
	if errors.Is(err, errTooLong) {
		return nil, skip(r, n-16)
	}
	if err != nil {
		return nil, err // no byte order: the stream is lost
	}
	b := make([]byte, head) // at most 16+maxHeader+7; the body's buffer waits for keep
	copy(b, h[:])
	if _, err := io.ReadFull(r, b[16:]); err != nil {
		return nil, err
	}
	m, d, err := header(b)
	if err != nil {
		if err := skip(r, n-head); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", errSkipped, err)
	}
	if !keep(m) {
		return nil, skip(r, n-head)
	}
	b = append(b, make([]byte, n-head)...) // at most MaxMessage in all
	if _, err := io.ReadFull(r, b[head:]); err != nil {
		return nil, err
	}
	d.b = b
	if err := m.body(d); err != nil {
		return nil, fmt.Errorf("%w: %v", errSkipped, err)
	}
	return m, nil
}

// skip reads past n bytes, then reports the message skipped.
func skip(r io.Reader, n int64) error {
	if _, err := io.CopyN(io.Discard, r, n); err != nil {
		return err
	}
	return errSkipped
}

// errSkipped is a whole message read and dropped.
var errSkipped = errors.New("ble: message skipped")

func (b *Bus) end(err error) {
	b.mu.Lock()
	if b.err != nil {
		b.mu.Unlock()
		return
	}
	b.err = ErrBusClosed
	calls := b.calls
	b.calls = map[uint32]chan *Message{}
	b.mu.Unlock()
	b.conn.Close()
	for _, ch := range calls {
		close(ch)
	}
	close(b.done)
}
