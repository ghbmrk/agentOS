package at

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// Engine runs AT commands (3GPP TS 27.007, ITU-T V.250) over one serial port
// and separates their responses from unsolicited result codes (URCs). One
// command runs at a time; URCs go to a buffered channel in arrival order.
type Engine struct {
	port io.ReadWriteCloser
	urc  func(string) bool // reports whether a line is a URC

	cmdMu sync.Mutex // one command at a time

	mu     sync.Mutex
	active *pending
	// stale is set after a timeout: a late final result may still arrive,
	// so the next command first resynchronizes with a bare AT.
	stale  bool
	closed bool
	err    error

	urcs chan string
	done chan struct{}
}

type pending struct {
	cmd    string
	resp   string          // "+CMGR" for AT+CMGR=1: its information lines are never URCs
	finals map[string]bool // extra final results (ATD, ATA)
	// marker, when set, must appear before a final result counts: finals
	// that arrive first belong to an earlier, timed-out command.
	marker string
	marked bool
	lines  []string
	prompt chan struct{}
	final  chan string
}

// Error is a command that ended in ERROR, +CME ERROR or +CMS ERROR, or in a
// call-setup final result such as NO CARRIER.
type Error struct {
	Cmd, Result string
}

func (e *Error) Error() string { return fmt.Sprintf("at: %s: %s", e.Cmd, e.Result) }

// ErrTimeout is a command the modem did not finish in time.
var ErrTimeout = errors.New("at: timeout")

// baseURCs are the TS 27.005/27.007 and V.250 unsolicited results.
var baseURCs = []string{"+CMTI:", "+CMT:", "+CDS:", "+CDSI:", "RING", "+CRING:", "+CLIP:", "+CCWA:",
	"NO CARRIER", "BUSY", "NO ANSWER", "+CUSD:", "+CREG:", "+CGREG:", "+CEREG:", "+CPIN:"}

// maxLine bounds one line from the modem. The longest real line is a
// 176-octet PDU in hex (352 characters).
const maxLine = 4096

// callFinals end ATD and ATA as well as OK and the errors.
var callFinals = map[string]bool{"NO CARRIER": true, "BUSY": true, "NO ANSWER": true, "NO DIALTONE": true}

// NewEngine starts reading port. extraURCs adds a vendor's URC prefixes.
func NewEngine(port io.ReadWriteCloser, extraURCs []string) *Engine {
	prefixes := append(append([]string(nil), baseURCs...), extraURCs...)
	e := &Engine{port: port, urcs: make(chan string, 256), done: make(chan struct{})}
	e.urc = func(l string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				return true
			}
		}
		return false
	}
	go e.read()
	return e
}

// URCs delivers unsolicited result codes. It is closed when the port fails.
func (e *Engine) URCs() <-chan string { return e.urcs }

// Done is closed when the port has failed or been closed.
func (e *Engine) Done() <-chan struct{} { return e.done }

// Close closes the port.
func (e *Engine) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	return e.port.Close()
}

func (e *Engine) read() {
	br := bufio.NewReader(e.port)
	var line []byte
	var err error
	overlong := false
	for {
		var b byte
		b, err = br.ReadByte()
		if err != nil {
			break
		}
		if overlong { // discard up to the next line end
			overlong = b != '\n'
			continue
		}
		if len(line) >= maxLine {
			line, overlong = line[:0], b != '\n'
			continue
		}
		switch b {
		case '\n':
			e.line(strings.TrimSpace(string(line)))
			line = line[:0]
			continue
		case '\r':
			if len(line) == 0 {
				continue
			}
		}
		line = append(line, b)
		// The SMS prompt "> " has no line end.
		if len(line) == 2 && line[0] == '>' && line[1] == ' ' {
			e.mu.Lock()
			if p := e.active; p != nil && p.prompt != nil {
				close(p.prompt)
				p.prompt = nil
			}
			e.mu.Unlock()
			line = line[:0]
		}
	}
	e.mu.Lock()
	e.err = err
	e.mu.Unlock()
	close(e.done)
	close(e.urcs)
}

func (e *Engine) line(l string) {
	if l == "" {
		return
	}
	e.mu.Lock()
	p := e.active
	e.mu.Unlock()
	if p != nil {
		if l == p.cmd { // echo before ATE0 takes effect
			return
		}
		if p.marker != "" && strings.HasPrefix(l, p.marker) {
			p.marked = true
			p.lines = append(p.lines, l)
			return
		}
		if (isFinal(l) || p.finals[l]) && p.marker != "" && !p.marked {
			return // a late final of the command that timed out
		}
		if isFinal(l) || p.finals[l] {
			e.mu.Lock()
			if e.active == p {
				e.active = nil
			}
			e.mu.Unlock()
			p.final <- l
			return
		}
		if (p.resp != "" && strings.HasPrefix(l, p.resp+":")) || !e.urc(l) {
			p.lines = append(p.lines, l)
			return
		}
	}
	if e.urc(l) {
		select {
		case e.urcs <- l:
		default: // a stalled reader loses URCs, never blocks responses
		}
	}
	// Anything else outside a command (late responses, banners) is dropped.
}

func isFinal(l string) bool {
	return l == "OK" || l == "ERROR" || strings.HasPrefix(l, "+CME ERROR") || strings.HasPrefix(l, "+CMS ERROR")
}

// Do runs cmd (without its trailing CR) and returns its information lines.
func (e *Engine) Do(ctx context.Context, cmd string, timeout time.Duration) ([]string, error) {
	return e.run(ctx, cmd, "", timeout)
}

// DoPrompt runs a command that answers with "> " and then takes payload
// ended by Ctrl-Z (AT+CMGS).
func (e *Engine) DoPrompt(ctx context.Context, cmd, payload string, timeout time.Duration) ([]string, error) {
	return e.run(ctx, cmd, payload, timeout)
}

func (e *Engine) run(ctx context.Context, cmd, payload string, timeout time.Duration) ([]string, error) {
	e.cmdMu.Lock()
	defer e.cmdMu.Unlock()
	e.mu.Lock()
	stale := e.stale
	e.stale = false
	e.mu.Unlock()
	if stale {
		// Resynchronize on a reply only this probe produces: any final
		// result before its +CSQ line is a late answer to the command that
		// timed out, and is dropped.
		if _, err := e.exchangeMarked(ctx, "AT+CSQ", "+CSQ:", 2*time.Second); err != nil {
			e.mu.Lock()
			e.stale = true
			e.mu.Unlock()
			return nil, err
		}
	}
	lines, err := e.exchange(ctx, cmd, payload, timeout)
	if err == ErrTimeout || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		e.mu.Lock()
		e.stale = true
		e.mu.Unlock()
	}
	return lines, err
}

func (e *Engine) exchange(ctx context.Context, cmd, payload string, timeout time.Duration) ([]string, error) {
	return e.exchangeWith(ctx, &pending{cmd: cmd, resp: respPrefix(cmd), final: make(chan string, 1)}, payload, timeout)
}

func (e *Engine) exchangeMarked(ctx context.Context, cmd, marker string, timeout time.Duration) ([]string, error) {
	return e.exchangeWith(ctx, &pending{cmd: cmd, marker: marker, final: make(chan string, 1)}, "", timeout)
}

func (e *Engine) exchangeWith(ctx context.Context, p *pending, payload string, timeout time.Duration) ([]string, error) {
	cmd := p.cmd
	if strings.HasPrefix(cmd, "ATD") || cmd == "ATA" {
		p.finals = callFinals
	}
	var prompt chan struct{}
	if payload != "" {
		prompt = make(chan struct{})
		p.prompt = prompt
	}
	e.mu.Lock()
	if e.closed || e.err != nil {
		e.mu.Unlock()
		return nil, modem.ErrDown
	}
	e.active = p
	e.mu.Unlock()
	clear := func() {
		e.mu.Lock()
		if e.active == p {
			e.active = nil
		}
		e.mu.Unlock()
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	if _, err := io.WriteString(e.port, cmd+"\r"); err != nil {
		clear()
		return nil, modem.ErrDown
	}
	if prompt != nil {
		select {
		case <-prompt:
		case f := <-p.final:
			return nil, &Error{Cmd: cmd, Result: f}
		case <-t.C:
			clear()
			_, _ = e.port.Write([]byte{0x1B}) // ESC cancels the pending text
			return nil, ErrTimeout
		case <-ctx.Done():
			clear()
			_, _ = e.port.Write([]byte{0x1B})
			return nil, ctx.Err()
		case <-e.done:
			return nil, modem.ErrDown
		}
		if _, err := io.WriteString(e.port, payload+"\x1a"); err != nil {
			clear()
			return nil, modem.ErrDown
		}
	}
	select {
	case f := <-p.final:
		if f != "OK" {
			return p.lines, &Error{Cmd: cmd, Result: f}
		}
		return p.lines, nil
	case <-t.C:
		clear()
		return nil, ErrTimeout
	case <-ctx.Done():
		clear()
		return nil, ctx.Err()
	case <-e.done:
		return nil, modem.ErrDown
	}
}

// respPrefix is the information-line prefix of an extended command:
// "+CLCC" for AT+CLCC, "+CMGR" for AT+CMGR=3.
func respPrefix(cmd string) string {
	if !strings.HasPrefix(cmd, "AT+") {
		return ""
	}
	n := cmd[2:]
	if i := strings.IndexAny(n, "=?"); i >= 0 {
		n = n[:i]
	}
	return n
}
