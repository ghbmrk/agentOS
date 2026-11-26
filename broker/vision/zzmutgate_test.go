package vision

// REQ: DEV-7

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func detailOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// listen returns a unix socket path whose connections each go to handle.
func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.sock")
	ln, err := net.Listen("unix", path)
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
	return path
}

// Each way a call can fail to read its reply has its own detail.
func TestCallFailureDetails(t *testing.T) {
	hello := Request{Op: OpHello}
	closed := listen(t, func(c net.Conn) { c.Close() })
	big := make([]byte, 4<<20)
	detect := Request{Op: OpDetect, Format: FormatGray8, Width: 2048, Height: 2048, Bytes: len(big)}
	for name, c := range map[string]struct {
		path    string
		req     Request
		payload []byte
		timeout time.Duration
		want    string
	}{
		"too long": {serve(t, func(Request) []byte { return append(bytes.Repeat([]byte("a"), MaxReplyLine+2), '\n') }), hello, nil, time.Second, "reply line over its bound"},
		"no reply": {serve(t, func(Request) []byte { return nil }), hello, nil, time.Second, "no complete reply"},
		"cut short": {serve(t, func(Request) []byte { return []byte(`{"state"`) }), hello, nil, time.Second,
			"no complete reply"},
		"write failed": {closed, detect, big, 5 * time.Second, "write failed"},
	} {
		_, err := Client{Path: c.path, Timeout: c.timeout}.call(context.Background(), c.req, c.payload)
		if CauseOf(err) != Unavailable || detailOf(err) != c.want {
			t.Errorf("%s: %v, want unavailable %q", name, err, c.want)
		}
	}
}

// A header line over its bound is a bad request before any dial; one at
// the bound is sent.
func TestCallHeaderBound(t *testing.T) {
	base := len(`{"op":""}`)
	at := Request{Op: strings.Repeat("x", MaxHeaderLine-base)}
	over := Request{Op: strings.Repeat("x", MaxHeaderLine-base+1)}
	nowhere := Client{Path: filepath.Join(t.TempDir(), "none.sock")}
	if _, err := nowhere.call(context.Background(), at, nil); detailOf(err) != "service not reachable" {
		t.Fatalf("at the bound: %v", err)
	}
	if _, err := nowhere.call(context.Background(), over, nil); CauseOf(err) != BadRequest {
		t.Fatalf("over the bound: %v", err)
	}
}

// The call closes its connection when it returns.
func TestCallClosesConn(t *testing.T) {
	res := make(chan error, 1)
	path := listen(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		if _, err := c.Read(buf); err != nil {
			res <- err
			return
		}
		c.Write([]byte(`{"state":"ready","device":"cpu","model":"vis","sha256":"` + hash + `"}` + "\n"))
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(buf)
		res <- err
	})
	if _, err := (Client{Path: path, Timeout: 10 * time.Second}).call(context.Background(), Request{Op: OpHello}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-res; err != io.EOF {
		t.Fatalf("server's read after the reply: %v, want EOF", err)
	}
}

// A cancelled context ends a call blocked on a silent service at once,
// not at its timeout.
func TestCallCancelEndsRead(t *testing.T) {
	path := listen(t, func(c net.Conn) {
		defer c.Close()
		io.Copy(io.Discard, c)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := Client{Path: path, Timeout: 20 * time.Second}.call(ctx, Request{Op: OpHello}, nil)
	if d := time.Since(start); d > 5*time.Second || detailOf(err) != "deadline" {
		t.Fatalf("%v after %v", err, d)
	}
}

// foreignCtx has a Done channel of its own, so a context derived from it
// starts a goroutine that lives until the child is cancelled.
type foreignCtx struct {
	context.Context
	done chan struct{}
}

func (f foreignCtx) Done() <-chan struct{} { return f.done }

func watchers() int {
	b := make([]byte, 1<<20)
	return strings.Count(string(b[:runtime.Stack(b, true)]), "propagateCancel.func")
}

// The call cancels its own timeout context when it returns.
func TestCallReleasesContext(t *testing.T) {
	path := serve(t, func(Request) []byte {
		return []byte(`{"state":"ready","device":"cpu","model":"vis","sha256":"` + hash + `"}` + "\n")
	})
	before := watchers()
	f := foreignCtx{Context: context.Background(), done: make(chan struct{})}
	if _, err := (Client{Path: path, Timeout: time.Minute}).call(f, Request{Op: OpHello}, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && watchers() > before; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := watchers(); n > before {
		t.Fatalf("%d context watchers after the call, %d before", n, before)
	}
}

// readLine finds a newline that opens a read.
func TestReadLineNewlineFirstInRead(t *testing.T) {
	buf := make([]byte, 100)
	if l, err := readLine(io.MultiReader(strings.NewReader("abc"), strings.NewReader("\n")), buf); err != nil || string(l) != "abc" {
		t.Fatalf("%q %v", l, err)
	}
	if l, err := readLine(strings.NewReader("\nabc"), buf); err != nil || len(l) != 0 {
		t.Fatalf("%q %v", l, err)
	}
}

// A call's reply buffer holds a line at its bound and its newline.
func TestReplyBufSize(t *testing.T) {
	buf := replyBuf()
	if len(buf) != MaxReplyLine+1 {
		t.Fatalf("%d bytes", len(buf))
	}
	if l, err := readLine(strings.NewReader(strings.Repeat("a", MaxReplyLine)+"\n"), buf); err != nil || len(l) != MaxReplyLine {
		t.Fatalf("at the bound: %d %v", len(l), err)
	}
	if _, err := readLine(strings.NewReader(strings.Repeat("a", MaxReplyLine+1)+"\n"), buf); err != ErrLineTooLong {
		t.Fatalf("over the bound: %v", err)
	}
}

// An empty template string is a template of no bytes, refused by its
// check, not a malformed reply.
func TestDecodeEmptyTemplate(t *testing.T) {
	r, err := decodeReply([]byte(`{"template":""}`))
	if err != nil || r.Template == nil || len(r.Template) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	_, err = parseReply(Request{Op: OpEnrol}, []byte(`{"template":""}`), nil)
	if detailOf(err) != "template outside its bounds" {
		t.Fatalf("%v", err)
	}
	if _, err := decodeReply([]byte(`{"template":"}`)); err == nil {
		t.Fatal("a one-quote template was taken")
	}
}

// Enrol checks its frame before it dials.
func TestEnrolChecksFrame(t *testing.T) {
	c := ControlClient{Path: filepath.Join(t.TempDir(), "none.sock")}
	_, err := c.Enrol(context.Background(), Frame{Format: "bogus", Width: 1, Height: 1})
	if CauseOf(err) != BadRequest {
		t.Fatalf("%v", err)
	}
}

func TestRequestCheckHelloAndDetectBounds(t *testing.T) {
	if err := (Request{Op: OpHello}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := (Request{Op: OpHello, Width: 1}).Check(); detailOf(err) != "hello takes no fields" {
		t.Fatalf("%v", err)
	}
	if err := (Request{Op: OpDetect, Format: "bogus", Width: 1, Height: 1}).Check(); detailOf(err) != "unknown frame format" {
		t.Fatalf("%v", err)
	}
	det := func(w, h int) error {
		return Request{Op: OpDetect, Format: FormatGray8, Width: w, Height: h, Bytes: w * h}.Check()
	}
	for _, c := range []struct {
		w, h int
		ok   bool
	}{
		{1, 1, true}, {0, 1, false}, {1, 0, false},
		{MaxWidth, 1, true}, {MaxWidth + 1, 1, false},
		{1, MaxHeight, true}, {1, MaxHeight + 1, false},
		{MaxWidth, MaxHeight, true},
	} {
		if err := det(c.w, c.h); (err == nil) != c.ok {
			t.Errorf("%dx%d: %v", c.w, c.h, err)
		}
	}
}

func TestCheckTemplateLengthBounds(t *testing.T) {
	tpl := func(n int) []byte {
		b := make([]byte, n)
		for i := 0; i+4 <= n; i += 4 {
			binary.LittleEndian.PutUint32(b[i:], math.Float32bits(1))
		}
		return b
	}
	for _, c := range []struct {
		n  int
		ok bool
	}{{0, false}, {3, false}, {4, true}, {5, false}, {8, true}, {MaxTemplate - 4, true}, {MaxTemplate, true}, {MaxTemplate + 4, false}} {
		if err := CheckTemplate(tpl(c.n)); (err == nil) != c.ok {
			t.Errorf("%d bytes: %v", c.n, err)
		}
	}
}

func TestValidHashAndModelName(t *testing.T) {
	h := func(c string) string { return strings.Repeat("a", 63) + c }
	for s, ok := range map[string]bool{
		hash: true, "": false, "abc": false, strings.Repeat("a", 63): false, strings.Repeat("a", 65): false,
		h("0"): true, h("9"): true, h("a"): true, h("f"): true,
		h("/"): false, h(":"): false, h("`"): false, h("g"): false, h("A"): false, h("F"): false,
	} {
		if ValidHash(s) != ok {
			t.Errorf("ValidHash(%q) = %v", s, !ok)
		}
	}
	for s, ok := range map[string]bool{
		"": false, "a": true, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
		"z": true, "0": true, "9": true, ".": true, "_": true, "-": true,
		"`": false, "{": false, "/": false, ":": false, "A": false, " ": false, "a b": false, "é": false,
	} {
		if ValidModelName(s) != ok {
			t.Errorf("ValidModelName(%q) = %v", s, !ok)
		}
	}
}
