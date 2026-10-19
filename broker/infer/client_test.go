package infer

// REQ: ARC-2, DEP-1

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// serve answers each connection's first request line with reply(req).
// A nil reply closes the connection unanswered; a reply holding "SLEEP"
// sleeps instead of answering.
func serve(t *testing.T, reply func(Request) []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
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
			go func() {
				defer c.Close()
				line, err := ReadLine(bufio.NewReader(c), MaxRequestLine)
				if err != nil {
					return
				}
				var req Request
				if json.Unmarshal(line, &req) != nil {
					return
				}
				b := reply(req)
				if string(b) == "SLEEP" {
					time.Sleep(5 * time.Second)
					return
				}
				c.Write(b)
			}()
		}
	}()
	return path
}

func vec(dim int, x float32) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = x + float32(i)
	}
	return v
}

func line(t *testing.T, r Reply) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestProtocolRoundTrip(t *testing.T) {
	path := serve(t, func(req Request) []byte {
		if req.Op == OpHello {
			return line(t, Reply{Model: "synthetic", SHA256: hash, Dim: 4, State: StateReady})
		}
		r := Reply{SHA256: hash, Dim: 4}
		for i := range req.Texts {
			r.Vectors = append(r.Vectors, vec(4, float32(i)))
		}
		return line(t, r)
	})
	c := Client{Path: path}
	in, err := c.Hello(context.Background())
	if err != nil || in != (Info{Model: "synthetic", SHA256: hash, Dim: 4}) {
		t.Fatalf("hello: %+v, %v", in, err)
	}
	vs, in, err := c.Embed(context.Background(), []string{"alpha", "beta", "gamma"})
	if err != nil || len(vs) != 3 || in.SHA256 != hash || in.Dim != 4 {
		t.Fatalf("embed: %v %+v %v", vs, in, err)
	}
	for i, v := range vs {
		if v[0] != float32(i) || len(v) != 4 {
			t.Fatalf("vector %d: %v", i, v)
		}
	}
}

// The service is untrusted: anything but a well-formed reply of the right
// shape is Unavailable and no vectors (INF-2).
func TestClientRejectsMalformedReplies(t *testing.T) {
	good := func(n int) Reply {
		r := Reply{SHA256: hash, Dim: 3}
		for i := 0; i < n; i++ {
			r.Vectors = append(r.Vectors, vec(3, 1))
		}
		return r
	}
	for _, c := range []struct {
		name  string
		reply func(*testing.T, Request) []byte
	}{
		{"wrong count", func(t *testing.T, r Request) []byte { return line(t, good(len(r.Texts)+1)) }},
		{"too few", func(t *testing.T, r Request) []byte { return line(t, good(len(r.Texts)-1)) }},
		{"wrong dim", func(t *testing.T, r Request) []byte {
			g := good(len(r.Texts))
			g.Vectors[1] = vec(4, 1)
			return line(t, g)
		}},
		{"zero dim", func(t *testing.T, r Request) []byte {
			return line(t, Reply{SHA256: hash, Vectors: [][]float32{{}, {}}})
		}},
		{"NaN", func(t *testing.T, r Request) []byte {
			return []byte(`{"sha256":"` + hash + `","dim":3,"vectors":[[1,2,NaN],[1,2,3]]}` + "\n")
		}},
		{"Inf", func(t *testing.T, r Request) []byte {
			return []byte(`{"sha256":"` + hash + `","dim":3,"vectors":[[1,2,1e39],[1,2,3]]}` + "\n")
		}},
		{"bad hash", func(t *testing.T, r Request) []byte {
			g := good(len(r.Texts))
			g.SHA256 = strings.ToUpper(hash)
			return line(t, g)
		}},
		{"over-long line", func(t *testing.T, r Request) []byte {
			return append([]byte(`{"detail":"`+strings.Repeat("x", MaxReplyLine)), '"', '}', '\n')
		}},
		{"truncated JSON", func(t *testing.T, r Request) []byte {
			b := line(t, good(len(r.Texts)))
			return append(b[:len(b)/2], '\n')
		}},
		{"EOF mid-reply", func(t *testing.T, r Request) []byte {
			b := line(t, good(len(r.Texts)))
			return b[:len(b)/2]
		}},
		{"closed unanswered", func(t *testing.T, r Request) []byte { return nil }},
		{"deadline", func(t *testing.T, r Request) []byte { return []byte("SLEEP") }},
		{"unknown cause", func(t *testing.T, r Request) []byte { return []byte(`{"error":"fine"}` + "\n") }},
		{"hello fields", func(t *testing.T, r Request) []byte {
			g := good(len(r.Texts))
			g.State = StateReady
			return line(t, g)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := serve(t, func(r Request) []byte { return c.reply(t, r) })
			start := time.Now()
			vs, _, err := Client{Path: path, Timeout: 300 * time.Millisecond}.Embed(context.Background(), []string{"a", "b"})
			if vs != nil || CauseOf(err) != Unavailable {
				t.Fatalf("got %v, %v; want no vectors and unavailable", vs, err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("the call outlived its deadline")
			}
		})
	}
}

func TestClientPassesTheServiceCause(t *testing.T) {
	for _, cause := range []Cause{Missing, Corrupt, Unavailable, BadRequest} {
		path := serve(t, func(Request) []byte { return line(t, Reply{Error: cause, Detail: "synthetic\x00detail"}) })
		_, err := Client{Path: path}.Hello(context.Background())
		var e *Error
		if !errors.As(err, &e) || e.Cause != cause || strings.ContainsRune(e.Detail, 0) {
			t.Fatalf("%s: got %v", cause, err)
		}
	}
}

// Removal (-infer=false): no socket, and the client says unavailable.
func TestClientWithoutServiceIsUnavailable(t *testing.T) {
	_, _, err := Client{Path: filepath.Join(t.TempDir(), "absent.sock")}.Embed(context.Background(), []string{"a"})
	if CauseOf(err) != Unavailable {
		t.Fatal(err)
	}
}

func TestClientChecksBoundsBeforeSending(t *testing.T) {
	var sent atomic.Bool
	path := serve(t, func(Request) []byte { sent.Store(true); return nil })
	for name, texts := range map[string][]string{
		"none":     nil,
		"65 texts": make([]string, MaxTexts+1),
		"9 KiB":    {strings.Repeat("x", 9<<10)},
	} {
		_, _, err := Client{Path: path}.Embed(context.Background(), texts)
		if CauseOf(err) != BadRequest {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if sent.Load() {
		t.Fatal("an oversize request reached the service")
	}
}

func TestReadLineBound(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want error
	}{
		{"abc\n", 3, nil},
		{"abcd\n", 3, ErrLineTooLong},
		{"abc", 3, errors.New("unexpected EOF")},
		{"", 3, errors.New("EOF")},
	} {
		_, err := ReadLine(bufio.NewReaderSize(strings.NewReader(c.in), 16), c.max)
		if (err == nil) != (c.want == nil) || err != nil && err.Error() != c.want.Error() && err != c.want {
			t.Fatalf("%q: %v, want %v", c.in, err, c.want)
		}
	}
	// A long line is refused without being read whole.
	big := strings.Repeat("y", 1<<20) + "\n"
	if _, err := ReadLine(bufio.NewReaderSize(strings.NewReader(big), 16), 64); err != ErrLineTooLong {
		t.Fatal(err)
	}
}
