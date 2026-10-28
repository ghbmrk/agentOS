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

// serve answers each request line on a connection with reply(req). A nil
// reply closes the connection unanswered; a reply holding "SLEEP" sleeps
// instead of answering.
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
				br := bufio.NewReader(c)
				for {
					line, err := ReadLine(br, MaxRequestLine)
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
					if b == nil {
						return
					}
					c.Write(b)
				}
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
			return line(t, Reply{Model: "synthetic", SHA256: hash, Dim: 4, State: StateReady, Ops: []string{OpEmbed}})
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

// REQ: PLN-7, RES-2
//
// The local route's text comes from an untrusted service: anything but a
// well-formed reply from the model hello named is Unavailable and no text.
func TestClientRejectsMalformedGenerate(t *testing.T) {
	text := func(s string) *string { return &s }
	hello := Reply{Model: "synthetic-gen", SHA256: hash, State: StateReady, Ops: []string{OpGenerate}}
	other := strings.Replace(hash, "0", "f", 1)
	for _, c := range []struct {
		name  string
		reply func(*testing.T, Request) []byte
	}{
		{"over-long text", func(t *testing.T, r Request) []byte {
			return line(t, Reply{SHA256: hash, Text: text(strings.Repeat("y", MaxGenerate+1))})
		}},
		{"invalid UTF-8", func(t *testing.T, r Request) []byte {
			return []byte(`{"sha256":"` + hash + `","text":"synthetic` + "\xff" + `"}` + "\n")
		}},
		{"no text", func(t *testing.T, r Request) []byte { return line(t, Reply{SHA256: hash}) }},
		{"wrong hash", func(t *testing.T, r Request) []byte { return line(t, Reply{SHA256: other, Text: text("synthetic")}) }},
		{"no hash", func(t *testing.T, r Request) []byte { return line(t, Reply{Text: text("synthetic")}) }},
		{"hello fields", func(t *testing.T, r Request) []byte {
			return line(t, Reply{SHA256: hash, Text: text("synthetic"), State: StateReady})
		}},
		{"vectors too", func(t *testing.T, r Request) []byte {
			return line(t, Reply{SHA256: hash, Text: text("synthetic"), Vectors: [][]float32{{1}}})
		}},
		{"EOF mid-line", func(t *testing.T, r Request) []byte {
			b := line(t, Reply{SHA256: hash, Text: text("synthetic")})
			return b[:len(b)/2]
		}},
		{"closed unanswered", func(t *testing.T, r Request) []byte { return nil }},
		{"deadline", func(t *testing.T, r Request) []byte { return []byte("SLEEP") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := serve(t, func(r Request) []byte {
				if r.Op == OpHello {
					return line(t, hello)
				}
				return c.reply(t, r)
			})
			start := time.Now()
			got, in, err := Client{Path: path, GenerateTimeout: 300 * time.Millisecond}.Generate(context.Background(), "synthetic prompt", 16)
			if got != "" || in != (Info{}) || CauseOf(err) != Unavailable {
				t.Fatalf("got %q, %+v, %v; want no text and unavailable", got, in, err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("the call outlived its deadline")
			}
		})
	}
}

// REQ: PLN-7
func TestGenerateRoundTripOnTheWire(t *testing.T) {
	var prompts atomic.Int32
	path := serve(t, func(r Request) []byte {
		if r.Op == OpHello {
			return line(t, Reply{Model: "synthetic-gen", SHA256: hash, State: StateReady, Ops: []string{OpEmbed, OpGenerate}, Dim: 4})
		}
		prompts.Add(1)
		s := "synthetic answer to " + r.Prompt
		return line(t, Reply{SHA256: hash, Text: &s})
	})
	got, in, err := Client{Path: path}.Generate(context.Background(), "question", 8)
	if err != nil || got != "synthetic answer to question" || in != (Info{Model: "synthetic-gen", SHA256: hash, Dim: 4, Generate: true}) {
		t.Fatalf("generate: %q %+v %v", got, in, err)
	}
	// An empty generation is text, not a missing reply.
	path = serve(t, func(r Request) []byte {
		if r.Op == OpHello {
			return line(t, Reply{SHA256: hash, State: StateReady, Ops: []string{OpGenerate}})
		}
		return []byte(`{"sha256":"` + hash + `","text":""}` + "\n")
	})
	if got, _, err := (Client{Path: path}).Generate(context.Background(), "question", 8); err != nil || got != "" {
		t.Fatalf("empty generation: %q %v", got, err)
	}
	if prompts.Load() != 1 {
		t.Fatalf("%d prompts sent, want 1", prompts.Load())
	}
}

// A hello that misstates what the model serves is Unavailable, and a model
// that does not serve generate never sees the prompt.
func TestClientChecksHelloOps(t *testing.T) {
	for name, r := range map[string]Reply{
		"no ops":          {SHA256: hash, State: StateReady, Dim: 4},
		"unknown op":      {SHA256: hash, State: StateReady, Ops: []string{"chat"}},
		"repeated op":     {SHA256: hash, State: StateReady, Ops: []string{OpGenerate, OpGenerate}},
		"embed, no dim":   {SHA256: hash, State: StateReady, Ops: []string{OpEmbed}},
		"dim, no embed":   {SHA256: hash, State: StateReady, Ops: []string{OpGenerate}, Dim: 4},
		"text with hello": {SHA256: hash, State: StateReady, Ops: []string{OpGenerate}, Text: new(string)},
	} {
		path := serve(t, func(Request) []byte { return line(t, r) })
		if _, err := (Client{Path: path}).Hello(context.Background()); CauseOf(err) != Unavailable {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var sent atomic.Bool
	path := serve(t, func(r Request) []byte {
		if r.Op == OpGenerate {
			sent.Store(true)
		}
		return line(t, Reply{SHA256: hash, State: StateReady, Ops: []string{OpEmbed}, Dim: 4})
	})
	if _, _, err := (Client{Path: path}).Generate(context.Background(), "synthetic", 8); CauseOf(err) != Missing {
		t.Fatalf("embed-only model: %v", err)
	}
	if sent.Load() {
		t.Fatal("the prompt reached a model that does not serve generate")
	}
}

// REQ: PLN-7
func TestClientChecksGenerateBoundsBeforeSending(t *testing.T) {
	var sent atomic.Bool
	path := serve(t, func(Request) []byte { sent.Store(true); return nil })
	for name, c := range map[string]struct {
		prompt string
		max    int
	}{
		"empty prompt":  {"", 8},
		"33 KiB prompt": {strings.Repeat("x", 33<<10), 8},
		"max_out 0":     {"synthetic", 0},
		"max_out 1025":  {"synthetic", MaxOut + 1},
	} {
		if _, _, err := (Client{Path: path}).Generate(context.Background(), c.prompt, c.max); CauseOf(err) != BadRequest {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if sent.Load() {
		t.Fatal("an out-of-bounds request reached the service")
	}
}
