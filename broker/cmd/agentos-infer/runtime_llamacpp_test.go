//go:build infer_llamacpp

package main

// REQ: PLN-7, RES-2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/infer"
)

// gguf builds a minimal GGUF header: the architecture, a tokenizer-style
// string array and a few other value types to be skipped, and a pooling
// type when pooling is not nil. It has no tensors.
func gguf(arch string, pooling *uint32) []byte {
	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	str := func(s string) { w(uint64(len(s))); b.WriteString(s) }
	n := uint64(5)
	if pooling != nil {
		n++
	}
	b.WriteString("GGUF")
	w(uint32(3))
	w(uint64(0))
	w(n)
	str("general.architecture")
	w(uint32(8))
	str(arch)
	str("general.size")
	w(uint32(10))
	w(uint64(1 << 40))
	str("tokenizer.ggml.tokens")
	w(uint32(9))
	w(uint32(8))
	w(uint64(3))
	str("a")
	str("bb")
	str("ccc")
	str("tokenizer.ggml.scores")
	w(uint32(9))
	w(uint32(6))
	w(uint64(2))
	w(float32(1))
	w(float32(2))
	str("general.flag")
	w(uint32(7))
	w(uint8(1))
	if pooling != nil {
		str(arch + ".pooling_type")
		w(uint32(4))
		w(*pooling)
	}
	return b.Bytes()
}

// withLlama says this build links the llama.cpp adapter.
const withLlama = true

func ctx(t *testing.T) context.Context { return context.Background() }

// unavailable is true for an error whose cause is unavailable; no error is not.
func unavailable(err error) bool { return err != nil && infer.CauseOf(err) == infer.Unavailable }

func u32(v uint32) *uint32 { return &v }

func writeModel(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o444); err != nil {
		t.Fatal(err)
	}
	return p
}

// newLlama is the adapter over the test binary standing in for llama-server.
func newLlama(t *testing.T) *llama {
	t.Helper()
	l := &llama{exe: os.Args[0], ready: 5 * time.Second}
	t.Cleanup(l.stop)
	return l
}

func TestLlamaModeComesFromTheGGUFHeader(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		embed   bool
		refused bool
	}{
		{"generate model has no pooling type", gguf("qwen3", nil), false, false},
		{"pooling none is generate", gguf("qwen3", u32(0)), false, false},
		{"mean pooling is embed", gguf("bert", u32(1)), true, false},
		{"cls pooling is embed", gguf("bert", u32(2)), true, false},
		{"last-token pooling is embed", gguf("qwen3", u32(3)), true, false},
		{"rank pooling is refused", gguf("bert", u32(4)), false, true},
		{"not a GGUF is refused", []byte("this is not a model file at all"), false, true},
		{"a truncated header is refused", gguf("qwen3", nil)[:40], false, true},
		{"an absurd key count is refused", append(append([]byte("GGUF"), 3, 0, 0, 0), bytes.Repeat([]byte{0xff}, 16)...), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			embed, err := modelIsEmbedding(writeModel(t, "m.gguf", c.data))
			if (err != nil) != c.refused || embed != c.embed {
				t.Fatalf("embed %v err %v; want embed %v refused %v", embed, err, c.embed, c.refused)
			}
		})
	}
	if _, err := modelIsEmbedding(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("an absent file is not a model")
	}
}

func TestLlamaDeeplyNestedArraysAreRefused(t *testing.T) {
	// nested builds a well-formed GGUF whose one value is an array nested
	// levels deep. Real files use one level; a hostile one must not drive the
	// header reader's recursion, so past maxGGUFDepth it is refused.
	nested := func(levels int) []byte {
		var b bytes.Buffer
		w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
		b.WriteString("GGUF")
		w(uint32(3))
		w(uint64(0))
		w(uint64(2))
		w(uint64(len("general.architecture")))
		b.WriteString("general.architecture")
		w(uint32(8))
		w(uint64(len("qwen3")))
		b.WriteString("qwen3")
		w(uint64(len("x")))
		b.WriteString("x")
		w(uint32(9))
		for i := 1; i < levels; i++ {
			w(uint32(9)) // element type: an array
			w(uint64(1))
		}
		w(uint32(4)) // innermost: an empty array of u32
		w(uint64(0))
		return b.Bytes()
	}
	if _, err := modelIsEmbedding(writeModel(t, "ok.gguf", nested(maxGGUFDepth))); err != nil {
		t.Fatalf("%d levels refused: %v", maxGGUFDepth, err)
	}
	if _, err := modelIsEmbedding(writeModel(t, "deep.gguf", nested(maxGGUFDepth+1))); err == nil {
		t.Fatalf("%d levels accepted", maxGGUFDepth+1)
	}
}

func TestLlamaRefusedModelIsErrRefused(t *testing.T) {
	l := newLlama(t)
	for name, data := range map[string][]byte{
		"junk":                 []byte("junk"),
		"a generative model":   gguf("qwen3", nil),
		"a ranking model":      gguf("bert", u32(4)),
		"pooling none (a LLM)": gguf("qwen3", u32(0)),
	} {
		if _, err := l.Load(writeModel(t, "m.gguf", data)); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: Load = %v; want ErrRefused", name, err)
		}
		if l.cur != nil {
			t.Errorf("%s: a refused model left a server", name)
		}
	}
}

func TestLlamaStartsALockedDownEmbeddingServer(t *testing.T) {
	t.Setenv("AGENTOS_CANARY_SECRET", "canary-value-not-a-secret")
	l := newLlama(t)
	dim, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3))))
	if err != nil || dim != fakeDim {
		t.Fatalf("Load = %d, %v; want the probe's %d", dim, err, fakeDim)
	}
	dir := l.cur.dir
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	for _, want := range []string{"--host\n" + filepath.Join(dir, "s.sock"), "--embedding", "--offline",
		"--no-webui", "--no-slots", "--parallel\n2", "--ctx-size\n4096", "--gpu-layers\n0"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("argv lacks %q: %q", want, argv)
		}
	}
	if strings.Contains(string(argv), "--port") || strings.Contains(string(argv), "--pooling") {
		t.Errorf("argv names a port: %q", argv)
	}
	// INF-8: the server's output goes nowhere, so nothing it logs reaches the service's.
	if fds, _ := os.ReadFile(filepath.Join(dir, "fds")); string(fds) != "/dev/null\n/dev/null" {
		t.Errorf("the server's stdout and stderr are %q; want /dev/null for both", fds)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if string(env) != "PATH=/usr/bin:/bin" {
		t.Errorf("the server's environment is %q; want PATH alone", env)
	}
}

func TestLlamaEmbedPlacesVectorsByIndex(t *testing.T) {
	l := newLlama(t)
	if _, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3)))); err != nil {
		t.Fatal(err)
	}
	vs, err := l.Embed([]string{"a", "bbb", "cc"})
	if err != nil || len(vs) != 3 {
		t.Fatalf("Embed = %v, %v", vs, err)
	}
	for i, n := range []int{1, 3, 2} {
		if len(vs[i]) != fakeDim || vs[i][0] != float32(n*10)/1000 {
			t.Errorf("vector %d = %v; want the vector of a %d-byte text", i, vs[i], n)
		}
	}
}

func TestLlamaLoadReplacesTheServer(t *testing.T) {
	l := newLlama(t)
	m := writeModel(t, "e.gguf", gguf("qwen3", u32(3)))
	if _, err := l.Load(m); err != nil {
		t.Fatal(err)
	}
	old := l.cur
	if _, err := l.Load(m); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("the old server still runs after a second Load")
	}
	if _, err := os.Stat(old.dir); !os.IsNotExist(err) {
		t.Fatalf("the old socket directory remains: %v", err)
	}
	l.stop()
	if _, err := l.Embed([]string{"x"}); err == nil {
		t.Fatal("a call after stop found a server")
	}
}

func TestLlamaLoadFailureLeavesNothingRunning(t *testing.T) {
	l := newLlama(t)
	l.ready = 300 * time.Millisecond
	if _, err := l.Load(writeModel(t, "slowstart.gguf", gguf("qwen3", u32(3)))); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("a server that never answers: Load = %v; want an ordinary error", err)
	}
	if l.cur != nil {
		t.Fatal("a failed Load left a server")
	}
	l.exe = filepath.Join(t.TempDir(), "absent")
	if _, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3)))); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("an absent executable: Load = %v; want an ordinary error", err)
	}
}

// lockedBuf is a log the service and the test both touch.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// llamaRig is the service over the adapter, on a unix socket.
func llamaRig(t *testing.T, name string, log io.Writer) infer.Client {
	t.Helper()
	model := gguf("qwen3", u32(3))
	path := writeModel(t, name, model)
	sum := sha256.Sum256(model)
	cfg := Config{Name: "fake", Model: path, Pin: hex.EncodeToString(sum[:]),
		CallTimeout: time.Second, Retry: 50 * time.Millisecond}
	sock := filepath.Join(t.TempDir(), "infer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newService(cfg, newLlama(t), log).Serve(ln)
	return infer.Client{Path: sock, Timeout: 10 * time.Second}
}

func TestLlamaEmbedFailuresAreUnavailableThenRecover(t *testing.T) {
	c := llamaRig(t, "e.gguf", nil)
	in, err := c.Hello(ctx(t))
	if err != nil || in.Dim != fakeDim {
		t.Fatalf("hello = %+v, %v", in, err)
	}
	vs, _, err := c.Embed(ctx(t), []string{"a", "bb"})
	if err != nil || len(vs) != 2 {
		t.Fatalf("first call: %v, %v", vs, err)
	}
	for _, p := range []string{"crash", "hang", "status", "malformed", "huge", "count", "short", "dup"} {
		if vs, _, err := c.Embed(ctx(t), []string{"x", p}); !unavailable(err) || vs != nil {
			t.Errorf("text %q: %v, %v; want unavailable and no vectors", p, vs, err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			vs, _, err = c.Embed(ctx(t), []string{"again"})
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil || len(vs) != 1 {
			t.Errorf("after %q: %v, %v; the service did not recover", p, vs, err)
		}
	}
}

func TestLlamaLogsCarryNoText(t *testing.T) {
	var log lockedBuf
	c := llamaRig(t, "e.gguf", &log)
	if _, _, err := c.Embed(ctx(t), []string{"log"}); err != nil { // the fake writes the text to its stderr
		t.Fatal(err)
	}
	if _, _, err := c.Embed(ctx(t), []string{"CANARY-TEXT-7f3a"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "CANARY-TEXT") || strings.Contains(log.String(), "log\n") {
		t.Fatalf("the service log carries request text: %q", log.String())
	}
}

// The adapter itself refuses what it cannot place or bound, before the
// service's own checks see it.
func TestLlamaAdapterRefusesUnplaceableAndOversizeReplies(t *testing.T) {
	l := newLlama(t)
	if _, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3)))); err != nil {
		t.Fatal(err)
	}
	if vs, err := l.Embed([]string{"x", "dup"}); err == nil {
		t.Errorf("two vectors for one index were placed: %v", vs)
	}
	if vs, err := l.Embed([]string{"x", "count"}); err == nil {
		t.Errorf("one vector for two texts was accepted: %v", vs)
	}
	if vs, err := l.Embed([]string{"huge"}); err == nil {
		t.Errorf("a reply over its bound was read: %d vectors", len(vs))
	}
	if vs, err := l.Embed([]string{"status"}); err == nil {
		t.Errorf("an error status was read as vectors: %v", vs)
	}
}
