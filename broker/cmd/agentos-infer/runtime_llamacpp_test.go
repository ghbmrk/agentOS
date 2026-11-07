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
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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
	for _, p := range []string{"crash", "hang", "status", "malformed", "huge", "count", "extra", "short", "dup"} {
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
	if vs, err := l.Embed([]string{"x", "extra"}); err == nil {
		t.Errorf("a thousand extra vectors were accepted: %d vectors", len(vs))
	}
	if vs, err := l.Embed([]string{"huge"}); err == nil {
		t.Errorf("a reply over its bound was read: %d vectors", len(vs))
	}
	if vs, err := l.Embed([]string{"status"}); err == nil {
		t.Errorf("an error status was read as vectors: %v", vs)
	}
}

// The adapter checks the status itself: a well-formed body under an error
// status is refused here, not only by the service's checks after it.
func TestLlamaAdapterChecksTheStatusItself(t *testing.T) {
	l := newLlama(t)
	if _, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3)))); err != nil {
		t.Fatal(err)
	}
	if vs, err := l.Embed([]string{"okbody"}); !errors.Is(err, errHTTP) {
		t.Fatalf("a well-formed reply under status 500: %v, %v; want errHTTP", vs, err)
	}
}

// llamaDirs lists the socket directories under tmp.
func llamaDirs(t *testing.T, tmp string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(tmp, dirPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// privateTmp points os.TempDir at a fresh directory for the test.
func privateTmp(t *testing.T) string {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	return tmp
}

// A server that answers health and then hangs on the dimension probe fails
// the load within the call bound, not the HTTP client's 10-minute backstop.
func TestLlamaDimensionProbeKeepsToTheCallBound(t *testing.T) {
	if l := newRuntime("x", 7*time.Second).(*llama); l.probe != 7*time.Second {
		t.Fatalf("newRuntime's probe bound = %v; want the call bound", l.probe)
	}
	tmp := privateTmp(t)
	l := newLlama(t)
	l.probe = 300 * time.Millisecond
	start := time.Now()
	_, err := l.Load(writeModel(t, "hangprobe.gguf", gguf("qwen3", u32(3))))
	if err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("a hung probe: Load = %v; want an ordinary error", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("a hung probe held Load for %s", d)
	}
	if l.cur != nil || len(llamaDirs(t, tmp)) != 0 {
		t.Fatalf("a hung probe left a server: %v %v", l.cur, llamaDirs(t, tmp))
	}
}

// A probe that answers a bad dimension stops the server it ran on.
func TestLlamaFailedProbeStopsTheServer(t *testing.T) {
	tmp := privateTmp(t)
	l := newLlama(t)
	if _, err := l.Load(writeModel(t, "badprobe.gguf", gguf("qwen3", u32(3)))); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("a bad probe: Load = %v; want an ordinary error", err)
	}
	if l.cur != nil {
		t.Fatal("a failed probe left the server current")
	}
	if d := llamaDirs(t, tmp); len(d) != 0 {
		t.Fatalf("a failed probe left a socket directory: %v", d)
	}
}

// Two Loads at once leave one server: neither replaces a server the other
// started without stopping it.
func TestLlamaConcurrentLoadsLeaveOneServer(t *testing.T) {
	tmp := privateTmp(t)
	l := newLlama(t)
	m := writeModel(t, "e.gguf", gguf("qwen3", u32(3)))
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); l.Load(m) }()
		}
		wg.Wait()
		d := llamaDirs(t, tmp)
		if l.cur == nil || len(d) != 1 || d[0] != l.cur.dir {
			t.Fatalf("round %d: socket directories %v, current %v; want the current server's alone", round, d, l.cur)
		}
	}
	l.stop()
	if d := llamaDirs(t, tmp); len(d) != 0 {
		t.Fatalf("after stop: %v", d)
	}
}

// A service killed outright leaves its socket directory; the next start
// removes it, and only directories this uid made for a process now gone.
func TestLlamaStartSweepsDeadServicesDirs(t *testing.T) {
	tmp := privateTmp(t)
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Skip("no true to run:", err)
	}
	dead := gone.Process.Pid
	mk := func(name string) string {
		p := filepath.Join(tmp, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(p, "s.sock"), nil, 0o600)
		return p
	}
	deadDir := mk(fmt.Sprintf("%s%d-1", dirPrefix, dead))
	liveDir := mk(fmt.Sprintf("%s%d-2", dirPrefix, os.Getpid()))
	oldDir := mk(dirPrefix + "123456") // no pid in the name: not this sweep's to judge
	target := t.TempDir()
	link := filepath.Join(tmp, fmt.Sprintf("%s%d-3", dirPrefix, dead))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tmp, fmt.Sprintf("%s%d-4", dirPrefix, dead))
	os.WriteFile(file, nil, 0o600)

	l := newLlama(t)
	if _, err := l.Load(writeModel(t, "e.gguf", gguf("qwen3", u32(3)))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deadDir); !os.IsNotExist(err) {
		t.Errorf("a dead service's directory remains: %v", err)
	}
	for _, p := range []string{liveDir, oldDir, link, file, target} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
}

// The reply's data array is refused at its first entry past the number of
// texts, before the rest is decoded: a reply of millions of {} entries
// holds at most max of them (#3771 item 7).
func TestLlamaReplyDecodeStopsPastTheTextCount(t *testing.T) {
	raw := []byte("[" + strings.Repeat(`{"index":0},`, 100000) + `{"index":0}]`)
	d := embedData{max: 2}
	if err := d.UnmarshalJSON(raw); err == nil {
		t.Fatalf("%d entries for 2 texts were decoded without error", len(d.list))
	}
	if len(d.list) > 2 {
		t.Fatalf("decoded %d entries before refusing; want at most 2", len(d.list))
	}
	for _, ok := range []string{`[]`, `null`, `[{"index":0,"embedding":[1]},{"index":1}]`} {
		d := embedData{max: 2}
		if err := d.UnmarshalJSON([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{`{}`, `"x"`, `[1]`} {
		d := embedData{max: 2}
		if err := d.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("%s was decoded as data", bad)
		}
	}
}
