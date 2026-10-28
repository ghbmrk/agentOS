package main

// REQ: ARC-2, DEP-1

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/infer"
)

// helperArg makes the test binary run main, for the fd-3 test.
const helperArg = "agentos-infer-main"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperArg {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		return
	}
	os.Exit(m.Run())
}

// fake is the CI runtime: a fixed concept-table vector per text (a hash of
// the text spread over dim floats), with switches to refuse the model, fail
// loads, crash, panic, hang or answer malformed vectors on the next calls.
type fake struct {
	dim int

	mu      sync.Mutex
	refuse  bool
	noLoad  bool
	mode    string // "", "crash", "panic", "hang", "short", "nan", "count"
	times   int    // calls left in mode
	loads   int
	release chan struct{} // closed by Load: a hung Embed returns
	inside  int
	maxIn   int
	gate    chan struct{} // when set, Embed waits on it (concurrency test)
}

func newFake(dim int) *fake { return &fake{dim: dim, release: make(chan struct{})} }

func (f *fake) Load(path string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	close(f.release)
	f.release = make(chan struct{})
	if f.refuse {
		return 0, ErrRefused
	}
	if f.noLoad {
		return 0, errors.New("runtime binary absent")
	}
	if _, err := os.Stat(path); err != nil {
		return 0, ErrRefused
	}
	return f.dim, nil
}

// failNext puts the next n calls in mode.
func (f *fake) failNext(mode string, n int) {
	f.mu.Lock()
	f.mode, f.times = mode, n
	f.mu.Unlock()
}

func (f *fake) Embed(texts []string) ([][]float32, error) {
	f.mu.Lock()
	mode, release, gate := "", f.release, f.gate
	if f.times > 0 {
		mode = f.mode
		f.times--
	}
	f.inside++
	f.maxIn = max(f.maxIn, f.inside)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inside--
		f.mu.Unlock()
	}()
	if gate != nil {
		<-gate
	}
	switch mode {
	case "crash":
		// A runtime's error may echo the request: the service must not.
		return nil, errors.New("runtime died on: " + strings.Join(texts, "|"))
	case "panic":
		panic("runtime panic")
	case "hang":
		<-release
		return nil, errors.New("killed")
	}
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = vector(t, f.dim)
	}
	switch mode {
	case "short":
		out[0] = out[0][:f.dim-1]
	case "nan":
		out[0][0] = float32(nan())
	case "count":
		out = out[1:]
	}
	return out, nil
}

func nan() float64 { var z float64; return z / z }

// vector is the fake's concept-table entry for t.
func vector(t string, dim int) []float32 {
	h := sha256.Sum256([]byte(t))
	v := make([]float32, dim)
	for i := range v {
		v[i] = float32(binary.BigEndian.Uint16(h[(2*i)%32:]))/65536 - 0.5
	}
	return v
}

// The synthetic model stand-in: bytes no runtime would load (INF-8).
var modelBytes = bytes.Repeat([]byte("synthetic-model-stand-in\n"), 4096)

func pin(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type rig struct {
	t    *testing.T
	sock string
	rt   *fake
	log  *lockedBuffer
	cfg  Config
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// serve runs the service on a unix socket in a temp dir, with the model
// file written from model (nil: absent) and pinned to p.
func serve(t *testing.T, model []byte, p string, rt *fake, edit func(*Config)) *rig {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{Name: "synthetic-embed", Model: filepath.Join(dir, "model.gguf"), Pin: p,
		CallTimeout: 300 * time.Millisecond, Retry: 50 * time.Millisecond}
	if model != nil {
		if err := os.WriteFile(cfg.Model, model, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if edit != nil {
		edit(&cfg)
	}
	r := &rig{t: t, sock: filepath.Join(dir, "infer.sock"), rt: rt, log: &lockedBuffer{}, cfg: cfg}
	ln, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newService(cfg, rt, r.log).Serve(ln)
	return r
}

func (r *rig) client() infer.Client { return infer.Client{Path: r.sock, Timeout: 5 * time.Second} }

// raw sends one line and reads one reply.
func (r *rig) raw(line []byte) (infer.Reply, error) {
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		return infer.Reply{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go c.Write(append(line, '\n'))
	got, err := infer.ReadLine(bufio.NewReader(c), infer.MaxReplyLine)
	if err != nil {
		return infer.Reply{}, err
	}
	var rep infer.Reply
	return rep, json.Unmarshal(got, &rep)
}

func texts(n int, prefix string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strings.Repeat("x", i)
	}
	return out
}

func TestEmbedReturnsVectorsAndHash(t *testing.T) {
	r := serve(t, modelBytes, pin(modelBytes), newFake(16), nil)
	ctx := context.Background()
	in, err := r.client().Hello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if in.Model != "synthetic-embed" || in.SHA256 != pin(modelBytes) || in.Dim != 16 {
		t.Fatalf("hello = %+v", in)
	}
	ts := []string{"synthetic note one", "synthetic note two", "synthetic note one"}
	vs, in2, err := r.client().Embed(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if in2.SHA256 != pin(modelBytes) || in2.Dim != 16 || len(vs) != 3 {
		t.Fatalf("embed = %+v, %d vectors", in2, len(vs))
	}
	for i, v := range vs {
		want := vector(ts[i], 16)
		for j := range v {
			if v[j] != want[j] {
				t.Fatalf("vector %d differs from the concept table at %d", i, j)
			}
		}
	}
	again, _, err := r.client().Embed(ctx, ts[:1])
	if err != nil || again[0][3] != vs[0][3] {
		t.Fatalf("same text, different vector: %v", err)
	}
	if r.rt.loads != 1 {
		t.Fatalf("%d loads, want 1", r.rt.loads)
	}
}

func TestServiceRejectsOversizeRequest(t *testing.T) {
	r := serve(t, modelBytes, pin(modelBytes), newFake(8), nil)
	line := func(ts []string) []byte {
		b, _ := json.Marshal(infer.Request{Op: infer.OpEmbed, Texts: ts})
		return b
	}
	big := strings.Repeat("y", infer.MaxText+1<<10) // 9 KiB
	for name, l := range map[string][]byte{
		"65 texts":   line(texts(infer.MaxTexts+1, "t")),
		"9 KiB text": line([]string{big}),
		"2 MiB line": append([]byte(`{"op":"embed","texts":["`), bytes.Repeat([]byte("z"), 2<<20)...),
		"no texts":   []byte(`{"op":"embed","texts":[]}`),
		"unknown op": []byte(`{"op":"train"}`),
		"not json":   []byte(`{"op":`),
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := r.raw(l)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Error != infer.BadRequest || rep.Vectors != nil {
				t.Fatalf("reply %+v, want bad_request", rep)
			}
			// The service keeps serving.
			if _, _, err := r.client().Embed(context.Background(), texts(infer.MaxTexts, "ok")); err != nil {
				t.Fatalf("after %s: %v", name, err)
			}
		})
	}
	if strings.Contains(r.log.String(), "yyyy") || strings.Contains(r.log.String(), "zzzz") {
		t.Fatal("the log carries request text")
	}
}

func TestServiceReportsMissingAndCorrupt(t *testing.T) {
	for _, c := range []struct {
		name  string
		model []byte
		pin   string
		rt    func(*fake)
		want  infer.Cause
	}{
		{"no file", nil, pin(modelBytes), nil, infer.Missing},
		{"truncated file", modelBytes[:len(modelBytes)/2], pin(modelBytes), nil, infer.Corrupt},
		{"wrong pin", modelBytes, pin([]byte("another synthetic model")), nil, infer.Corrupt},
		{"no pin", modelBytes, "", nil, infer.Corrupt},
		{"runtime refuses the file", modelBytes, pin(modelBytes), func(f *fake) { f.refuse = true }, infer.Corrupt},
		{"runtime does not start", modelBytes, pin(modelBytes), func(f *fake) { f.noLoad = true }, infer.Unavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			rt := newFake(8)
			if c.rt != nil {
				c.rt(rt)
			}
			r := serve(t, c.model, c.pin, rt, nil)
			for i := 0; i < 3; i++ { // the process stays up and keeps answering
				_, err := r.client().Hello(context.Background())
				if got := infer.CauseOf(err); err == nil || got != c.want {
					t.Fatalf("hello %d: %v, want %s", i, err, c.want)
				}
				vs, _, err := r.client().Embed(context.Background(), []string{"synthetic"})
				if got := infer.CauseOf(err); err == nil || got != c.want || vs != nil {
					t.Fatalf("embed %d: %v, want %s", i, err, c.want)
				}
			}
		})
	}
}

// A model installed after start is found by the next call past Retry.
func TestServiceFindsAModelInstalledLater(t *testing.T) {
	r := serve(t, nil, pin(modelBytes), newFake(8), nil)
	if _, err := r.client().Hello(context.Background()); infer.CauseOf(err) != infer.Missing {
		t.Fatalf("hello: %v", err)
	}
	if err := os.WriteFile(r.cfg.Model, modelBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * r.cfg.Retry)
	if _, err := r.client().Hello(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCrashIsUnavailableThenRecovers(t *testing.T) {
	for _, mode := range []string{"crash", "panic", "hang", "short", "nan", "count"} {
		t.Run(mode, func(t *testing.T) {
			rt := newFake(8)
			r := serve(t, modelBytes, pin(modelBytes), rt, func(c *Config) { c.Retry = time.Hour })
			ctx := context.Background()
			if _, err := r.client().Hello(ctx); err != nil {
				t.Fatal(err)
			}
			rt.failNext(mode, 1)
			vs, _, err := r.client().Embed(ctx, []string{"synthetic"})
			if infer.CauseOf(err) != infer.Unavailable || vs != nil {
				t.Fatalf("failed call: %v, %d vectors; want unavailable", err, len(vs))
			}
			// The next call reloads the runtime at once (Retry is an hour,
			// so only the failure's mark allows it) and answers.
			vs, _, err = r.client().Embed(ctx, []string{"synthetic"})
			if err != nil || len(vs) != 1 {
				t.Fatalf("after %s: %v", mode, err)
			}
			var loads, inside int
			for end := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				rt.mu.Lock()
				loads, inside = rt.loads, rt.inside
				rt.mu.Unlock()
				if inside == 0 || time.Now().After(end) {
					break
				}
			}
			if loads != 2 {
				t.Fatalf("%d loads, want 2 (start and reload)", loads)
			}
			if inside != 0 {
				t.Fatalf("%d runtime calls still running: the reload did not end a hung call", inside)
			}
		})
	}
}

func TestServiceCapsConcurrentCalls(t *testing.T) {
	rt := newFake(8)
	r := serve(t, modelBytes, pin(modelBytes), rt, func(c *Config) { c.CallTimeout = 5 * time.Second })
	if _, err := r.client().Hello(context.Background()); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	rt.mu.Lock()
	rt.gate = gate
	rt.mu.Unlock()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := r.client().Embed(context.Background(), []string{"synthetic burst"})
			errs <- err
		}()
	}
	time.Sleep(300 * time.Millisecond)
	rt.mu.Lock()
	in := rt.inside
	rt.mu.Unlock()
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if in != 2 || rt.maxIn != 2 {
		t.Fatalf("%d calls in the runtime at once (max %d), want 2", in, rt.maxIn)
	}
}

// REQ: ARC-2
func TestLogsCarryNoText(t *testing.T) {
	const canary = "synthetic-infer-text-canary-5d2e"
	rt := newFake(8)
	r := serve(t, modelBytes, pin(modelBytes), rt, nil)
	ctx := context.Background()
	vs, _, err := r.client().Embed(ctx, []string{canary, "plain synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"crash", "panic", "hang", "nan"} {
		rt.failNext(mode, 1)
		if _, _, err := r.client().Embed(ctx, []string{canary}); err == nil {
			t.Fatalf("%s: no error", mode)
		} else if strings.Contains(err.Error(), canary) {
			t.Fatalf("%s: the reply's detail carries the text: %v", mode, err)
		}
	}
	r.raw([]byte(`{"op":"embed","texts":["` + canary + strings.Repeat("q", infer.MaxText) + `"]}`))
	r.raw([]byte(`{"op":"embed","texts":["` + canary))
	log := r.log.String()
	if !strings.Contains(log, "embedded 2 texts") || !strings.Contains(log, "reloading") {
		t.Fatalf("the log lacks the counts and causes it should carry:\n%s", log)
	}
	if strings.Contains(log, canary) {
		t.Fatalf("the log carries request text:\n%s", log)
	}
	b, _ := json.Marshal(vs[0][0])
	if strings.Contains(log, string(b)) {
		t.Fatalf("the log carries a vector value %s:\n%s", b, log)
	}
}

// REQ: ARC-2
//
// main serves the listener it is handed as fd 3 and names no socket of its
// own; with no runtime in this build it answers, Unavailable.
func TestMainServesTheListenerOnFD3(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "infer.sock")
	model := filepath.Join(dir, "model.gguf")
	if err := os.WriteFile(model, modelBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	lf, err := ul.File()
	if err != nil {
		t.Fatal(err)
	}
	ul.Close() // the child holds the only copy now
	var stderr lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := childproc.Command(ctx, childproc.NewEnv("PATH=/usr/bin:/bin"),
		childproc.Options{Dir: dir, Stderr: &stderr, ExtraFiles: []*os.File{lf}, WaitDelay: time.Second},
		os.Args[0], helperArg, "-model", model, "-model-sha256", pin(modelBytes), "-runtime", "/nonexistent")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lf.Close()
	defer func() { cancel(); cmd.Wait() }()
	_, err = infer.Client{Path: sock, Timeout: 5 * time.Second}.Hello(context.Background())
	var e *infer.Error
	if !errors.As(err, &e) || e.Cause != infer.Unavailable || e.Detail != "runtime did not load" {
		t.Fatalf("hello: %v (log: %s)", err, stderr.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("the service made files beside its socket: %v", ents)
	}
}
