//go:build infer_real && infer_llamacpp

package main

// REQ: PLN-7, RES-2

// This test runs the real llama-server on a real embedding model file: the
// server from AGENTOS_LLAMA_SERVER and the model from AGENTOS_LLAMA_EMBED_MODEL
// with the SHA-256 it is pinned to in AGENTOS_LLAMA_EMBED_SHA256. CI compiles them in every run (go vet -tags
// infer_real,infer_llamacpp) and runs them in the infer-real workflow,
// which downloads the pinned release and models and checks their hashes
// before this runs. A test whose variables are unset skips, so a plain
// `go test -tags infer_real,infer_llamacpp` on a laptop does nothing.

import (
	"context"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/infer"
)

// realRig is the service over the real adapter on the named model.
func realRig(t *testing.T) infer.Client {
	t.Helper()
	server, model, pin := os.Getenv("AGENTOS_LLAMA_SERVER"), os.Getenv("AGENTOS_LLAMA_EMBED_MODEL"), os.Getenv("AGENTOS_LLAMA_EMBED_SHA256")
	if server == "" || model == "" || pin == "" {
		t.Skip("AGENTOS_LLAMA_SERVER, AGENTOS_LLAMA_EMBED_MODEL and AGENTOS_LLAMA_EMBED_SHA256 are not all set")
	}
	l := &llama{exe: server, ready: 5 * time.Minute}
	t.Cleanup(l.stop)
	cfg := Config{Name: filepath.Base(model), Model: model, Pin: pin,
		CallTimeout: 2 * time.Minute, Retry: time.Second}
	sock := filepath.Join(t.TempDir(), "infer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newService(cfg, l, nil).Serve(ln)
	return infer.Client{Path: sock, Timeout: 5 * time.Minute}
}

func TestRealRuntimeEmbed(t *testing.T) {
	c := realRig(t)
	ctx := context.Background()
	in, err := c.Hello(ctx)
	if err != nil || in.Dim != 1024 || in.SHA256 != os.Getenv("AGENTOS_LLAMA_EMBED_SHA256") {
		t.Fatalf("hello = %+v, %v; want an embedding model with the pinned hash", in, err)
	}
	texts := []string{"the cat sat on the mat", "quarterly revenue grew", "the cat sat on the mat"}
	a, _, err := c.Embed(ctx, texts)
	if err != nil || len(a) != len(texts) {
		t.Fatalf("embed = %d vectors, %v", len(a), err)
	}
	for i, v := range a {
		if len(v) != in.Dim || !infer.Finite(v) {
			t.Fatalf("vector %d: %d floats, finite %v; want %d finite", i, len(v), infer.Finite(v), in.Dim)
		}
	}
	b, _, err := c.Embed(ctx, texts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if cosine(a[i], b[i]) < 0.9999 {
			t.Errorf("text %d differs across two calls (cosine %f)", i, cosine(a[i], b[i]))
		}
	}
	// The same text in one batch gives the same vector, and a different
	// text a different one: the vectors are placed by their input.
	if cosine(a[0], a[2]) < 0.9999 || cosine(a[0], a[1]) > 0.99 {
		t.Errorf("batch placement: cos(0,2) %f, cos(0,1) %f", cosine(a[0], a[2]), cosine(a[0], a[1]))
	}
}

func cosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
