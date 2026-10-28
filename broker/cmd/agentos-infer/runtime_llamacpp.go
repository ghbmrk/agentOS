//go:build infer_llamacpp

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/infer"
)

// newRuntime is the llama.cpp adapter, embedding only (D-230): it runs the pinned llama-server at
// path as a child of this service and speaks to it over a unix socket in a
// private directory, so the service needs no network, not even loopback
// (INFER-A3, INFER-A11). The server is a separate executable and is never
// linked: this binary stays CGO_ENABLED=0.
func newRuntime(path string) Runtime { return &llama{exe: path, ready: 2 * time.Minute} }

// llama is the Runtime over one llama-server child at a time.
type llama struct {
	exe   string
	ready time.Duration // the most Load waits for the server to answer health

	mu  sync.RWMutex
	cur *llamaProc // nil before the first Load and after a failed one
}

// llamaProc is one running llama-server and the way to reach it.
type llamaProc struct {
	dir    string
	cancel context.CancelFunc
	done   chan struct{} // closed when the child has exited
	http   *http.Client
}

// Bounds on what the server may answer: it is untrusted (INFER-A11), so
// nothing it sends is read past these.
const (
	maxEmbeddingBody = 32 << 20 // 64 vectors of MaxDim floats as JSON
	maxHealthBody    = 4 << 10
	// slots and slotTokens are the server's parallel slots and the context of each
	// (INFER-A6); llama-server divides --ctx-size across its slots.
	slots      = 2
	slotTokens = 2048
)

var (
	errNoServer = errors.New("llama-server is not running")
	errBadReply = errors.New("llama-server answered a malformed reply")
	errHTTP     = errors.New("llama-server answered an error status")
)

func (l *llama) Load(path string) (int, error) {
	embed, err := modelIsEmbedding(path)
	l.stop()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if !embed {
		return 0, fmt.Errorf("%w: not an embedding model", ErrRefused)
	}
	p, err := l.start(path)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	l.cur = p
	l.mu.Unlock()
	// The dimension is what the server returns, not what the file claims:
	// an output head can differ from the embedding length.
	vs, err := l.Embed([]string{"dimension probe"})
	if err != nil || len(vs) != 1 || len(vs[0]) == 0 || len(vs[0]) > infer.MaxDim {
		l.stop()
		return 0, errBadReply
	}
	return len(vs[0]), nil
}

// stop ends the current server, which makes any call stuck on it return.
func (l *llama) stop() {
	l.mu.Lock()
	p := l.cur
	l.cur = nil
	l.mu.Unlock()
	if p != nil {
		p.close()
	}
}

func (p *llamaProc) close() {
	p.cancel()
	<-p.done
	os.RemoveAll(p.dir)
}

// start runs llama-server on the model and waits until it answers health.
// Every flag below closes something: embedding mode with the model's last-token
// pooling, two slots of 2048 tokens (the leaf's memory, INFER-A6), CPU only, no web
// UI, no slots endpoint, no network fetch, and its log discarded since the
// service's log carries no request text (INF-8).
func (l *llama) start(model string) (*llamaProc, error) {
	dir, err := os.MkdirTemp("", "llama-")
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "s.sock")
	args := []string{
		"--model", model,
		"--host", sock,
		"--embedding", "--pooling", "last",
		"--parallel", fmt.Sprint(slots),
		"--ctx-size", fmt.Sprint(slots * slotTokens),
		"--gpu-layers", "0",
		"--no-webui", "--no-slots", "--offline",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := childproc.Command(ctx, childproc.NewEnv("PATH=/usr/bin:/bin"), childproc.Options{
		Dir:         "/",
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
		WaitDelay:   2 * time.Second,
		KillGroup:   true,
	}, l.exe, args...)
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(dir)
		return nil, errors.New("llama-server did not start")
	}
	p := &llamaProc{dir: dir, cancel: cancel, done: make(chan struct{})}
	go func() { cmd.Wait(); close(p.done) }()
	p.http = &http.Client{
		Timeout: 10 * time.Minute, // a backstop: the service bounds a call and reloads
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
	if err := p.waitHealthy(l.ready); err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

func (p *llamaProc) waitHealthy(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		select {
		case <-p.done:
			return errors.New("llama-server exited while loading")
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/health", nil)
		resp, err := p.http.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBody))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				cancel()
				return nil
			}
		}
		cancel()
		if time.Now().After(deadline) {
			return errors.New("llama-server not ready in time")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *llama) proc() (*llamaProc, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.cur == nil {
		return nil, errNoServer
	}
	return l.cur, nil
}

// post sends one JSON request and decodes the reply into out, reading at
// most limit bytes of it. The server's body is never put in an error.
func (p *llamaProc) post(path string, body, out any, limit int64) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return errNoServer
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errHTTP
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return errBadReply
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errBadReply
	}
	return nil
}

// Embed returns one vector per text, in order, from the server's
// OpenAI-style endpoint (pooled and L2-normalised by the model's own
// pooling).
func (l *llama) Embed(texts []string) ([][]float32, error) {
	p, err := l.proc()
	if err != nil {
		return nil, err
	}
	var r struct {
		Data []struct {
			Index     *int      `json:"index"`
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	err = p.post("/v1/embeddings", map[string]any{"input": texts, "encoding_format": "float"}, &r, maxEmbeddingBody)
	if err != nil {
		return nil, err
	}
	if len(r.Data) != len(texts) {
		return nil, errBadReply
	}
	out := make([][]float32, len(texts))
	for _, d := range r.Data {
		if d.Index == nil || *d.Index < 0 || *d.Index >= len(out) || out[*d.Index] != nil {
			return nil, errBadReply
		}
		out[*d.Index] = d.Embedding
	}
	return out, nil
}

// modelIsEmbedding reads the model's GGUF header for what the model is.
// A model whose architecture names a pooling type of mean, cls or last
// (<arch>.pooling_type 1 to 3) is an embedding model and runs with
// --embedding; one without it is a generative model, which Load refuses
// (D-230). A ranking model (4) and any file that is not a GGUF are refused
// too. The header is read-only and bounded.
func modelIsEmbedding(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, errors.New("model unreadable")
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	var h struct {
		Magic   [4]byte
		Version uint32
		Tensors uint64
		KVs     uint64
	}
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil || string(h.Magic[:]) != "GGUF" || h.Version < 2 || h.Version > 3 || h.KVs > 1<<16 {
		return false, errors.New("not a GGUF file")
	}
	var arch string
	pooling := map[string]uint32{}
	for i := uint64(0); i < h.KVs; i++ {
		key, err := ggufString(r)
		if err != nil {
			return false, errors.New("malformed GGUF header")
		}
		var typ uint32
		if err := binary.Read(r, binary.LittleEndian, &typ); err != nil {
			return false, errors.New("malformed GGUF header")
		}
		switch {
		case key == "general.architecture" && typ == ggufString8:
			if arch, err = ggufString(r); err != nil {
				return false, errors.New("malformed GGUF header")
			}
		case strings.HasSuffix(key, ".pooling_type") && typ == ggufUint32:
			var v uint32
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return false, errors.New("malformed GGUF header")
			}
			pooling[key] = v
		default:
			if err := ggufSkip(r, typ, 0); err != nil {
				return false, errors.New("malformed GGUF header")
			}
		}
	}
	if arch == "" {
		return false, errors.New("GGUF names no architecture")
	}
	switch pooling[arch+".pooling_type"] {
	case 0:
		return false, nil
	case 1, 2, 3:
		return true, nil
	}
	return false, errors.New("ranking models are not served")
}

// maxGGUFDepth is how deep arrays may nest in the header: real files use one
// level (a list of strings), and a hostile one must not drive the recursion.
const maxGGUFDepth = 4

// GGUF value types (the spec's gguf_metadata_value_type).
const (
	ggufUint32  = 4
	ggufString8 = 8
	ggufArray   = 9
)

// ggufSize is the byte size of each fixed-width value type; zero for the
// string and array types, which carry their own lengths.
var ggufSize = map[uint32]int64{0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}

func ggufString(r *bufio.Reader) (string, error) {
	var n uint64
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil || n > 1<<20 {
		return "", errors.New("bad string")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// ggufSkip discards one value of type typ.
func ggufSkip(r *bufio.Reader, typ uint32, depth int) error {
	if n, ok := ggufSize[typ]; ok {
		_, err := r.Discard(int(n))
		return err
	}
	switch typ {
	case ggufString8:
		var n uint64
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil || n > 1<<30 {
			return errors.New("bad string")
		}
		_, err := r.Discard(int(n))
		return err
	case ggufArray:
		if depth >= maxGGUFDepth {
			return errors.New("arrays nested too deep")
		}
		var elem uint32
		var n uint64
		if err := binary.Read(r, binary.LittleEndian, &elem); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil || n > 1<<24 {
			return errors.New("bad array")
		}
		if sz, ok := ggufSize[elem]; ok {
			_, err := r.Discard(int(int64(n) * sz))
			return err
		}
		for i := uint64(0); i < n; i++ {
			if err := ggufSkip(r, elem, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("unknown value type")
}
