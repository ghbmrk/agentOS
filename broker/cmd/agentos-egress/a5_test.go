package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: A5, ARC-1, CRED-1

// A5 (the holders spec, #2404): on a split box the process that serves
// the model path holds no canary secret and no vault key. This test is
// that process: a child process is the vault process and the holders,
// over a vault whose API key and vault key it generates; this process
// runs the proxy, makes a call whose provider echoes the key, then scans
// its own memory for both. It learns each value only split in two, the
// second half masked, so the whole value is in its memory only if it
// leaked here.

const a5Env = "AGENTOS_A5_PROXY_DIR"

// split is a value as the child tells it: its first half, and its second
// half XORed with a mask, so neither line holds the value.
type split struct{ a, bx, m []byte }

func splitOf(v []byte) split {
	a, b := v[:len(v)/2], v[len(v)/2:]
	m := make([]byte, len(b))
	rand.Read(m)
	bx := make([]byte, len(b))
	for i := range b {
		bx[i] = b[i] ^ m[i]
	}
	return split{append([]byte(nil), a...), bx, m}
}

func (s split) line(name string) string {
	return fmt.Sprintf("A5 %s %x %x %x", name, s.a, s.bx, s.m)
}

// at reports whether the value starts at mem[i], unmasking byte by byte.
func (s split) at(mem []byte, i int) bool {
	if i+len(s.a)+len(s.bx) > len(mem) {
		return false
	}
	for j := range s.bx {
		if mem[i+len(s.a)+j]^s.m[j] != s.bx[j] {
			return false
		}
	}
	return true
}

// memHolds reports whether this process's readable memory holds s's
// value anywhere.
func memHolds(t *testing.T, s split) bool {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("no /proc/self/maps: %v", err)
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Skipf("no /proc/self/mem: %v", err)
	}
	defer mem.Close()
	const chunk = 8 << 20
	over := len(s.a) + len(s.bx)
	buf := make([]byte, chunk+over)
	for _, l := range strings.Split(string(maps), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[1][0] != 'r' || len(f) >= 6 && strings.HasPrefix(f[5], "[v") {
			continue
		}
		lo, hi, _ := strings.Cut(f[0], "-")
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		for off := start; off < end; off += chunk {
			n := min(uint64(len(buf)), end-off)
			got, _ := mem.ReadAt(buf[:n], int64(off))
			b := buf[:got]
			for i := 0; ; {
				k := bytes.Index(b[i:], s.a)
				if k < 0 {
					break
				}
				if s.at(b, i+k) {
					return true
				}
				i += k + 1
			}
		}
	}
	return false
}

func TestA5ProxyMemoryHoldsNoKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/self/mem")
	}
	proxyDir, err := os.MkdirTemp("", "a5")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(proxyDir) })
	cmd := exec.Command(os.Args[0], "-test.run=^TestA5VaultChild$")
	cmd.Env = append(os.Environ(), a5Env+"="+proxyDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })

	dirs := holderDirs{}
	splits := map[string]split{}
	sc := bufio.NewScanner(out)
	for (len(dirs) < 2 || len(splits) < 2) && sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 3 && f[0] == "A5":
			dirs[f[1]] = f[2]
		case len(f) == 5 && f[0] == "A5":
			var s split
			s.a, _ = hex.DecodeString(f[2])
			s.bx, _ = hex.DecodeString(f[3])
			s.m, _ = hex.DecodeString(f[4])
			splits[f[1]] = s
		}
	}
	if len(dirs) < 2 || len(splits) < 2 {
		t.Fatalf("the vault child ended before telling its holders: %v", sc.Err())
	}
	go io.Copy(io.Discard, out)

	pv, err := newProxyView(grants{}, "agent", nil, dirs, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := holder.Listen(filepath.Join(proxyDir, holder.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: holder.HandHandler(pv, maxView)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	waitUntil(t, "the open view", func() bool { return pv.storedGrant("agent", "openai") })

	var w *httptest.ResponseRecorder
	waitUntil(t, "a call through the holder", func() bool {
		w = httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer placeholder")
		pv.model().HandlerFor("agent", "private", noAudit{}).ServeHTTP(w, req)
		return w.Code == http.StatusOK
	})
	if !strings.Contains(w.Body.String(), "hello ") {
		t.Fatalf("call: %s", w.Body)
	}

	ctrl := []byte(synthetic(t, "a5-control-"))
	if !memHolds(t, splitOf(ctrl)) {
		t.Fatal("control: the scan missed a value this process holds")
	}
	runtime.KeepAlive(ctrl)
	for _, name := range []string{"canary", "vaultkey"} {
		s, ok := splits[name]
		if !ok || len(s.a) == 0 {
			t.Fatalf("the vault child did not tell its %s", name)
		}
		if memHolds(t, s) {
			t.Errorf("the proxy process's memory holds the %s", name)
		}
	}
}

// TestA5VaultChild is TestA5ProxyMemoryHoldsNoKey's vault process: it
// runs only as that test's child.
func TestA5VaultChild(t *testing.T) {
	proxyDir := os.Getenv(a5Env)
	if proxyDir == "" {
		t.Skip("the A5 test's child process")
	}
	tr, _ := reflecting(t, true)
	openaiDir, _ := heldAt(t, egress.OpenAI("openai"), tr)
	anthDir, _ := heldAt(t, egress.Anthropic("anthropic"), tr)
	r := newFastRig(t, true) // its vault holds a generated OpenAI key
	r.c.holders = holderDirs{"openai": openaiDir, "anthropic": anthDir}
	r.c.keepEvery = 5 * time.Millisecond
	r.c.modelTransport = noDial{t}
	withGrants(r.c, grants{}, "agent")
	r.c.view = newViewKeeper(r.c, proxyDir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.c.view.run(ctx)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	s, _ := r.c.v.Secret("openai")
	canary := []byte(s.Reveal())
	r.c.mu.Unlock()
	fmt.Println("A5 openai " + openaiDir)
	fmt.Println("A5 anthropic " + anthDir)
	fmt.Println(splitOf(canary).line("canary"))
	fmt.Println(splitOf(r.key).line("vaultkey"))
	io.Copy(io.Discard, os.Stdin) // until the proxy side is done
}
