package cleanroom

// REQ: OSS-2, OSS-3

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// lateVMs lets the builder and the vm manager refer to each other: the
// manager needs the builder's services at Open.
type lateVMs struct{ m **vm.Manager }

func (l lateVMs) Create(ctx context.Context, id string, s vm.Spec) (vm.Machine, error) {
	return (*l.m).Create(ctx, id, s)
}
func (l lateVMs) Get(id string) (vm.Machine, error)            { return (*l.m).Get(id) }
func (l lateVMs) Resume(ctx context.Context, id string) error  { return (*l.m).Resume(ctx, id) }
func (l lateVMs) Destroy(ctx context.Context, id string) error { return (*l.m).Destroy(ctx, id) }
func (l lateVMs) Machines() []string                           { return (*l.m).Machines() }

type latePreempt struct{ m **vm.Manager }

func (l latePreempt) Preempt(id string) error { return (*l.m).Preempt(id) }

// planeStub stands in for the guest plane: every other machine's socket
// answers with private data.
type planeStub struct {
	root, canary string
	mu           sync.Mutex
	srv          map[string]*http.Server
}

func (p *planeStub) Open(id string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dir := filepath.Join(p.root, id)
	if p.srv[id] != nil {
		return dir, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, Socket))
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, p.canary)
	})}
	go srv.Serve(l)
	p.srv[id] = srv
	return dir, nil
}

func (p *planeStub) Close(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.srv[id]; s != nil {
		s.Close()
		os.RemoveAll(filepath.Join(p.root, id))
		delete(p.srv, id)
	}
}

// TestIntegrationCleanRoomCannotReachPrivateData is the clean-room part of
// the A12 leakage audit, under gVisor: canary private data is planted in a
// journal, a vault, a recall index, a workspace, a private machine's layer,
// and the guest plane's sockets. A hostile clean room probes all of it,
// asks its own socket for executor and owner services, and tries the
// network. It reaches none of it, and no canary appears in the artifact.
func TestIntegrationCleanRoomCannotReachPrivateData(t *testing.T) {
	bin := os.Getenv("AGENTOS_RUNSC")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and run as root (CI integration job)")
	}
	var rb [8]byte
	rand.Read(rb[:])
	canary := "CANARY-" + hex.EncodeToString(rb[:])

	img := t.TempDir()
	for _, d := range []string{"work", "tmp", "proc", "dev", "sys"} {
		if err := os.Mkdir(filepath.Join(img, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command("go", "build", "-o", filepath.Join(img, "guest"), "./testdata/guest")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building guest: %v\n%s", err, out)
	}

	// Unix socket paths are short (108 bytes), so not t.TempDir().
	state, err := os.MkdirTemp("", "cr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	private := map[string]string{
		"journal":   filepath.Join(state, "journal", "journal.db"),
		"vault":     filepath.Join(state, "vault", "vault.bin"),
		"recall":    filepath.Join(state, "recall", "index.db"),
		"workspace": filepath.Join(state, "workspaces", "w1", "notes.txt"),
	}
	for _, p := range private {
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(canary), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	brokerDir := filepath.Join(state, "broker")
	plane := &planeStub{root: filepath.Join(state, "plane"), canary: canary, srv: map[string]*http.Server{}}
	probes := []string{
		private["journal"], private["vault"], private["recall"], private["workspace"],
		filepath.Join(brokerDir, "machines", "owner-task", "upper", "work", "canary"),
		"/etc/shadow",
	}
	socks := []string{filepath.Join(plane.root, "owner-task", Socket)}

	var mgr *vm.Manager
	b, err := New(Config{
		Dir: filepath.Join(state, "cleanroom"), Machines: lateVMs{&mgr}, Image: "cleanroom",
		MemMB: 256, Argv: []string{"/guest", "build"},
		Env:     []string{"PROBES=" + strings.Join(probes, ":"), "SOCKS=" + strings.Join(socks, ":")},
		Poll:    100 * time.Millisecond,
		Retry:   time.Second,
		Timeout: 90 * time.Second,
		Logf:    t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt := &gvisor.Runtime{Bin: bin, StateDir: filepath.Join(state, "runsc")}
	adm, err := admission.New(admission.Config{CapacityMB: 4096}, latePreempt{&mgr})
	if err != nil {
		t.Fatal(err)
	}
	cfg := vm.Config{
		StateDir: brokerDir,
		Images:   map[string]string{"cleanroom": img, "base": img},
		Runtime:  rt, Admit: adm,
		Services: b.Services(plane),
	}
	if p := os.Getenv("AGENTOS_CGROUP_PARENT"); p != "" {
		g, err := cgroup.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Cgroups = g
	} else {
		cfg.NoCgroups = true
	}
	mgr, err = vm.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range mgr.Machines() {
			mgr.Destroy(context.Background(), id)
		}
		syscall.Unmount(filepath.Join(rt.StateDir, "null-netns"), syscall.MNT_DETACH)
	})

	// A private machine holding owner data in its own layer.
	if _, err := mgr.Create(context.Background(), "owner-task", vm.Spec{
		Image: "base", Class: admission.Accepted, MemMB: 256, Label: vm.Private,
		Argv: []string{"/guest", "idle"}, Env: []string{"CANARY=" + canary},
	}); err != nil {
		t.Fatal(err)
	}
	waitFile(t, probes[4])

	if err := b.Send(nextDay(), [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(2 * time.Minute)
	var outs []Outcome
	for len(outs) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no outcome from the clean room")
		}
		time.Sleep(100 * time.Millisecond)
		outs, _ = b.Outcomes()
	}
	if outs[0].Result != "built" {
		t.Fatalf("outcome %+v", outs[0])
	}
	a, err := b.Store().Get(outs[0].Artifact)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := a.ReadFile("hint.json")
	if string(h) != string(skillHint(t)) {
		t.Fatalf("clean room saw hint %q", h)
	}
	rep, _ := a.ReadFile("report.txt")
	t.Logf("clean room's probe report:\n%s", rep)
	want := []string{"svc /mcp 404", "svc /owner/next 404", "svc /owner/reply 404", "write /run/agentos refused", "net tcp refused"}
	for _, p := range probes {
		want = append(want, "read "+p+" absent")
	}
	want = append(want, "read /work/canary absent")
	for _, s := range socks {
		want = append(want, "dial "+s+" refused")
	}
	for _, w := range want {
		if !strings.Contains(string(rep), w+"\n") {
			t.Errorf("probe report lacks %q", w)
		}
	}
	// No canary anywhere in what the clean room produced.
	filepath.Walk(filepath.Join(state, "cleanroom", "artifacts"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if data, _ := os.ReadFile(p); strings.Contains(string(data), canary) {
				t.Errorf("canary in clean-room output %s", p)
			}
		}
		return nil
	})
	for _, id := range mgr.Machines() {
		if strings.HasPrefix(id, Prefix) {
			t.Errorf("clean room %s not destroyed", id)
		}
	}
	if m, err := mgr.Get("owner-task"); err != nil || m.State != vm.Running {
		t.Fatalf("private machine disturbed: %+v %v", m, err)
	}
}

func waitFile(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(p); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", p)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
