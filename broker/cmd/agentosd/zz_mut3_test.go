package main

// REQ: REV-CHK-mut (#5848)
//
// OWN-page-session-mut3: each check below fails when mutgate deletes one of
// the statements of plankeys.go, imagepin.go, noticepull.go, diskquota.go,
// follow.go and infer.go that #5194's run listed as surviving. The checks
// are plain functions, each called at the end of one existing test of its
// file, not Test functions of their own: a new Test changes the package's
// run list, which mutgate reads as changing every test of the package
// (pacing_test.go's at23, #5848's release finding), so the gate would then
// count every old survivor of cmd/agentosd against this change.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/owner/notice"
	"github.com/ghbmrk/agentos/broker/owner/notice/noticesock"
	"github.com/ghbmrk/agentos/broker/update"
)

// mut3Log sends the standard logger to a buffer for the rest of the test.
func mut3Log(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// mut3Open names a descriptor of this process open on path, or "". Callers
// scan straight after the call under test, which allocates too little to
// start a GC that could close a leaked file through its finalizer.
func mut3Open(t *testing.T, path string) string {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("no /proc/self/fd to count descriptors: %v", err)
	}
	for _, e := range fds {
		if to, _ := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); to == path {
			return e.Name()
		}
	}
	return ""
}

func mut3PlanHolderReadsEachRefusalAsItself(t *testing.T) {
	dir := t.TempDir()
	// A file open to others is refused with the file check's own error, not
	// read as a seed of the wrong size.
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, make([]byte, ed25519.SeedSize), 0o644); err != nil {
		t.Fatal(err)
	}
	_, want := readPrivate(open, ed25519.SeedSize)
	if _, err := loadPlanHolder(open); want == nil || err == nil || err.Error() != want.Error() {
		t.Fatalf("open to others: %v, want %v", err, want)
	}
	// One byte over max is refused, whatever reads it.
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readPrivate(big, 4); b != nil || err == nil || err.Error() != big+": larger than 4 bytes" {
		t.Fatalf("over max: %q, %v", b, err)
	}
	if b, err := readPrivate(big, 5); err != nil || string(b) != "12345" {
		t.Fatalf("at max: %q, %v", b, err)
	}
	// Each read closes its file.
	resolved, err := filepath.EvalSymlinks(big)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		readPrivate(big, 5)
		if fd := mut3Open(t, resolved); fd != "" {
			t.Fatalf("a read left %s open (fd %s)", big, fd)
		}
	}
}

func mut3PlanKeysLogWhyAGrantGivesNoKey(t *testing.T) {
	r := newGrantRig(t)
	keys := r.keys()
	var bad key.Key
	notJSON := json.Unmarshal([]byte("{"), &bad)
	for name, c := range map[string]struct {
		write func()
		want  string
	}{
		"bare root": {func() { r.write(t, r.root, 0o600) }, "plan keys: grant " + r.path + ": a bare root, not a clerk key"},
		"not json": {func() {
			os.Remove(r.path)
			if err := os.WriteFile(r.path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "plan keys: grant " + r.path + ": " + notJSON.Error()},
		"over the cap": {func() {
			os.Remove(r.path)
			if err := os.WriteFile(r.path, bytes.Repeat([]byte(" "), maxPlanGrant+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "plan keys: grant " + r.path + ": " + r.path + ": larger than 65536 bytes"},
	} {
		c.write()
		r.logs = nil
		if _, h, ok := keys("a"); ok || h != nil {
			t.Errorf("%s: a key", name)
		}
		if len(r.logs) != 1 || r.logs[0] != c.want {
			t.Errorf("%s: logs %q, want %q", name, r.logs, c.want)
		}
	}
}

func mut3MachineHolderIsTheDomainSeparatedHMAC(t *testing.T) {
	holder := seedKey(4)
	mac := hmac.New(sha256.New, holder.Seed())
	mac.Write([]byte("agentos guest plan holder\x00"))
	mac.Write([]byte("m1"))
	want := ed25519.NewKeyFromSeed(mac.Sum(nil))
	if got := machineHolder(holder, "m1"); !got.Equal(want) {
		t.Fatal("machine m1's key is not HMAC(seed, \"agentos guest plan holder\\x00\" || name)")
	}
}

func mut3ImagePinNamesAMissingFileAndClosesWhatItOpens(t *testing.T) {
	dir := t.TempDir()
	if v, err := readCLIPin(dir); v != "" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no pin file: %q, %v; want not-exist", v, err)
	}
	img := pinnedImage(t, "1.2.3\n")
	rdir, err := filepath.EvalSymlinks(img)
	if err != nil {
		t.Fatal(err)
	}
	rpin := filepath.Join(rdir, cliPinPath)
	for range 3 {
		readCLIPin(img)
		if fd := mut3Open(t, rpin); fd != "" {
			t.Fatalf("a read left the pin file open (fd %s)", fd)
		}
		if fd := mut3Open(t, rdir); fd != "" {
			t.Fatalf("a read left the image root open (fd %s)", fd)
		}
	}
}

// mut3Notices serves notice.sock: a 500 while fail is set, else batch,
// counting every ask.
type mut3Notices struct {
	mu    sync.Mutex
	fail  bool
	batch notice.Batch
	asks  int
}

func (f *mut3Notices) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks++
	if f.fail {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(f.batch)
}

func (f *mut3Notices) set(fail bool, b notice.Batch) {
	f.mu.Lock()
	f.fail, f.batch = fail, b
	f.mu.Unlock()
}

func (f *mut3Notices) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.asks }

func mut3NoticeRig(t *testing.T) (*noticePuller, *mut3Notices, func() []string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "np")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, notice.Socket)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &mut3Notices{}
	srv := &http.Server{Handler: f}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	var mu sync.Mutex
	var got []string
	p := newNoticePuller(sock, func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
		return nil
	})
	return p, f, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, got...) }
}

func mut3NoticePollFailsAndResetsAsItShould(t *testing.T) {
	p, f, texts := mut3NoticeRig(t)
	c := noticesock.New(p.socket)
	f.set(true, notice.Batch{})
	if err := p.poll(context.Background(), c); err == nil {
		t.Fatal("a failed ask polled clean")
	}
	// Missed 3 says so once; a batch with none missed resets the count, so a
	// later overflow of 2 is said again.
	for _, m := range []uint64{3, 0, 2} {
		f.set(false, notice.Batch{Boot: "b", Missed: m})
		if err := p.poll(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if g := texts(); len(g) != 2 || g[0] != noticeMissedText || g[1] != noticeMissedText {
		t.Fatalf("texts = %q, want the missed line twice", g)
	}
	// A notice with no text is logged by its code.
	buf := mut3Log(t)
	f.set(false, notice.Batch{Boot: "b", Notices: []notice.Item{item(1, notice.Code("free_text"), "")}})
	if err := p.poll(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `notice socket: dropped a notice with code "free_text" that has no text`) {
		t.Fatalf("log %q", buf.String())
	}
}

func mut3NoticeRunTextsWaitsBetweenFailuresAndStops(t *testing.T) {
	p, f, texts := mut3NoticeRig(t)
	// A failing socket is asked again after each pause, not in a spin.
	p.retry = 50 * time.Millisecond
	f.set(true, notice.Batch{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.run(ctx); close(done) }()
	time.Sleep(300 * time.Millisecond)
	if n := f.count(); n < 2 || n > 12 {
		t.Fatalf("%d asks in 300ms at a 50ms pause", n)
	}
	// After the failure clears, the next ask's notice is texted.
	f.set(false, notice.Batch{Boot: "b", Notices: []notice.Item{item(1, notice.MailRemoved, "")}})
	deadline := time.Now().Add(5 * time.Second)
	for len(texts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(texts()) != 1 {
		t.Fatalf("texts %q after the socket recovered", texts())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop")
	}
	// A pause is cut short by the end of ctx.
	p.retry = time.Hour
	f.set(true, notice.Batch{})
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { p.run(ctx); close(done) }()
	for f.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // run is now in its hour-long pause
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run waited out its pause after ctx ended")
	}
}

func mut3DiskQuotaRefusesBeforeTouchingTheDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if _, _, err := machineQuota("bogus", dir); err == nil || err.Error() != `-disk-quota="bogus": want on or off` {
		t.Fatalf("bogus mode: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused mode made the state dir (%v)", err)
	}
	// A state dir that cannot be made is that error, not a quota one.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := machineQuota("on", filepath.Join(file, "state"))
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "mkdir" || strings.Contains(err.Error(), "prjquota") {
		t.Fatalf("unmakeable state dir: %v", err)
	}
	buf := mut3Log(t)
	var notes []func() string
	if d := openMachineDisk("off", dir, &notes); !d.off {
		t.Fatal("off is not off")
	}
	if !strings.Contains(buf.String(), "-disk-quota=off: agent machines run without disk quotas; a guest can fill the state disk (RES-4)") {
		t.Fatalf("log %q", buf.String())
	}
}

func mut3FollowSettingSaysWhatIsMissingAndWhatIsFollowed(t *testing.T) {
	for _, c := range [][2]string{{t.TempDir(), ""}, {"", filepath.Join(t.TempDir(), "root.json")}} {
		if _, err := newFollowSetting(c[0], c[1], noGuard); err == nil || err.Error() != "-update-store and -shipped-root go together" {
			t.Fatalf("%q: %v", c, err)
		}
	}
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	s, err := newFollowSetting(dir, shipped, noGuard)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := update.RootDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if obj, detail := s.retryLine(); obj != "updates, now from the project" || detail != "root "+digest[:12]+"; RETRY replaces it" {
		t.Fatalf("following the project: %q, %q", obj, detail)
	}
	if err := os.WriteFile(filepath.Join(dir, "source.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if obj, detail := s.retryLine(); obj != "updates, source unread" || detail != "RETRY replaces what I follow now" {
		t.Fatalf("an unreadable source: %q, %q", obj, detail)
	}
}

func mut3InferFlagsAndRefusals(t *testing.T) {
	var f inferFlags
	fl := flag.NewFlagSet("agentosd", flag.ContinueOnError)
	f.register(fl)
	if err := fl.Parse([]string{"-infer", "-infer-model", "/m.gguf", "-infer-model-sha256", "ab12"}); err != nil {
		t.Fatal(err)
	}
	if !f.On || f.Model != "/m.gguf" || f.Pin != "ab12" {
		t.Fatalf("flags %+v", f)
	}
	leaf := func() (*cgroup.Group, error) { return nil, errors.New("synthetic: no leaf") }
	for _, uid := range []int{-1, 0, os.Getuid()} {
		if _, err := superviseInference(context.Background(), inferFlags{UID: uid}, leaf, &bytes.Buffer{}); err == nil ||
			err.Error() != "-infer-uid must name the service's own uid, distinct from root and the broker's" {
			t.Fatalf("uid %d: %v", uid, err)
		}
	}
	const unknown = 2147480001
	if _, err := superviseInference(context.Background(), inferFlags{UID: unknown}, leaf, &bytes.Buffer{}); err == nil ||
		!strings.HasPrefix(err.Error(), "-infer-uid 2147480001: ") {
		t.Fatalf("unknown uid: %v", err)
	}
	root := shortDir(t)
	machines := func() (*cgroup.Group, error) { return &cgroup.Group{Path: filepath.Join(root, "machines")}, nil }
	if _, err := inferenceLeaf(machines, 0)(); err == nil || err.Error() != "the inference budget is 0 MB" {
		t.Fatalf("0 MB: %v", err)
	}
	if _, err := inferenceLeaf(machines, 64)(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no memory.max: %v", err)
	}
}
