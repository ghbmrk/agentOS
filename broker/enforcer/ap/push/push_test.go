package push

// REQ: NET-3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
)

// fakeAP is an SSH server that holds files and understands exactly the
// four commands push sends; anything else fails the test. Like an access
// point's shell, it keeps running a command after the client has closed
// the connection, and it models the access point's lock (apLock, taken
// only by a command that starts with flock) and token file (token, which
// a command checks only if it carries the check).
type fakeAP struct {
	t       *testing.T
	addr    string
	hostKey ssh.PublicKey
	apLock  sync.Mutex // the access point's flock on lockPath
	mu      sync.Mutex
	files   map[string][]byte
	token   string   // tokenPath's content
	events  []string // what took effect, in order: "claim 1", "write 1 <path>", "refused 1 <path>", "reload 1"
	hold    *hold    // holds one write after its stdin has arrived
	applies int
	writes  int
	logins  int
	stuck   bool // ignores writes, like a full or read-only flash

	failWrite  map[string]bool // writes of these paths fail
	cut        map[string]bool // stdin of writes to these paths ends halfway
	readFails  map[string]bool // reads of these paths print the file, then exit 1
	failReload int             // the next this many reloads fail
	failClaim  bool            // claims fail, as on an access point without flock

	// newest is the login number of the newest connection that has run
	// a command; interleaved is set when an older one runs a command
	// after it, which is two connections' commands interleaving.
	newest      int
	interleaved bool
}

// hold stalls the write of path on connection login: while its stdin is
// still arriving (a command the access point starts late, or whose
// stdin never ends) or once it holds the lock to move its file (one the
// access point is slow to finish). The write then runs to its end
// whatever the client did.
type hold struct {
	login   int
	path    string
	inLock  bool
	arrived chan struct{} // closed when the held write has started
	release chan struct{} // the test closes it to let the write go on
	done    chan struct{} // closed when the held write has ended
}

func (f *fakeAP) holdWrite(login int, path string, inLock bool) *hold {
	h := &hold{login: login, path: path, inLock: inLock, arrived: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	f.mu.Lock()
	f.hold = h
	f.mu.Unlock()
	f.t.Cleanup(func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
	})
	return h
}

func (f *fakeAP) event(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

// tokenRE finds a Sync's token in a command: 32 hex digits standing
// alone, which a 64-digit hash is not.
var tokenRE = regexp.MustCompile(`\b[0-9a-f]{32}\b`)

func newFakeAP(t *testing.T, client ssh.PublicKey) *fakeAP {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hk)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAP{t: t, hostKey: signer.PublicKey(), files: map[string][]byte{}}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(k.Marshal(), client.Marshal()) {
				return nil, errors.New("unknown key")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, cfg)
		}
	}()
	return f
}

func (f *fakeAP) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.logins++
	login := f.logins
	f.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go f.session(login, ch, creqs)
	}
}

func (f *fakeAP) session(login int, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Cmd string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		status := f.exec(login, p.Cmd, ch)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{status}))
		return
	}
}

func (f *fakeAP) exec(login int, cmd string, ch ssh.Channel) uint32 {
	f.mu.Lock()
	if login < f.newest {
		f.interleaved = true
	}
	f.newest = max(f.newest, login)
	f.mu.Unlock()
	for _, p := range ap.Paths {
		if cmd == readCmd(p) {
			f.mu.Lock()
			defer f.mu.Unlock()
			b, ok := f.files[p]
			if !ok {
				return 1
			}
			ch.Write(b)
			if f.readFails[p] {
				return 1
			}
			return 0
		}
	}
	tok := tokenRE.FindString(cmd)
	// What the shell does with the command's two guards: the lock only
	// if the command takes it, the token check only if it carries one.
	takesLock := strings.HasPrefix(cmd, "{ flock -x 9 && ") && strings.HasSuffix(cmd, "; } 9>"+lockPath)
	checks := strings.Contains(cmd, owns(tok)+" && ")
	lock := func() func() {
		if !takesLock {
			return func() {}
		}
		f.apLock.Lock()
		return f.apLock.Unlock
	}
	stale := func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return checks && f.token != tok
	}
	switch {
	case tok != "" && cmd == claimCmd(tok):
		defer lock()()
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failClaim {
			return 1
		}
		f.token = tok
		f.events = append(f.events, fmt.Sprint("claim ", login))
		return 0
	case tok != "" && cmd == applyCmd(tok):
		defer lock()()
		if stale() {
			f.event(fmt.Sprint("refused ", login, " reload"))
			return 1
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failReload > 0 {
			f.failReload--
			return 1
		}
		f.applies++
		f.events = append(f.events, fmt.Sprint("reload ", login))
		return 0
	}
	for _, p := range ap.Paths {
		if !strings.Contains(cmd, "cat > "+tmpPath(p, tok)+" ") {
			continue
		}
		// The lock is taken where the command takes it: before stdin is
		// read, or only for the move once the hash has checked.
		lockFirst := takesLock
		lockForMove := strings.Contains(cmd, " && { flock -x 9 && "+owns(tok)+" && mv -f ")
		unlock := func() {}
		defer func() { unlock() }()
		if lockFirst {
			unlock = lock()
		}
		f.mu.Lock()
		h := f.hold
		f.mu.Unlock()
		held := h != nil && h.login == login && h.path == p
		if held {
			defer close(h.done)
			close(h.arrived)
			if !h.inLock {
				<-h.release // stdin still arriving
			}
		}
		b, _ := io.ReadAll(ch)
		f.mu.Lock()
		if f.cut[p] {
			b = b[:len(b)/2] // stdin ended early
		}
		f.mu.Unlock()
		// The access point's own check: the hash in the command must be
		// that of what arrived, or nothing is moved into place.
		if cmd != writeCmd(p, tok, b) {
			return 1
		}
		if lockForMove && !lockFirst {
			f.apLock.Lock()
			unlock = f.apLock.Unlock
		}
		if held && h.inLock {
			<-h.release // slow to move
		}
		if stale() {
			f.event(fmt.Sprint("refused ", login, " ", p))
			return 1
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failWrite[p] {
			return 1
		}
		f.writes++
		if !f.stuck {
			f.files[p] = b
		}
		f.events = append(f.events, fmt.Sprint("write ", login, " ", p))
		return 0
	}
	f.t.Errorf("the access point was sent an unknown command %q", cmd)
	return 127
}

func (f *fakeAP) set(path string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = b
}

// n is the counts, read under the lock.
func (f *fakeAP) n() (logins, writes, applies, files int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.writes, f.applies, len(f.files)
}

func (f *fakeAP) setStuck(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stuck = v
}

func (f *fakeAP) get(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[path]
}

// dial is the tests' admin-port dialer: loopback to the fake.
var dial = (&net.Dialer{}).DialContext

func enforcerKey(t *testing.T) ssh.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func config() []ap.File {
	return []ap.File{
		{Path: ap.PathNetwork, Data: []byte("config interface 'admin'\n")},
		{Path: ap.PathWireless, Data: []byte("config wifi-station\n\toption vid '101'\n\toption key 'CANARYTVAAAAAAAAAAAAAAAAAA'\n")},
		{Path: ap.PathAuthKeys, Data: []byte("ssh-ed25519 AAAA\n")},
	}
}

// TestDriftRepushed: a first Sync writes everything to an empty access
// point and reloads; a second finds nothing to do; a file changed on the
// access point (a password added, a station's VLAN moved) or deleted is
// found as drift and written back, and only it, then reloaded and read
// back. Watch does the same on its own tick. Catches a changed AP config
// left in place.
func TestDriftRepushed(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	ctx := context.Background()

	res, err := p.Sync(ctx, config())
	if err != nil || !res.Applied || len(res.Drift) != 3 {
		t.Fatalf("first sync: %+v %v", res, err)
	}
	res, err = p.Sync(ctx, config())
	if _, _, applies, _ := f.n(); err != nil || res.Applied || len(res.Drift) != 0 || applies != 2 {
		t.Fatalf("in-sync sync: %+v %v applies=%d", res, err, applies)
	}

	_, writes, _, _ := f.n()
	f.set(ap.PathWireless, append(f.get(ap.PathWireless), "config wifi-station\n\toption vid '10'\n\toption key 'CANARYINTRUDERAAAAAAAAAAAA'\n"...))
	res, err = p.Sync(ctx, config())
	if _, w, _, _ := f.n(); err != nil || !res.Applied || len(res.Drift) != 1 || res.Drift[0] != ap.PathWireless || w != writes+1 {
		t.Fatalf("drift sync: %+v %v", res, err)
	}
	if !bytes.Equal(f.get(ap.PathWireless), config()[1].Data) {
		t.Fatal("drift left in place")
	}

	f.mu.Lock()
	delete(f.files, ap.PathAuthKeys)
	f.mu.Unlock()
	_, writes, _, _ = f.n()
	res, err = p.Sync(ctx, config())
	if _, w, _, _ := f.n(); err != nil || len(res.Drift) != 1 || res.Drift[0] != ap.PathAuthKeys || w != writes+1 {
		t.Fatalf("deleted file: %+v %v", res, err)
	}

	// Watch: drift between ticks is put back by the next one.
	// The test waits for Watch to return, and a Sync that the cancel
	// itself cuts short is not a failure.
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	reports := make(chan Result, 16)
	go func() {
		defer close(done)
		p.Watch(wctx, 20*time.Millisecond, func() ([]ap.File, error) { return config(), nil }, func(r Result, err error) {
			if err != nil && wctx.Err() == nil {
				t.Errorf("watch: %v", err)
			}
			select {
			case reports <- r:
			default:
			}
		})
	}()
	<-reports
	f.set(ap.PathNetwork, []byte("config interface 'lan'\n\toption proto 'static'\n"))
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-reports:
			if r.Applied {
				if !bytes.Equal(f.get(ap.PathNetwork), config()[0].Data) {
					t.Fatal("watch applied but left the drift")
				}
				return
			}
		case <-deadline:
			t.Fatal("watch never pushed the drift back")
		}
	}
}

// TestPinnedHostKey: an access point (or anyone on the admin port) with
// another host key is refused before the enforcer logs in or sends a
// byte of config. Catches a pusher that trusts whatever answers.
func TestPinnedHostKey(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	other := enforcerKey(t).PublicKey()
	p := &Pusher{Addr: f.addr, HostKey: other, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("other host key: %v", err)
	}
	if logins, writes, _, files := f.n(); logins != 0 || writes != 0 || files != 0 {
		t.Fatal("config reached an access point with the wrong host key")
	}
	if _, err := (&Pusher{Addr: f.addr, Signer: me, Dial: dial}).Sync(context.Background(), config()); err == nil {
		t.Fatal("synced with no pinned host key")
	}
	if _, err := (&Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me}).Sync(context.Background(), config()); err == nil {
		t.Fatal("synced with no admin-port dialer")
	}
}

// TestVerifyAndPaths: an access point that accepts writes but does not
// keep them fails the Sync, and a path outside ap.Paths is refused before
// any connection.
func TestVerifyAndPaths(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.setStuck(true)
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); !errors.Is(err, ErrVerify) {
		t.Fatalf("stuck access point: %v", err)
	}
	f.setStuck(false)
	logins, _, _, _ := f.n()
	bad := append(config(), ap.File{Path: "/etc/rc.local", Data: []byte("reboot\n")})
	if _, err := p.Sync(context.Background(), bad); !errors.Is(err, ErrPath) || func() bool { l, _, _, _ := f.n(); return l != logins }() {
		t.Fatalf("other path: %v", err)
	}
	// An oversized file is not read whole: it counts as drift and is
	// rewritten, so a hostile access point cannot stop the re-pushes.
	f.set(ap.PathNetwork, bytes.Repeat([]byte("x"), MaxFile+1))
	res, err := p.Sync(context.Background(), config())
	if err != nil || !slices.Contains(res.Drift, ap.PathNetwork) || !bytes.Equal(f.get(ap.PathNetwork), config()[0].Data) {
		t.Fatalf("oversized file: %+v %v", res, err)
	}
}

// TestFailedReloadFinished: a Sync whose reload fails after its writes is
// finished by the next, which finds the files in place and reloads them.
// Catches a revoked password that keeps working because the reload that
// would drop it failed once and was never tried again.
func TestFailedReloadFinished(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failReload = 1
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); err == nil {
		t.Fatal("a failed reload was not reported")
	}
	if _, _, applies, _ := f.n(); applies != 0 {
		t.Fatalf("applies = %d", applies)
	}
	if res, err := p.Sync(context.Background(), config()); err != nil || len(res.Drift) != 0 {
		t.Fatalf("second sync: %+v %v", res, err)
	}
	if _, _, applies, _ := f.n(); applies != 1 {
		t.Fatalf("the files in place were never reloaded: applies = %d", applies)
	}
}

// TestSyncsDoNotOverlap: two Syncs of one Pusher never interleave their
// commands on the access point: once a newer connection has run a
// command, no older one runs another. Catches a shared temporary file
// swapped between two pushes. It checks commands, not how long the fake
// holds a connection open: the fake sees a connection end only some time
// after Sync's Close returns, so counting open connections saw two at
// once between correct Syncs (#4248).
func TestSyncsDoNotOverlap(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Sync(context.Background(), config()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.interleaved || f.logins != 4 {
		t.Fatalf("interleaved %v over %d logins", f.interleaved, f.logins)
	}
}

// TestTempFilePerPath: each path is written through a temporary file of
// its own path and Sync, on /etc, so no two writes can share one, and
// the claim's glob matches every one of them.
func TestTempFilePerPath(t *testing.T) {
	seen := map[string]string{}
	tok, other := token(), token()
	for _, p := range ap.Paths {
		for _, k := range []string{tok, other} {
			tp := tmpPath(p, k)
			if !strings.HasPrefix(tp, "/etc/") || strings.Count(tp, "/") != 2 || strings.ContainsAny(tp, " ;|&$`'\"*?[") {
				t.Errorf("temporary file for %s: %q", p, tp)
			}
			if m, _ := path.Match(tmpGlob, tp); !m {
				t.Errorf("the claim does not remove %s", tp)
			}
			if q, dup := seen[tp]; dup {
				t.Errorf("%s and %s share %s", p, q, tp)
			}
			seen[tp] = p
		}
	}
	for _, p := range ap.Paths {
		if m, _ := path.Match(tmpGlob, p); m {
			t.Errorf("the claim removes %s", p)
		}
	}
	// The write command itself uses its path's and Sync's file and no other's.
	for _, p := range ap.Paths {
		for _, q := range ap.Paths {
			if has := strings.Contains(writeCmd(p, tok, nil), tmpPath(q, tok)) && !strings.Contains(writeCmd(p, tok, nil), other); has != (p == q) {
				t.Errorf("write command for %s names the temporary file of %s: %v", p, q, has)
			}
		}
	}
}

// TestCutOffReadDoesNotHang: a file far past MaxFile is cut and
// rewritten without waiting for the rest of it. Catches a read that waits
// for a command that has more to say than the enforcer will take.
func TestCutOffReadDoesNotHang(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.set(ap.PathNetwork, bytes.Repeat([]byte("x"), 16<<20))
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	start := time.Now()
	res, err := p.Sync(context.Background(), config())
	if err != nil || !slices.Contains(res.Drift, ap.PathNetwork) || time.Since(start) > 4*time.Second {
		t.Fatalf("sync of a 16 MiB file: %+v %v after %v", res, err, time.Since(start))
	}
}

// TestDefaultsAndLimit: a zero Timeout means 30 seconds, not none, and a
// file of exactly MaxFile bytes is read back whole.
func TestDefaultsAndLimit(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	big := []ap.File{{Path: ap.PathNetwork, Data: bytes.Repeat([]byte("x"), MaxFile)}}
	f.set(ap.PathNetwork, big[0].Data)
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial}
	if res, err := p.Sync(context.Background(), big); err != nil || res.Applied {
		t.Fatalf("default timeout, file at the limit: %+v %v", res, err)
	}
}

// TestFailedReadIsDrift: a read that prints a file of exactly MaxFile
// bytes but exits with an error does not count as holding it. Catches a
// read that skips the exit status.
func TestFailedReadIsDrift(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	data := bytes.Repeat([]byte("x"), MaxFile)
	f.set(ap.PathNetwork, data)
	f.mu.Lock()
	f.readFails = map[string]bool{ap.PathNetwork: true}
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	res, err := p.Sync(context.Background(), []ap.File{{Path: ap.PathNetwork, Data: data}})
	// The read-back after the write fails the same way, so Sync ends in
	// ErrVerify; what counts is that the file was found as drift.
	if !errors.Is(err, ErrVerify) || !slices.Contains(res.Drift, ap.PathNetwork) {
		t.Fatalf("a failed read counted as holding the file: %+v %v", res, err)
	}
}

// TestFailedWriteStillReloads: when a later file's write fails, the files
// written before it are still reloaded, so a revoked password in the
// first file does not stay live because the error named another file.
// Catches a Sync that returns between a write and the reload.
func TestFailedWriteStillReloads(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failWrite = map[string]bool{ap.PathAuthKeys: true}
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	for i := range 2 {
		if _, err := p.Sync(context.Background(), config()); err == nil {
			t.Fatalf("sync %d: a failed write was not reported", i)
		}
		if _, _, applies, _ := f.n(); applies != i+1 {
			t.Fatalf("sync %d: applies = %d", i, applies)
		}
	}
	if !bytes.Equal(f.get(ap.PathWireless), config()[1].Data) {
		t.Fatal("the written file is not in place")
	}
}

// TestCutWriteNotMovedInPlace: a write whose stdin ends early leaves the
// file on the access point as it was, and the next Sync writes it whole.
// Catches a half-written config moved into place by a dropped connection.
func TestCutWriteNotMovedInPlace(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	old := []byte("config dropbear\n\toption PasswordAuth 'off'\n")
	f.set(ap.PathAuthKeys, old)
	f.mu.Lock()
	f.cut = map[string]bool{ap.PathAuthKeys: true}
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); err == nil {
		t.Fatal("a cut write was not reported")
	}
	if !bytes.Equal(f.get(ap.PathAuthKeys), old) {
		t.Fatalf("a half-written file was moved into place: %q", f.get(ap.PathAuthKeys))
	}
	f.mu.Lock()
	f.cut = nil
	f.mu.Unlock()
	if _, err := p.Sync(context.Background(), config()); err != nil || !bytes.Equal(f.get(ap.PathAuthKeys), config()[2].Data) {
		t.Fatalf("the next sync did not write it whole: %v", err)
	}
}

// TestFailedWriteDoesNotBlockLaterFiles: a write that fails on every Sync
// does not keep a later file from being written, so a revoked key in
// wireless is applied although network cannot be written.
func TestFailedWriteDoesNotBlockLaterFiles(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failWrite = map[string]bool{ap.PathNetwork: true}
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	res, err := p.Sync(context.Background(), config())
	if err == nil || !res.Applied {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if !bytes.Equal(f.get(ap.PathWireless), config()[1].Data) || !bytes.Equal(f.get(ap.PathAuthKeys), config()[2].Data) {
		t.Fatal("a file after the failing one was not written")
	}
	if _, _, applies, _ := f.n(); applies != 1 {
		t.Fatalf("applies = %d", applies)
	}
}

// TestWriteAndReloadErrorsBothReturned: when a write and the reload both
// fail, both are in the error, and Applied stays false.
func TestWriteAndReloadErrorsBothReturned(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failWrite = map[string]bool{ap.PathNetwork: true}
	f.failReload = 1
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	res, err := p.Sync(context.Background(), config())
	if err == nil || res.Applied || !strings.Contains(err.Error(), "write "+ap.PathNetwork) || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("sync: %+v %v", res, err)
	}
}

// TestNothingWrittenNotApplied: when every write fails, Applied is false
// although the reload ran.
func TestNothingWrittenNotApplied(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failWrite = map[string]bool{}
	for _, p := range ap.Paths {
		f.failWrite[p] = true
	}
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	res, err := p.Sync(context.Background(), config())
	if err == nil || res.Applied {
		t.Fatalf("sync: %+v %v", res, err)
	}
}

// revoked is config() with a second station whose password has since
// been revoked: what a Sync that timed out was still writing.
func revoked() []ap.File {
	c := config()
	c[1].Data = append(bytes.Clone(c[1].Data), "config wifi-station\n\toption vid '102'\n\toption key 'CANARYREVOKEDAAAAAAAAAAAAA'\n"...)
	return c
}

// TestLateWriteOfTimedOutSyncRefused: a Sync times out while the access
// point has not yet started its write of the wireless file, which carries
// a password since revoked; the command keeps running there after the
// client has gone. The next Sync writes the config without that password.
// When the old write then runs, it finds the newer claim and does
// nothing, so the revoked password stays out. Catches a late write of a
// timed-out Sync putting back an older config (ENF-g-8, #4313).
func TestLateWriteOfTimedOutSyncRefused(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	h := f.holdWrite(1, ap.PathWireless, false)
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 300 * time.Millisecond}
	if _, err := p.Sync(context.Background(), revoked()); err == nil {
		t.Fatal("a Sync whose write never ended did not fail")
	}
	<-h.arrived
	p.Timeout = 5 * time.Second
	if _, err := p.Sync(context.Background(), config()); err != nil {
		t.Fatalf("next sync: %v", err)
	}
	close(h.release)
	<-h.done
	if got := f.get(ap.PathWireless); !bytes.Equal(got, config()[1].Data) {
		t.Fatalf("the timed-out Sync's late write put back %q", got)
	}
	f.mu.Lock()
	last := f.events[len(f.events)-1]
	f.mu.Unlock()
	if last != "refused 1 "+ap.PathWireless {
		t.Fatalf("last event %q", last)
	}
	if res, err := p.Sync(context.Background(), config()); err != nil || len(res.Drift) != 0 {
		t.Fatalf("sync after: %+v %v", res, err)
	}
}

// TestSlowWriteEndsBeforeNextClaim: a Sync times out while its write
// holds the access point's lock. The next Sync's claim waits for that
// write to end, so the old write and every command of the new Sync run
// one after the other, and the new Sync's write lands last. Catches two
// Syncs' writes sharing a temporary file at once (ENF-g-8, #4313).
func TestSlowWriteEndsBeforeNextClaim(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	h := f.holdWrite(1, ap.PathWireless, true)
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 300 * time.Millisecond}
	if _, err := p.Sync(context.Background(), revoked()); err == nil {
		t.Fatal("a Sync whose write never ended did not fail")
	}
	<-h.arrived
	p.Timeout = 5 * time.Second
	errc := make(chan error, 1)
	go func() {
		_, err := p.Sync(context.Background(), config())
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond) // the new claim is waiting on the lock
	f.mu.Lock()
	early := slices.Contains(f.events, "claim 2")
	f.mu.Unlock()
	close(h.release)
	if err := <-errc; err != nil {
		t.Fatalf("next sync: %v", err)
	}
	<-h.done
	if early {
		t.Fatal("the next Sync claimed the access point while the old write held its lock")
	}
	f.mu.Lock()
	ev := slices.Clone(f.events)
	f.mu.Unlock()
	old, claim := slices.Index(ev, "write 1 "+ap.PathWireless), slices.Index(ev, "claim 2")
	if old < 0 || claim < old {
		t.Fatalf("events %q", ev)
	}
	if got := f.get(ap.PathWireless); !bytes.Equal(got, config()[1].Data) {
		t.Fatalf("wireless holds %q", got)
	}
}

// TestFailedClaimWritesNothing: an access point that cannot take the
// claim (no flock, a full /tmp) gets no write and no reload, and the
// Sync fails. Catches a Sync that writes without holding the claim.
func TestFailedClaimWritesNothing(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.mu.Lock()
	f.failClaim = true
	f.mu.Unlock()
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); err == nil || !strings.Contains(err.Error(), "claim") {
		t.Fatalf("sync: %v", err)
	}
	if _, writes, applies, files := f.n(); writes != 0 || applies != 0 || files != 0 {
		t.Fatalf("writes=%d applies=%d files=%d", writes, applies, files)
	}
}

// TestCommandsTakeTheLock: the claim, every write's move and the reload
// run under the access point's lock, the move and the reload only while
// their Sync's token is the newest; a write reads stdin with no lock
// held; the claim removes earlier temporary files; and the reload does
// not pass the lock's descriptor to what it starts. Each Sync draws a
// new token.
func TestCommandsTakeTheLock(t *testing.T) {
	tok := token()
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(tok) || tok == token() {
		t.Fatalf("token %q", tok)
	}
	for _, c := range []string{claimCmd(tok), applyCmd(tok)} {
		if !strings.HasPrefix(c, "{ flock -x 9 && ") || !strings.HasSuffix(c, "; } 9>"+lockPath) {
			t.Errorf("not under the lock: %q", c)
		}
	}
	if !strings.HasPrefix(applyCmd(tok), "{ flock -x 9 && "+owns(tok)+" && ") {
		t.Errorf("reload does not check the token first: %q", applyCmd(tok))
	}
	if !strings.HasSuffix(claimCmd(tok), " && rm -f "+tmpGlob+"; } 9>"+lockPath) {
		t.Errorf("claim leaves earlier temporary files: %q", claimCmd(tok))
	}
	for _, p := range ap.Paths {
		c := writeCmd(p, tok, []byte("x"))
		read, move, ok := strings.Cut(c, " && { flock -x 9 && "+owns(tok)+" && mv -f "+tmpPath(p, tok)+" "+p+"; } 9>"+lockPath)
		if !ok || strings.Contains(read, "flock") || !strings.HasPrefix(read, "umask 077 && cat > "+tmpPath(p, tok)+" && ") || move != " || { rm -f "+tmpPath(p, tok)+"; false; }" {
			t.Errorf("write does not read unlocked and move under the lock with the token checked: %q", c)
		}
	}
	if !strings.Contains(applyCmd(tok), "reload_config 9>&-;") {
		t.Errorf("reload keeps the lock's descriptor: %q", applyCmd(tok))
	}
}

// TestEndlessStdinHoldsNothing: a timed-out Sync's write whose stdin never
// ends on the access point (a link that dropped before its end) does not
// hold up the next Syncs, which write and reload as usual. Catches a
// write that takes the access point's lock before reading stdin, which
// would keep every revocation off the access point until it rebooted.
func TestEndlessStdinHoldsNothing(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	h := f.holdWrite(1, ap.PathWireless, false) // released only at cleanup
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Dial: dial, Timeout: 300 * time.Millisecond}
	if _, err := p.Sync(context.Background(), revoked()); err == nil {
		t.Fatal("a Sync whose write never ended did not fail")
	}
	<-h.arrived
	p.Timeout = 2 * time.Second
	for i := range 2 {
		if res, err := p.Sync(context.Background(), config()); err != nil || (i == 0) != res.Applied {
			t.Fatalf("sync %d behind an endless write: %+v %v", i, res, err)
		}
	}
	if got := f.get(ap.PathWireless); !bytes.Equal(got, config()[1].Data) {
		t.Fatalf("wireless holds %q", got)
	}
}
