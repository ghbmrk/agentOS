package push

// REQ: NET-3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
)

// fakeAP is an SSH server that holds files and understands exactly the
// three commands push sends; anything else fails the test.
type fakeAP struct {
	t       *testing.T
	addr    string
	hostKey ssh.PublicKey
	mu      sync.Mutex
	files   map[string][]byte
	applies int
	writes  int
	logins  int
	stuck   bool // ignores writes, like a full or read-only flash
}

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
		go f.session(ch, creqs)
	}
}

func (f *fakeAP) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Cmd string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		status := f.exec(p.Cmd, ch)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{status}))
		return
	}
}

func (f *fakeAP) exec(cmd string, ch ssh.Channel) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cmd == applyCmd {
		f.applies++
		return 0
	}
	for _, p := range ap.Paths {
		switch cmd {
		case readCmd(p):
			b, ok := f.files[p]
			if !ok {
				return 1
			}
			ch.Write(b)
			return 0
		case writeCmd(p):
			b, _ := io.ReadAll(ch)
			f.writes++
			if !f.stuck {
				f.files[p] = b
			}
			return 0
		}
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
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Timeout: 5 * time.Second}
	ctx := context.Background()

	res, err := p.Sync(ctx, config())
	if err != nil || !res.Applied || len(res.Drift) != 3 {
		t.Fatalf("first sync: %+v %v", res, err)
	}
	res, err = p.Sync(ctx, config())
	if _, _, applies, _ := f.n(); err != nil || res.Applied || len(res.Drift) != 0 || applies != 1 {
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
	if res, err := p.Sync(ctx, config()); err != nil || len(res.Drift) != 1 || res.Drift[0] != ap.PathAuthKeys {
		t.Fatalf("deleted file: %+v %v", res, err)
	}

	// Watch: drift between ticks is put back by the next one.
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reports := make(chan Result, 16)
	go p.Watch(wctx, 20*time.Millisecond, func() ([]ap.File, error) { return config(), nil }, func(r Result, err error) {
		if err != nil {
			t.Errorf("watch: %v", err)
		}
		reports <- r
	})
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
	p := &Pusher{Addr: f.addr, HostKey: other, Signer: me, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("other host key: %v", err)
	}
	if logins, writes, _, files := f.n(); logins != 0 || writes != 0 || files != 0 {
		t.Fatal("config reached an access point with the wrong host key")
	}
	if _, err := (&Pusher{Addr: f.addr, Signer: me}).Sync(context.Background(), config()); err == nil {
		t.Fatal("synced with no pinned host key")
	}
}

// TestVerifyAndPaths: an access point that accepts writes but does not
// keep them fails the Sync, and a path outside ap.Paths is refused before
// any connection.
func TestVerifyAndPaths(t *testing.T) {
	me := enforcerKey(t)
	f := newFakeAP(t, me.PublicKey())
	f.setStuck(true)
	p := &Pusher{Addr: f.addr, HostKey: f.hostKey, Signer: me, Timeout: 5 * time.Second}
	if _, err := p.Sync(context.Background(), config()); !errors.Is(err, ErrVerify) {
		t.Fatalf("stuck access point: %v", err)
	}
	f.setStuck(false)
	logins, _, _, _ := f.n()
	bad := append(config(), ap.File{Path: "/etc/rc.local", Data: []byte("reboot\n")})
	if _, err := p.Sync(context.Background(), bad); !errors.Is(err, ErrPath) || func() bool { l, _, _, _ := f.n(); return l != logins }() {
		t.Fatalf("other path: %v", err)
	}
	f.set(ap.PathNetwork, bytes.Repeat([]byte("x"), MaxFile+1))
	if _, err := p.Sync(context.Background(), config()); err == nil {
		t.Fatal("read an oversized file")
	}
}
