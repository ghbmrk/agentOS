package main

// REQ: CLK-1, CLK-7, PLN-5

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// shortDir is a directory short enough for a socket's path, this uid's
// alone.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cm")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

var good = []string{
	"-dir", "/var/lib/agentos-model", "-owner-sock", "/run/agentos-model/owner.sock",
	"-signin-sock", "/run/agentos-signin/signin.sock", "-agentosd-uid", "0",
}

func with(flag, v string) []string {
	a := slices.Clone(good)
	a[slices.Index(a, flag)+1] = v
	return a
}

func TestFlags(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil || c.agentosdUID != 0 || c.signInSock != "/run/agentos-signin/signin.sock" {
		t.Fatalf("parse(good) = %+v, %v", c, err)
	}
	bad := map[string][]string{
		"relative dir":       with("-dir", "var/lib/agentos-model"),
		"no owner socket":    with("-owner-sock", ""),
		"relative signin":    with("-signin-sock", "signin.sock"),
		"no agentosd uid":    with("-agentosd-uid", "-1"),
		"stray argument":     append(slices.Clone(good), "x"),
		"an unknown flag":    append(slices.Clone(good), "-model-sock", "/run/m.sock"),
		"no signin socket":   with("-signin-sock", ""),
		"negative agentosd":  with("-agentosd-uid", "-7"),
		"relative owner one": with("-owner-sock", "owner.sock"),
	}
	for name, args := range bad {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func keyPipe(t *testing.T, name string, k [clerkkey.Len]byte) *os.File {
	t.Helper()
	b, err := clerkkey.Marshal(clerkkey.Key{Name: name, Key: k})
	must(t, err)
	r, w, err := os.Pipe()
	must(t, err)
	t.Cleanup(func() { r.Close() })
	_, err = w.Write(b)
	must(t, err)
	w.Close()
	return r
}

// fullPipe holds a hand-off-sized payload, its writer closed.
func fullPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	must(t, err)
	t.Cleanup(func() { r.Close() })
	_, err = w.Write(make([]byte, 90))
	must(t, err)
	w.Close()
	return r
}

func unread(t *testing.T, r *os.File) {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil || len(b) != 90 {
		t.Fatalf("the key was read: %d bytes left, %v", len(b), err)
	}
}

// CLK-1: a clerk refused as root, as agentosd's uid, or on a state
// directory another uid can reach takes no key, so the key never sits in a
// process a peer could read.
func TestARefusedClerkLeavesItsKeyUnread(t *testing.T) {
	me := os.Getuid()
	dir := shortDir(t)
	args := with("-dir", dir)
	r := fullPipe(t)
	err := start(with("-agentosd-uid", strconv.Itoa(me)), io.Discard, r)
	if err == nil || !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("got %v, want a root or peer-uid refusal", err)
	}
	unread(t, r)
	if me == 0 {
		return
	}
	must(t, os.Chmod(dir, 0o750))
	args[slices.Index(args, "-agentosd-uid")+1] = strconv.Itoa(me + 1)
	r = fullPipe(t)
	if err := start(args, io.Discard, r); err == nil || !strings.Contains(err.Error(), "open to other uids") {
		t.Fatalf("got %v, want the open state directory refused", err)
	}
	unread(t, r)
}

// A hand-off of another clerk's key, or a damaged one, opens nothing.
func TestTheKeyMustBeTheModelClerks(t *testing.T) {
	c := config{dir: shortDir(t)}
	for name, r := range map[string]*os.File{"the mail clerk's": keyPipe(t, "mail", [32]byte{7}), "a damaged": fullPipe(t)} {
		if err := serve(context.Background(), c, r); !errors.Is(err, clerkkey.ErrKey) {
			t.Errorf("%s key: %v", name, err)
		}
	}
}

// sealedSlot writes a plan login sealed under the model clerk's key k, as
// plan.Store seals it, into dir's slot: a stored token and a refused-login
// stop. The token is a synthetic canary.
func sealedSlot(t *testing.T, dir string, k [32]byte) {
	t.Helper()
	ck := clerkkey.Key{Name: clerkName, Key: k}
	sk, err := ck.Sealer()
	must(t, err)
	s, err := clerk.NewAESSealer(sk)
	must(t, err)
	b, err := s.Seal([]byte(`{"tokens":{"access_token":"canary-not-a-token"},"stop":"`+plan.StopRefused+`"}`), []byte("agentos/clerk/plan/codex"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, planSlot), b, 0o600))
}

// host is a fake of agentosd's sign-in socket, on its wire: it records
// each call, makes the route signinroute names, and refuses signinstart
// after seeing the guest's endpoint in it.
type host struct {
	routes string
	mu     sync.Mutex
	ops    []string
	guest  string
	served bool // the guest's endpoint answered in its route at signinstart
}

// answers reports whether an HTTP endpoint at sock answers this uid, which
// stands for agentosd's sandbox host: a refused peer is closed unanswered.
func answers(sock string) bool {
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "GET /none HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		return false
	}
	b := make([]byte, 12)
	n, _ := io.ReadFull(c, b)
	return n == len(b) && strings.HasPrefix(string(b), "HTTP/1.1 ")
}

func (h *host) serve(t *testing.T, sock string) {
	ln, err := proc.ListenKernel(sock, os.Getuid())
	must(t, err)
	t.Cleanup(func() { ln.Close() })
	go proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var a struct{ Guest string }
			json.Unmarshal(raw, &a)
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ops = append(h.ops, op)
			h.guest = a.Guest
			route := filepath.Join(h.routes, a.Guest)
			switch op {
			case "signinroute":
				if err := os.Mkdir(route, 0o700); err != nil {
					return nil, err
				}
				return json.Marshal(map[string]string{"route": route})
			case "signinstart":
				h.served = answers(filepath.Join(route, run.SignInRouteSocket))
				return nil, errors.New("no machine in this test")
			}
			return nil, nil
		})
	})
}

// running serves c with key k and answers the owner socket's caller.
func running(t *testing.T, c config, k [32]byte) run.PlanOwner {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, keyPipe(t, clerkName, k)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	o := run.PlanOwner{Conn: proc.Conn{Socket: c.ownerSock, UID: os.Getuid(), Timeout: time.Minute}}
	for range 200 {
		if _, err := os.Stat(c.ownerSock); err == nil {
			return o
		}
		select {
		case err := <-done:
			done <- nil // for the cleanup, which waits on it
			t.Fatalf("serve ended: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("the owner socket never opened")
	return o
}

// refused starts c with key k for at most two seconds: an error, or nil if
// it opened and served.
func refused(t *testing.T, c config, k [32]byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return serve(ctx, c, keyPipe(t, clerkName, k))
}

func testConfig(t *testing.T) config {
	rd := shortDir(t)
	state := filepath.Join(rd, "s")
	must(t, os.Mkdir(state, 0o700))
	return config{dir: state, ownerSock: filepath.Join(rd, "o.sock"), signInSock: filepath.Join(rd, "h.sock"), agentosdUID: os.Getuid()}
}

// CLK-1, CLK-7: the plan login lives in this clerk's own sealed slot. It
// opens at start under the same key and shows on the owner socket;
// planremove empties it on the drive; a slot another uid can read, or that
// is a link, refuses the start, since that is the directory tampered with.
func TestThePlanLoginIsSealedInTheClerksOwnSlot(t *testing.T) {
	k := [32]byte{7}
	c := testConfig(t)
	sealedSlot(t, c.dir, k)
	owner := running(t, c, k)
	st, err := owner.State()
	if err != nil || !st.SignedIn || st.Stopped != plan.StopRefused || st.Mode != plan.Permitted {
		t.Fatalf("state = %+v, %v; want the sealed login, stopped refused", st, err)
	}
	must(t, owner.Remove())
	if b, err := os.ReadFile(filepath.Join(c.dir, planSlot)); err != nil || len(b) != 0 {
		t.Fatalf("after planremove the slot holds %d bytes, %v", len(b), err)
	}

	open := testConfig(t)
	sealedSlot(t, open.dir, k)
	must(t, os.Chmod(filepath.Join(open.dir, planSlot), 0o640))
	if err := refused(t, open, k); err == nil {
		t.Error("a slot another uid can read opened")
	}
	link := testConfig(t)
	sealedSlot(t, filepath.Dir(link.dir), k)
	must(t, os.Symlink(filepath.Join(filepath.Dir(link.dir), planSlot), filepath.Join(link.dir, planSlot)))
	if err := refused(t, link, k); err == nil {
		t.Error("a slot that is a link opened")
	}
}

// PLN-5, CLK-7: the owner's planbegin runs the sign-in through agentosd's
// sign-in socket (run.SignInSock): agentosd makes the guest's route, this
// process serves the guest's endpoint in it, to agentosd's uid, before the
// machine is asked for, and a start agentosd refuses is stopped and shows no code.
func TestPlanBeginRunsTheSignInOnAgentosdsSocket(t *testing.T) {
	c := testConfig(t)
	h := &host{routes: shortDir(t)}
	h.serve(t, c.signInSock)
	b, err := running(t, c, [32]byte{7}).Begin()
	if err != nil || b.Code != "" || b.Detail != run.DSignInFailed {
		t.Fatalf("planbegin = %+v, %v; want %s and no code", b, err, run.DSignInFailed)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if want := []string{"signinroute", "signinstart", "signinstop"}; !slices.Equal(h.ops, want) {
		t.Errorf("agentosd saw %v, want %v", h.ops, want)
	}
	if !strings.HasPrefix(h.guest, "signin-") || !h.served {
		t.Errorf("guest %q, endpoint served in its route at start: %v", h.guest, h.served)
	}
}

// CLK-1: the process holding the plan login links none of the main side's
// code, and not provagent, whose plan sign-in this replaces.
func TestTheModelProcessLinksNoMainSideCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	must(t, err)
	const b = "github.com/ghbmrk/agentos/broker/"
	for _, dep := range strings.Fields(string(out)) {
		if dep == b+"owner" {
			t.Errorf("the model clerk's process links the owner channel %s", dep)
		}
		for _, no := range []string{"provagent", "vm", "egress", "infer", "guest", "browser", "localui", "localsrv", "modelroute", "tpmseal", "clerk/seal", "owner/kernelsock", "daemon", "voice"} {
			if dep == b+no || strings.HasPrefix(dep, b+no+"/") {
				t.Errorf("the model clerk's process links %s", dep)
			}
		}
	}
}

// CLK-1, OWN-17 (#3568 UX 1): a slot whose value does not open (sealed
// under another key, damaged, or oversized) is never opened, and the clerk
// starts signed out rather than refusing every start, so the owner's
// planremove and sign-in stay reachable. The owner's next write replaces
// the slot, and a start after it opens the slot under this key.
func TestAnUnopenableSlotStartsSignedOut(t *testing.T) {
	k := [32]byte{7}
	for name, write := range map[string]func(dir string){
		"another key's": func(dir string) { sealedSlot(t, dir, [32]byte{8}) },
		"damaged": func(dir string) {
			must(t, os.WriteFile(filepath.Join(dir, planSlot), []byte("not a sealed slot"), 0o600))
		},
		"oversized": func(dir string) {
			must(t, os.WriteFile(filepath.Join(dir, planSlot), make([]byte, maxPlanSlot+1), 0o600))
		},
	} {
		c := testConfig(t)
		write(c.dir)
		before, err := os.ReadFile(filepath.Join(c.dir, planSlot))
		must(t, err)
		owner := running(t, c, k)
		st, err := owner.State()
		if err != nil || st.SignedIn || st.Stopped != "" {
			t.Errorf("%s slot: state = %+v, %v; want signed out and not stopped", name, st, err)
			continue
		}
		if after, _ := os.ReadFile(filepath.Join(c.dir, planSlot)); string(after) != string(before) {
			t.Errorf("%s slot: changed before any write", name)
		}
		must(t, owner.Remove())
		if b, err := os.ReadFile(filepath.Join(c.dir, planSlot)); err != nil || len(b) != 0 {
			t.Errorf("%s slot: the owner's write left %d bytes, %v", name, len(b), err)
		}
		again := testConfig(t)
		again.dir = c.dir
		if st, err := running(t, again, k).State(); err != nil || st.SignedIn {
			t.Errorf("%s slot: after the write a start reads %+v, %v", name, st, err)
		}
	}
}
