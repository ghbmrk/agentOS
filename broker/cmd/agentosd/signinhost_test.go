package main

// REQ: PLN-5, CLK-7, CLK-1, ARC-2, CAP-8

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vm"
)

// signInBox is the sandbox host as a sign-in sees it: CreateProviderWorker
// opens the machine's route as vm.Manager does (Config.ProviderRoutes),
// Exec runs the sign-in command's CLI, which is cli, and the cat reads.
type signInBox struct {
	routes vm.Services
	cli    func(route string) (printed string)

	mu        sync.Mutex
	specs     map[string]vm.Spec
	mounts    map[string]string
	argv      map[string][]string
	printed   map[string]string
	exited    map[string]bool
	destroyed []string
	createErr error
	created   chan string // each create, once it returns
}

func newSignInBox(cli func(string) string) *signInBox {
	return &signInBox{cli: cli, specs: map[string]vm.Spec{}, mounts: map[string]string{}, argv: map[string][]string{},
		printed: map[string]string{}, exited: map[string]bool{}, created: make(chan string, 16)}
}

func (b *signInBox) CreateProviderWorker(_ context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error) {
	b.mu.Lock()
	err := b.createErr
	b.mu.Unlock()
	if seed != nil {
		err = errors.New("a sign-in machine is never seeded")
	}
	if err != nil {
		return vm.Machine{}, err
	}
	dir, err := b.routes.Open(id)
	if err != nil {
		return vm.Machine{}, err
	}
	b.mu.Lock()
	b.specs[id], b.mounts[id] = s, dir
	b.mu.Unlock()
	b.created <- id
	return vm.Machine{ID: id}, nil
}

func (b *signInBox) Exec(_ context.Context, id string, c vm.Command, _ time.Duration) (vm.ExecResult, error) {
	b.mu.Lock()
	route, ok := b.mounts[id]
	gone := slices.Contains(b.destroyed, id)
	b.mu.Unlock()
	if !ok || gone || c.As != vm.Private {
		return vm.ExecResult{}, vm.ErrUnknown
	}
	if c.Argv[0] == "cat" {
		b.mu.Lock()
		defer b.mu.Unlock()
		switch c.Argv[1] {
		case "/var/lib/agentos-work/.agentos-signin":
			return vm.ExecResult{Stdout: []byte(b.printed[id])}, nil
		case "/var/lib/agentos-work/.agentos-signin-status":
			if b.exited[id] {
				return vm.ExecResult{Stdout: []byte("1\n")}, nil
			}
			return vm.ExecResult{ExitCode: 1}, nil
		}
		return vm.ExecResult{ExitCode: 1}, nil
	}
	b.mu.Lock()
	b.argv[id] = c.Argv
	b.mu.Unlock()
	go func() {
		p := b.cli(route)
		b.mu.Lock()
		b.printed[id] = p
		b.mu.Unlock()
	}()
	return vm.ExecResult{}, nil
}

func (b *signInBox) Destroy(_ context.Context, id string) error {
	b.mu.Lock()
	_, ok := b.mounts[id]
	if ok {
		b.destroyed = append(b.destroyed, id)
		delete(b.mounts, id)
	}
	b.mu.Unlock()
	if !ok {
		return vm.ErrUnknown
	}
	b.routes.Close(id)
	return nil
}

func (b *signInBox) gone(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Contains(b.destroyed, id)
}

func (b *signInBox) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.specs)
}

// fallRoutes is the other provider workers' route source.
type fallRoutes struct{ opened, closed []string }

func (f *fallRoutes) Open(id string) (string, error) {
	f.opened = append(f.opened, id)
	return "/run/vault/" + id, nil
}
func (f *fallRoutes) Close(id string) { f.closed = append(f.closed, id) }

func newSignInHost(box *signInBox, fall vm.Services) *signInHost {
	h := &signInHost{M: box, Plan: signInPlans["codex"], UID: os.Getuid(), Fall: fall, NewID: func() string { return randHex(6) }}
	box.routes = h
	return h
}

// signInRoute is a route directory as the clerk makes it.
func signInRoute(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	route := filepath.Join(dir, "signin-0011223344556677")
	if err := os.Mkdir(route, 0o700); err != nil {
		t.Fatal(err)
	}
	return route
}

func signInWait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The machine is a private provider worker from the plan's image, admitted
// as accepted work with 1024 MB, whose only mount out is the route; it runs
// the declared sign-in argv, and signinread returns what it printed and
// when it exits. Other provider workers keep their own routes.
func TestSignInWorkerRunsTheCLIOnTheGuestsRoute(t *testing.T) {
	box := newSignInBox(func(string) string { return "Enter this one-time code ABCD-12345\n" })
	fall := &fallRoutes{}
	h := newSignInHost(box, fall)
	route := signInRoute(t)
	if err := h.Start(context.Background(), "signin-0011223344556677", route); err != nil {
		t.Fatal(err)
	}
	id := <-box.created
	if !strings.HasPrefix(id, vm.ProviderPrefix) {
		t.Fatalf("machine %q is not a provider worker", id)
	}
	want := vm.Spec{Image: "codex", Class: admission.Accepted, MemMB: 1024, Label: vm.Private, Argv: []string{"/bin/sleep", "infinity"}}
	box.mu.Lock()
	spec, mount, argv := box.specs[id], box.mounts[id], box.argv[id]
	box.mu.Unlock()
	if !slices.Equal(spec.Argv, want.Argv) || spec.Image != want.Image || spec.Class != want.Class || spec.MemMB != want.MemMB || spec.Label != want.Label {
		t.Fatalf("spec %+v", spec)
	}
	if mount != route {
		t.Fatalf("mount %q, want the route %q", mount, route)
	}
	tail := []string{"env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/var/lib/agentos-codex", "CODEX_HOME=/var/lib/agentos-codex", "GIT_DIR=/dev/null",
		"/usr/local/bin/agentos-codex-forwarder", "-listen", "127.0.0.1:18432", "-socket", "/run/agentos/route.sock", "--",
		"codex", "login", "--device-auth", "--experimental_issuer", "http://127.0.0.1:18432"}
	if len(argv) < len(tail) || !slices.Equal(argv[len(argv)-len(tail):], tail) {
		t.Fatalf("argv %q", argv)
	}
	signInWait(t, "the CLI's output", func() bool {
		r, err := h.Read(context.Background(), "signin-0011223344556677")
		return err == nil && r.Printed != "" && !r.Exited
	})
	box.mu.Lock()
	box.exited[id] = true
	box.mu.Unlock()
	if r, err := h.Read(context.Background(), "signin-0011223344556677"); err != nil || !r.Exited || r.Printed != "Enter this one-time code ABCD-12345\n" {
		t.Fatalf("after exit: %+v %v", r, err)
	}
	// A provider worker that is not a sign-in keeps the fallback's route,
	// and a sign-in ID with no sign-in gets none.
	if dir, err := h.Open("pw-run-1"); err != nil || dir != "/run/vault/pw-run-1" {
		t.Fatalf("other provider worker: %q %v", dir, err)
	}
	h.Close("pw-run-1")
	if _, err := h.Open(signInPrefix + "ffff"); err == nil {
		t.Fatal("a sign-in ID with no sign-in was given a route")
	}
	if len(fall.opened) != 1 || len(fall.closed) != 1 {
		t.Fatalf("fallback saw %v %v", fall.opened, fall.closed)
	}
	h.Stop("signin-0011223344556677")
	if len(fall.closed) != 1 {
		t.Fatalf("a sign-in's close reached the fallback: %v", fall.closed)
	}
}

// Another uid's call is refused before anything starts: the socket admits
// only -plan-uid, and -plan-uid is the clerk's own.
func TestSignInHostAdmitsOnlyTheClerk(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(box, nil)
	h.UID = os.Getuid() + 1
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	route := signInRoute(t)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"op": "signinstart", "args": signInArgs{Guest: "signin-0011223344556677", Route: route}})
	conn.Write(append(b, '\n'))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	answer, _ := io.ReadAll(conn)
	conn.Close()
	if strings.Contains(string(answer), `"ok":true`) || box.count() != 0 {
		t.Fatalf("another uid's call was answered %q, %d machines", answer, box.count())
	}
	me := os.Getuid()
	for _, c := range []struct {
		sock string
		uid  int
		ok   bool
	}{
		{"", -1, true},
		{"/run/agentos-signin/signin.sock", 0, me != 0},
		{"/run/agentos-signin/signin.sock", -1, false},
		{"", 0, false},
		{"/run/agentos-signin/signin.sock", me, false},
		{"/run/agentos-signin/signin.sock", 901, false},
		{"/run/agentos/signin.sock", 0, false},
		{"signin.sock", 0, false},
	} {
		if _, err := signInFlags(c.sock, "/run/agentos", c.uid, 901); (err == nil) != c.ok {
			t.Errorf("signInFlags(%q, %d): %v", c.sock, c.uid, err)
		}
	}
}

// A route that is not a directory, is owned by another uid, may be written
// by group or other, has a link on the way, or is relative starts nothing;
// nor does a guest name that is not one directory.
func TestSignInRouteMustBeTheClerks(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(box, nil)
	base, _ := filepath.EvalSymlinks(t.TempDir())
	file := filepath.Join(base, "file")
	os.WriteFile(file, nil, 0o600)
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o770)
	link := filepath.Join(base, "link")
	os.Symlink(signInRoute(t), link)
	good := signInRoute(t)
	cases := map[string]struct{ guest, route string }{
		"not a directory":  {"signin-1", file},
		"group-writable":   {"signin-1", open},
		"a link":           {"signin-1", link},
		"relative":         {"signin-1", "route"},
		"unclean":          {"signin-1", good + "/../" + filepath.Base(good)},
		"missing":          {"signin-1", filepath.Join(base, "none")},
		"guest with slash": {"signin/1", good},
		"guest upper":      {"Signin-1", good},
	}
	for name, c := range cases {
		if err := h.Start(context.Background(), c.guest, c.route); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	h.UID = os.Getuid() + 1
	if err := h.Start(context.Background(), "signin-1", good); !errors.Is(err, errSignInRoute) {
		t.Errorf("another uid's route: %v", err)
	}
	if box.count() != 0 {
		t.Fatalf("%d machines started", box.count())
	}
	// The route is checked again as the machine starts.
	h.UID = os.Getuid()
	h.mu.Lock()
	h.routes = map[string]string{signInPrefix + "x": open}
	h.mu.Unlock()
	if _, err := h.Open(signInPrefix + "x"); err == nil {
		t.Fatal("a route that changed after signinstart was mounted")
	}
}

// signinstop, the caller's end (it stops reading for the lease) and
// shutdown each destroy the machine; a second start for a running guest is
// refused, and a guest is free again once its machine is gone.
func TestSignInStopDestroysTheMachine(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(box, nil)
	ctx := context.Background()

	route := signInRoute(t)
	if err := h.Start(ctx, "signin-a", route); err != nil {
		t.Fatal(err)
	}
	a := <-box.created
	if err := h.Start(ctx, "signin-a", route); !errors.Is(err, errSignInRunning) {
		t.Fatalf("second start: %v", err)
	}
	h.Stop("signin-a")
	if !box.gone(a) {
		t.Fatal("stop left the machine")
	}
	if _, err := h.Read(ctx, "signin-a"); !errors.Is(err, errSignInNone) {
		t.Fatalf("read after stop: %v", err)
	}
	h.Stop("signin-a") // idempotent

	h.Lease = 40 * time.Millisecond
	if err := h.Start(ctx, "signin-a", route); err != nil {
		t.Fatalf("start after stop: %v", err)
	}
	b := <-box.created
	for range 5 {
		time.Sleep(10 * time.Millisecond)
		h.Read(ctx, "signin-a") // a caller that reads keeps it
	}
	if box.gone(b) {
		t.Fatal("a read sign-in was destroyed")
	}
	signInWait(t, "the lease to end it", func() bool { return box.gone(b) })

	h.Lease = 0
	if err := h.Start(ctx, "signin-b", route); err != nil {
		t.Fatal(err)
	}
	c := <-box.created
	h.Shutdown()
	if !box.gone(c) {
		t.Fatal("shutdown left the machine")
	}
	if err := h.Start(ctx, "signin-c", route); !errors.Is(err, errSignInClosed) {
		t.Fatalf("start after shutdown: %v", err)
	}
	box.mu.Lock()
	box.createErr = errors.New("no room")
	box.mu.Unlock()
	h.closed = false
	if err := h.Start(ctx, "signin-d", route); !errors.Is(err, errSignInFailed) {
		t.Fatalf("a failed create: %v", err)
	}
	if h.byGuest["signin-d"] != nil || len(h.routes) != 0 {
		t.Fatal("a failed start kept its guest or route")
	}
}

// oneAddr resolves every name to one address.
type oneAddr netip.Addr

func (a oneAddr) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(a)}, nil
}

// codexLogin is the plan login clerk on a fake provider that hands out the
// user code ABCD-12345 (clerk/run planLoginAt).
func codexLogin(t *testing.T) *plan.Login {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/accounts/deviceauth/usercode" {
			io.WriteString(w, `{"device_auth_id":"dev-1","user_code":"ABCD-12345","interval":"5"}`)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	d := plan.Codex(netguard.New(netguard.Config{Resolver: oneAddr(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}))
	host := "example.com:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	for i := range d.Endpoints {
		d.Endpoints[i].Host = host
	}
	d.Mode = plan.Permitted
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.New(d, plan.NewStore(s, nil), roots)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// run.SignInSock against this handler: PlanHost.Begin starts the CLI
// through it, the CLI asks its endpoint in the route for its user code as
// Codex does, and Begin shows the code; Stop destroys the machine and
// closes the endpoint.
func TestSignInSockSpeaksTheHostsWire(t *testing.T) {
	login := codexLogin(t)
	box := newSignInBox(func(route string) string {
		c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(route, run.SignInRouteSocket))
		}}}
		resp, err := c.Post("http://127.0.0.1:18432/api/accounts/deviceauth/usercode", "application/json", bytes.NewReader([]byte(`{"client_id":"app_x"}`)))
		if err != nil {
			return "error " + err.Error()
		}
		var u struct {
			UserCode string `json:"user_code"`
		}
		json.NewDecoder(resp.Body).Decode(&u)
		resp.Body.Close()
		return "Welcome to Codex\n\x1b[94mhttp://127.0.0.1:18432/codex/device\x1b[0m\nEnter this one-time code \x1b[94m" + u.UserCode + "\x1b[0m\n"
	})
	h := newSignInHost(box, nil)
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	ws := run.SignInSock{Host: proc.Conn{Socket: sock, UID: os.Getuid()}, Dir: dir, Login: login, SandboxUID: os.Getuid()}
	ph := &run.PlanHost{Login: login, Prompt: run.CodexSignIn(), Workers: ws,
		Times: run.SignInTimes{Poll: 5 * time.Millisecond, Link: 3 * time.Second, Wall: 200 * time.Millisecond}}
	b := ph.Begin(context.Background())
	if b != (run.PlanBegun{Page: "https://auth.openai.com/codex/device", Code: "ABCD-12345", From: "OpenAI"}) {
		t.Fatalf("begun: %+v", b)
	}
	id := <-box.created
	// The owner does not approve within Wall: the clerk stops the sign-in,
	// agentosd destroys the machine and the endpoint closes.
	signInWait(t, "the machine to be destroyed", func() bool { return box.gone(id) })
	signInWait(t, "the route to be removed", func() bool {
		ents, _ := os.ReadDir(dir)
		return len(ents) == 0
	})
	if st := ph.State(); st.Last != run.DSignInTimedOut {
		t.Fatalf("state: %+v", st)
	}
	if _, err := h.Read(context.Background(), "x"); !errors.Is(err, errSignInNone) {
		t.Fatal(err)
	}
	// A refused start reaches the clerk as an error and leaves no route.
	box.mu.Lock()
	box.createErr = errors.New("no room")
	box.mu.Unlock()
	if b := ph.Begin(context.Background()); b.Detail != run.DSignInFailed {
		t.Fatalf("refused start: %+v", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("a refused start left %v", ents)
	}
}
