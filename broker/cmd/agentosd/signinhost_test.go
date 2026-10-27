package main

// REQ: PLN-5, CLK-7, CLK-1, PLN-6

import (
	"bufio"
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
	"syscall"
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
	stuck     map[string]bool // machines whose destroy fails
	created   chan string     // each create, once it returns
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
	if b.stuck[id] {
		b.mu.Unlock()
		return errors.New("the runtime did not stop")
	}
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

func (b *signInBox) Machines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for id := range b.mounts {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
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

func newSignInHost(t *testing.T, box *signInBox, fall vm.Services) *signInHost {
	t.Helper()
	h := &signInHost{M: box, Plan: signInPlans["codex"], UID: os.Getuid(), GID: os.Getgid(), Routes: signInRoutes(t), Fall: fall, NewID: func() string { return randHex(6) }}
	box.routes = h
	return h
}

// signInRoutes is -signin-routes, prepared as agentosd prepares it.
func signInRoutes(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	routes := filepath.Join(dir, "routes")
	if err := prepareSignInRoutes(routes); err != nil {
		t.Fatal(err)
	}
	return routes
}

// signInRoute makes guest's route as signinroute does.
func signInRoute(t *testing.T, h *signInHost, guest string) string {
	t.Helper()
	route, err := h.Route(guest)
	if err != nil {
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
	h := newSignInHost(t, box, fall)
	route := signInRoute(t, h, "signin-0011223344556677")
	if fi, err := os.Lstat(route); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 || filepath.Dir(route) != h.Routes {
		t.Fatalf("route %q: %v %v", route, fi, err)
	}
	if err := h.Start(context.Background(), "signin-0011223344556677"); err != nil {
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
	if _, err := os.Lstat(route); !os.IsNotExist(err) {
		t.Fatalf("stop left the route: %v", err)
	}
}

// Another uid's call is refused before anything starts: the socket admits
// only -plan-uid, and -plan-uid is the clerk's own.
func TestSignInHostAdmitsOnlyTheClerk(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	signInRoute(t, h, "signin-0011223344556677")
	h.UID = os.Getuid() + 1
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, op := range []string{"signinroute", "signinstart"} {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{"op": op, "args": signInArgs{Guest: "signin-0011223344556677"}})
		conn.Write(append(b, '\n'))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		answer, _ := io.ReadAll(conn)
		conn.Close()
		if strings.Contains(string(answer), `"ok":true`) || box.count() != 0 {
			t.Fatalf("another uid's %s was answered %q, %d machines", op, answer, box.count())
		}
	}
	me := os.Getuid()
	const routes = "/run/agentos-signin-routes"
	for _, c := range []struct {
		sock, routes string
		uid          int
		ok           bool
	}{
		{"", "", -1, true},
		{"/run/agentos-signin/signin.sock", routes, 0, me != 0},
		{"/run/agentos-signin/signin.sock", routes, -1, false},
		{"", "", 0, false},
		{"/run/agentos-signin/signin.sock", routes, me, false},
		{"/run/agentos-signin/signin.sock", routes, 901, false},
		{"/run/agentos/signin.sock", routes, 0, false},
		{"signin.sock", routes, 0, false},
		{"/run/agentos-signin/signin.sock", "", 0, false},
		{"", routes, -1, false},
		{"/run/agentos-signin/signin.sock", "/run/agentos-signin", 0, false},
		{"/run/agentos-signin/signin.sock", "/run/agentos", 0, false},
		{"/run/agentos-signin/signin.sock", "routes", 0, false},
		{"/run/agentos-signin/signin.sock", routes + "/", 0, false},
	} {
		if _, err := signInFlags(c.sock, c.routes, "/run/agentos", c.uid, 901); (err == nil) != c.ok {
			t.Errorf("signInFlags(%q, %q, %d): %v", c.sock, c.routes, c.uid, err)
		}
	}
}

// agentosd makes every route itself, in -signin-routes, which must be its
// own and writable by no other uid; signinstart mounts only the route
// agentosd made for the guest, whatever the caller names, and a route the
// clerk changed after signinroute (not a directory, group- or
// world-writable, a link, another uid's) starts nothing; nor does a guest
// name that is not one directory (#3248 Security 1).
func TestSignInRouteMustBeTheClerks(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	ctx := context.Background()

	// -signin-routes: made 0711, emptied of a last run's routes, and
	// refused when another uid may write it or a link is on the way.
	if fi, err := os.Lstat(h.Routes); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("routes: %v %v", fi, err)
	}
	signInRoute(t, h, "signin-stale")
	if err := prepareSignInRoutes(h.Routes); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(h.Routes); len(ents) != 0 {
		t.Fatalf("a last run's routes stayed: %v", ents)
	}
	base := filepath.Dir(h.Routes)
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o733)
	sub := filepath.Join(open, "routes")
	os.Mkdir(sub, 0o711)
	link := filepath.Join(base, "link")
	os.Symlink(h.Routes, link)
	// Sticky does not save the routes directory itself: the clerk owns
	// its route, so it could still rename it there.
	sticky := filepath.Join(base, "sticky")
	os.Mkdir(sticky, 0o711)
	os.Chmod(sticky, 0o777|os.ModeSticky)
	for name, dir := range map[string]string{"group-writable": open, "under a writable parent": sub, "a link": link, "relative": "routes", "unclean": h.Routes + "/", "sticky and world-writable": sticky} {
		if err := prepareSignInRoutes(dir); err == nil {
			t.Errorf("-signin-routes %s: prepared", name)
		}
	}
	// One left 0700 is made 0711, so the clerk can reach its route.
	os.Chmod(h.Routes, 0o700)
	if err := prepareSignInRoutes(h.Routes); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(h.Routes); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("routes left 0700: %v %v", fi, err)
	}
	// As root, each route is chowned to -plan-uid, not left root's.
	if os.Geteuid() == 0 {
		h.UID, h.GID = 65534, 65534
		fi, err := os.Lstat(signInRoute(t, h, "signin-owner"))
		if st, ok := fi.Sys().(*syscall.Stat_t); err != nil || !ok || st.Uid != 65534 || st.Gid != 65534 {
			t.Fatalf("route owner: %+v %v", fi.Sys(), err)
		}
		h.Stop("signin-owner")
		h.UID, h.GID = os.Getuid(), os.Getgid()
	}

	// signinstart mounts only agentosd's route for the guest: one the
	// caller names, or none made, starts nothing.
	elsewhere, _ := filepath.EvalSymlinks(t.TempDir())
	if err := h.Start(ctx, "signin-1"); !errors.Is(err, errSignInRoute) {
		t.Fatalf("start with no route made: %v", err)
	}
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	call := func(op string, args any) string {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		b, _ := json.Marshal(map[string]any{"op": op, "args": args})
		conn.Write(append(b, '\n'))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		answer, _ := bufio.NewReader(conn).ReadString('\n')
		return answer
	}
	if a := call("signinroute", signInArgs{Guest: "signin-1"}); !strings.Contains(a, filepath.Join(h.Routes, "signin-1")) {
		t.Fatalf("signinroute: %s", a)
	}
	if a := call("signinstart", map[string]string{"guest": "signin-1", "route": elsewhere}); !strings.Contains(a, `"ok":true`) {
		t.Fatalf("signinstart: %s", a)
	}
	id := <-box.created
	box.mu.Lock()
	mount := box.mounts[id]
	box.mu.Unlock()
	if mount != filepath.Join(h.Routes, "signin-1") {
		t.Fatalf("mounted %q, not agentosd's route", mount)
	}
	if a := call("signinroute", signInArgs{Guest: "signin-1"}); strings.Contains(a, `"ok":true`) {
		t.Fatalf("a running guest's route was made again: %s", a)
	}
	call("signinstop", signInArgs{Guest: "signin-1"})

	// A route the clerk changed after signinroute starts nothing.
	tamper := map[string]func(route string){
		"not a directory": func(r string) { os.Remove(r); os.WriteFile(r, nil, 0o600) },
		"group-writable":  func(r string) { os.Chmod(r, 0o770) },
		"a link":          func(r string) { os.Remove(r); os.Symlink(elsewhere, r) },
		"missing":         func(r string) { os.Remove(r) },
	}
	for name, f := range tamper {
		f(signInRoute(t, h, "signin-2"))
		if err := h.Start(ctx, "signin-2"); err == nil {
			t.Errorf("%s: started", name)
		}
		h.Stop("signin-2")
		if _, err := os.Lstat(filepath.Join(h.Routes, "signin-2")); !os.IsNotExist(err) {
			t.Errorf("%s: stop left the route: %v", name, err)
		}
	}
	if _, err := os.Lstat(elsewhere); err != nil {
		t.Fatalf("removing a route followed its link: %v", err)
	}
	for _, g := range []string{"signin/1", "Signin-1", "..", ""} {
		if _, err := h.Route(g); !errors.Is(err, errSignInGuest) {
			t.Errorf("route for %q: %v", g, err)
		}
		if err := h.Start(ctx, g); err == nil {
			t.Errorf("guest %q started", g)
		}
	}
	signInRoute(t, h, "signin-3")
	h.UID = os.Getuid() + 1
	if err := h.Start(ctx, "signin-3"); !errors.Is(err, errSignInRoute) {
		t.Errorf("another uid's route: %v", err)
	}
	if box.count() != 1 {
		t.Fatalf("%d machines started", box.count())
	}
	// The route is checked again as the machine starts.
	h.UID = os.Getuid()
	os.Chmod(filepath.Join(h.Routes, "signin-3"), 0o770)
	h.mu.Lock()
	h.routes = map[string]string{signInPrefix + "x": filepath.Join(h.Routes, "signin-3")}
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
	h := newSignInHost(t, box, nil)
	ctx := context.Background()

	signInRoute(t, h, "signin-a")
	if err := h.Start(ctx, "signin-a"); err != nil {
		t.Fatal(err)
	}
	a := <-box.created
	if err := h.Start(ctx, "signin-a"); !errors.Is(err, errSignInRunning) {
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
	signInRoute(t, h, "signin-a")
	if err := h.Start(ctx, "signin-a"); err != nil {
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
	signInRoute(t, h, "signin-b")
	signInRoute(t, h, "signin-c")
	if err := h.Start(ctx, "signin-b"); err != nil {
		t.Fatal(err)
	}
	c := <-box.created
	h.Shutdown()
	if !box.gone(c) {
		t.Fatal("shutdown left the machine")
	}
	if err := h.Start(ctx, "signin-c"); !errors.Is(err, errSignInClosed) {
		t.Fatalf("start after shutdown: %v", err)
	}
	if _, err := h.Route("signin-e"); !errors.Is(err, errSignInClosed) {
		t.Fatalf("route after shutdown: %v", err)
	}
	box.mu.Lock()
	box.createErr = errors.New("no room")
	box.mu.Unlock()
	h.closed = false
	signInRoute(t, h, "signin-d")
	if err := h.Start(ctx, "signin-d"); !errors.Is(err, errSignInFailed) {
		t.Fatalf("a failed create: %v", err)
	}
	if h.byGuest["signin-d"] != nil || len(h.routes) != 0 {
		t.Fatal("a failed start kept its guest or route")
	}
	// Every stopped guest's route is gone; signin-c never started.
	if ents, _ := os.ReadDir(h.Routes); len(ents) != 1 || ents[0].Name() != "signin-c" {
		t.Fatalf("routes left: %v", ents)
	}
}

// A crash during a sign-in or a plan run leaves its provider worker
// reloaded Stopped with its placeholder seed; the sweep at start destroys
// every provider worker and no other machine, and one that will not go
// stops none of the rest (#3249, #3308).
func TestStartSweepDestroysLeftoverProviderWorkers(t *testing.T) {
	// REQ: PLN-6
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	left := []string{signInPrefix + "aaaaaa", vm.ProviderPrefix + "bbbbbb", signInPrefix + "cccccc", vm.ProviderPrefix + "dddddd"}
	kept := []string{vm.WorkerPrefix + "0a1b2c3d-pw-x", "agent-1", "signin-agent", "xpw-a1b2c3"}
	box.mu.Lock()
	for _, id := range append(slices.Clone(left), kept...) {
		box.mounts[id] = ""
	}
	box.stuck = map[string]bool{left[1]: true}
	box.mu.Unlock()

	h.Sweep()
	for _, id := range []string{left[0], left[2], left[3]} {
		if !box.gone(id) {
			t.Fatalf("the sweep left %s", id)
		}
	}
	for _, id := range append([]string{left[1]}, kept...) {
		if box.gone(id) {
			t.Fatalf("the sweep destroyed %s", id)
		}
	}
	box.mu.Lock()
	delete(box.stuck, left[1])
	box.mu.Unlock()
	h.Sweep() // the next start takes the one that would not go
	if !box.gone(left[1]) {
		t.Fatal("a second sweep left the stuck machine")
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
	h := newSignInHost(t, box, nil)
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	dir := h.Routes
	ws := run.SignInSock{Host: proc.Conn{Socket: sock, UID: os.Getuid()}, Login: login, SandboxUID: os.Getuid()}
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
	// agentosd removes the route at signinstop, before the clerk records
	// the timeout.
	signInWait(t, "the clerk to record the timeout", func() bool { return ph.State().Last == run.DSignInTimedOut })
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

// The provider-worker sweep is pinned in main.go: it runs once the
// manager is open and given to the host, before -signin-sock is served
// and before the provider runner can start a plan run, and setup's
// sign-in machines are closed before that manager opens, so no worker
// it destroys has a live owner (#3308).
func TestProviderSweepRunsBeforeAnyProviderWorker(t *testing.T) {
	// REQ: PLN-6
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	sweep := strings.Index(s, "\t\t\tsignIns.Sweep()\n")
	if sweep < 0 || strings.Count(s, "signIns.Sweep()") != 1 {
		t.Fatal("main.go does not call signIns.Sweep() exactly once")
	}
	for _, before := range []string{"\tsignInHost.Close(cctx)\n", "\tm, err := vm.Open(ctx, vmc)\n", "\tsignIns.M = m\n"} {
		if i := strings.Index(s, before); i < 0 || i > sweep {
			t.Fatalf("%q at %d, not before the sweep at %d", before, i, sweep)
		}
	}
	for _, later := range []string{"serveSignIns(", "providerRunner(m,"} {
		if i := strings.Index(s, later); i < 0 || i < sweep {
			t.Fatalf("%q at %d, not after the sweep at %d", later, i, sweep)
		}
	}
}
