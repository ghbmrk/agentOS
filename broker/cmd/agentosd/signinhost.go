package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vm"
)

// agentosd hosts the model clerk's plan sign-in workers
// (MIG-4-untrusted-exit-b1, #2780(b), PLN-5, CLK-7): clerk/run's PlanHost
// runs the plan's sign-in CLI through run.SignInWorkers, and the box's
// only sandbox host is this process's vm.Manager. The clerk's process
// calls four ops on -signin-sock, which admits only -plan-uid:
// signinroute {guest}, signinstart {guest}, signinread {guest} and
// signinstop {guest}. signinroute makes the guest's route, the directory
// the clerk serves that guest's plan endpoint in (run.ListenPlan), and
// answers its path; it is the machine's one mount out, so the CLI's only
// way out is its own endpoint. agentosd makes each route itself, in
// -signin-routes, a directory the clerk cannot write, so the clerk owns
// the route but cannot rename or replace it between agentosd's check and
// the runtime's mount (#3248 Security 1). The socket is a sockets.Server endpoint, as
// localui.sock is: {"op","args"} lines, {"ok","result"} or {"error"}
// answers, which clerk/run SignInSock reads with kernel/proc's Conn.
// TestSignInSockSpeaksTheHostsWire serves this handler to SignInSock.

// signInPlan is a plan's sign-in guest: its image, what the machine runs
// until it is destroyed, and the sign-in CLI, run in Cwd with exactly Env.
type signInPlan struct {
	Image string
	Idle  []string
	Cwd   string
	Env   []string
	Argv  []string
}

// signInPlans are the plans whose sign-in agentosd hosts. Codex is CLI
// 0.162.1's device-code sign-in as measured (#809), its issuer the
// forwarder in front of the guest's endpoint, /run/agentos/route.sock
// (vm.ServicesMount); copied from provagent.Builtins, which b3 deletes.
var signInPlans = map[string]signInPlan{
	"codex": {
		Image: "codex",
		Idle:  []string{"/bin/sleep", "infinity"},
		Cwd:   "/var/lib/agentos-work",
		Env:   []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/var/lib/agentos-codex", "CODEX_HOME=/var/lib/agentos-codex", "GIT_DIR=/dev/null"},
		Argv: []string{"/usr/local/bin/agentos-codex-forwarder", "-listen", "127.0.0.1:18432", "-socket", vm.ServicesMount + "/" + signInRouteSocket, "--",
			"codex", "login", "--device-auth", "--experimental_issuer", "http://127.0.0.1:18432"},
	},
}

// signInRouteSocket is the endpoint's socket in the route directory: the
// clerk listens on route/route.sock (run.ListenPlan).
const signInRouteSocket = "route.sock"

// The sign-in machine's budget: a provider worker, private because the
// CLI writes the login's placeholders, admitted as accepted work.
const (
	signInMemMB = 1024
	signInClass = admission.Accepted
)

// The sign-in CLI's output and exit status, in the machine's workspace.
const (
	signInOut    = "/.agentos-signin"
	signInStatus = "/.agentos-signin-status"
	// signInPrinted bounds what signinread returns (clerk/run maxPrinted).
	signInPrinted = 64 << 10
)

// signInMachines is the vm.Manager calls a sign-in uses.
type signInMachines interface {
	CreateProviderWorker(ctx context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error)
	Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error)
	Destroy(ctx context.Context, id string) error
	Machines() []string
}

// The host's refusals, sockets.Codes so the clerk gets their text.
const (
	errSignInGuest   sockets.Code = "signin: a guest is lowercase letters, digits and dashes, at most 64"
	errSignInRoute   sockets.Code = "signin: the route is not a directory of the plan clerk's alone"
	errSignInNoRoute sockets.Code = "signin: agentosd could not make the route"
	errSignInRunning sockets.Code = "signin: a sign-in already runs for this guest"
	errSignInNone    sockets.Code = "signin: no sign-in runs for this guest"
	errSignInClosed  sockets.Code = "signin: agentosd is shutting down"
	errSignInStopped sockets.Code = "signin: the sign-in was stopped as it started"
	errSignInFailed  sockets.Code = "signin: the sign-in machine did not start"
)

var signInGuestName = regexp.MustCompile(`\A[a-z0-9-]{1,64}\z`)

// signInHost runs the clerk's sign-ins. It is also the provider workers'
// route source (vm.Config.ProviderRoutes): a sign-in machine is given its
// route, every other provider worker goes to Fall, as before.
type signInHost struct {
	M    signInMachines
	Plan signInPlan
	UID  int // -plan-uid: the only owner of a route
	GID  int // -plan-uid's primary group, a route's group
	// Routes is -signin-routes, where agentosd makes each guest's route
	// (prepareSignInRoutes): its own, and no other uid may write it.
	Routes string
	Fall   vm.Services // the other provider workers' routes; nil, none
	// Lease ends a sign-in its caller stopped reading (a clerk that ended
	// or lost it); Wall ends any sign-in. Zero: a minute and 20 minutes,
	// past the clerk's own 15 (run.SignInTimes).
	Lease, Wall time.Duration
	NewID       func() string // after signInPrefix

	mu      sync.Mutex
	closed  bool
	byGuest map[string]*signInRun
	routes  map[string]string // machine ID -> route
}

type signInRun struct {
	id, route string
	read      time.Time // the caller's last start or read
	end       chan struct{}
	once      sync.Once
}

// checkRoute is the route rule: an absolute path with no link in it,
// naming a directory owned by uid that no group or other may write.
func checkRoute(route string, uid int) error {
	if uid < 0 {
		return errSignInRoute
	}
	if !filepath.IsAbs(route) || filepath.Clean(route) != route {
		return errSignInRoute
	}
	if real, err := filepath.EvalSymlinks(route); err != nil || real != route {
		return errSignInRoute
	}
	fi, err := os.Lstat(route)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return errSignInRoute
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid {
		return errSignInRoute
	}
	return nil
}

// prepareSignInRoutes makes dir, -signin-routes, agentosd's own, sets it
// 0711 (so the clerk can reach its route but not list or change the
// rest), and empties it, as no sign-in runs before agentosd serves them. It and every
// directory above it must be owned by root or this process and writable
// by no other uid, sticky directories aside, so no other uid can rename a
// route agentosd made there.
func prepareSignInRoutes(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("-signin-routes must be a clean absolute path")
	}
	if err := os.Mkdir(dir, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if real, err := filepath.EvalSymlinks(dir); err != nil || real != dir {
		return fmt.Errorf("-signin-routes %s: has a link on the way", dir)
	}
	me := os.Geteuid()
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !fi.IsDir() || (st.Uid != 0 && int(st.Uid) != me) {
			return fmt.Errorf("-signin-routes: %s is not root's or agentosd's", d)
		}
		open := fi.Mode().Perm()&0o022 != 0
		if d == dir && open || open && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("-signin-routes: another uid may write %s", d)
		}
		if d == "/" {
			break
		}
	}
	// A directory left 0700 would keep the clerk from its route.
	if err := os.Chmod(dir, 0o711); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Route makes guest's route afresh, a directory in h.Routes owned by
// h.UID and 0700, and returns its path; the clerk serves guest's endpoint
// in it before signinstart. A guest whose sign-in runs keeps its route.
func (h *signInHost) Route(guest string) (string, error) {
	if !signInGuestName.MatchString(guest) {
		return "", errSignInGuest
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return "", errSignInClosed
	case h.byGuest[guest] != nil:
		return "", errSignInRunning
	case h.Routes == "":
		return "", errSignInNoRoute
	}
	route := filepath.Join(h.Routes, guest)
	if err := os.RemoveAll(route); err != nil {
		return "", errSignInNoRoute
	}
	if err := os.Mkdir(route, 0o700); err != nil {
		return "", errSignInNoRoute
	}
	if err := os.Lchown(route, h.UID, h.GID); err != nil {
		os.Remove(route)
		return "", errSignInNoRoute
	}
	return route, nil
}

// removeRoute removes guest's route, whatever the clerk left in it.
// RemoveAll follows no link, so nothing outside the route goes with it.
func (h *signInHost) removeRoute(route string) {
	if route == "" || filepath.Dir(route) != h.Routes {
		return
	}
	if err := os.RemoveAll(route); err != nil {
		log.Printf("signin: remove %s: %v", route, err)
	}
}

// signInPrefix starts a sign-in machine's ID: a provider worker's
// (vm.ProviderPrefix) that never gets another route.
const signInPrefix = vm.ProviderPrefix + "signin-"

// Open is a provider worker's route: a sign-in machine's own route,
// checked again as it starts, or the fallback's.
func (h *signInHost) Open(id string) (string, error) {
	if strings.HasPrefix(id, signInPrefix) {
		h.mu.Lock()
		route, ok := h.routes[id]
		h.mu.Unlock()
		if !ok {
			return "", errSignInNone
		}
		if err := checkRoute(route, h.UID); err != nil {
			return "", err
		}
		return route, nil
	}
	if h.Fall == nil {
		return "", nil
	}
	return h.Fall.Open(id)
}

func (h *signInHost) Close(id string) {
	switch {
	case strings.HasPrefix(id, signInPrefix):
		h.mu.Lock()
		delete(h.routes, id)
		h.mu.Unlock()
	case h.Fall != nil:
		h.Fall.Close(id)
	}
}

// Start starts guest's sign-in CLI in a fresh machine whose only mount out
// is the route signinroute made for it. One sign-in runs per guest.
func (h *signInHost) Start(ctx context.Context, guest string) error {
	if !signInGuestName.MatchString(guest) {
		return errSignInGuest
	}
	if h.Routes == "" {
		return errSignInRoute
	}
	route := filepath.Join(h.Routes, guest)
	if err := checkRoute(route, h.UID); err != nil {
		return err
	}
	r := &signInRun{id: signInPrefix + h.NewID(), route: route, read: time.Now(), end: make(chan struct{})}
	h.mu.Lock()
	switch {
	case h.closed:
		h.mu.Unlock()
		return errSignInClosed
	case h.byGuest[guest] != nil:
		h.mu.Unlock()
		return errSignInRunning
	}
	if h.byGuest == nil {
		h.byGuest, h.routes = map[string]*signInRun{}, map[string]string{}
	}
	h.byGuest[guest] = r
	h.routes[r.id] = route
	h.mu.Unlock()

	p := h.Plan
	spec := vm.Spec{Image: p.Image, Class: signInClass, MemMB: signInMemMB, Label: vm.Private, Argv: p.Idle}
	_, err := h.M.CreateProviderWorker(ctx, r.id, spec, nil)
	if err == nil {
		var res vm.ExecResult
		res, err = h.M.Exec(ctx, r.id, signInCommand(p), 30*time.Second)
		if err == nil && (res.ExitCode != 0 || res.TimedOut) {
			err = fmt.Errorf("exit status %d, timed out %t", res.ExitCode, res.TimedOut)
		}
	}
	select {
	case <-r.end:
		// Stopped or shut down while it was created: its destroy may
		// have come first.
		h.destroy(guest, r.id)
		h.mu.Lock()
		closed := h.closed
		h.mu.Unlock()
		if closed {
			return errSignInClosed
		}
		return errSignInStopped
	default:
	}
	if err != nil {
		// Only the status: the output is the guest's, never logged.
		log.Printf("signin: %s: start %s: %v", guest, r.id, err)
		h.stop(guest, r)
		return errSignInFailed
	}
	lease, wall := h.Lease, h.Wall
	if lease <= 0 {
		lease = time.Minute
	}
	if wall <= 0 {
		wall = 20 * time.Minute
	}
	go h.watch(guest, r, lease, wall)
	return nil
}

// signInCommand starts the CLI in the background and returns, as the
// worker's Exec runs one command at a time and the CLI waits for the
// owner; its stdout and stderr go to one file and its exit status to
// another, and env -i gives it exactly p.Env.
func signInCommand(p signInPlan) vm.Command {
	argv := []string{
		"sh", "-c", `cd "$1" || exit 125; out=$2; st=$3; shift 3; ("$@" >"$out" 2>&1 </dev/null; echo $? >"$st") >/dev/null 2>&1 </dev/null & exit 0`,
		"sh", p.Cwd, p.Cwd + signInOut, p.Cwd + signInStatus, "env", "-i",
	}
	argv = append(append(argv, p.Env...), p.Argv...)
	return vm.Command{Argv: argv, MaxOutput: 4 << 10, As: vm.Private}
}

// signInRead is signinread's answer.
type signInRead struct {
	Printed string `json:"printed"`
	Exited  bool   `json:"exited"`
}

// Read returns what guest's CLI has printed so far, at most signInPrinted
// bytes, and whether it has exited. Each read renews the lease.
func (h *signInHost) Read(ctx context.Context, guest string) (signInRead, error) {
	h.mu.Lock()
	r := h.byGuest[guest]
	if r != nil {
		r.read = time.Now()
	}
	h.mu.Unlock()
	if r == nil {
		return signInRead{}, errSignInNone
	}
	cat := func(path string, max int) (string, bool) {
		res, err := h.M.Exec(ctx, r.id, vm.Command{Argv: []string{"cat", h.Plan.Cwd + path}, MaxOutput: max, As: vm.Private}, 10*time.Second)
		return string(res.Stdout), err == nil && res.ExitCode == 0
	}
	out, _ := cat(signInOut, signInPrinted)
	st, ok := cat(signInStatus, 64)
	return signInRead{Printed: out, Exited: ok && strings.TrimSpace(st) != ""}, nil
}

// Stop destroys guest's sign-in machine and removes its route. A guest
// with none is not an error: the lease or the CLI's end may have come
// first, or signinstart was refused after signinroute.
func (h *signInHost) Stop(guest string) {
	if !signInGuestName.MatchString(guest) {
		return
	}
	h.mu.Lock()
	r := h.byGuest[guest]
	if r == nil && h.Routes != "" {
		h.removeRoute(filepath.Join(h.Routes, guest))
	}
	h.mu.Unlock()
	if r != nil {
		h.stop(guest, r)
	}
}

// stop destroys r once and frees guest for another sign-in.
func (h *signInHost) stop(guest string, r *signInRun) {
	r.once.Do(func() {
		close(r.end)
		h.destroy(guest, r.id)
		h.mu.Lock()
		if h.byGuest[guest] == r {
			delete(h.byGuest, guest)
			h.removeRoute(r.route)
		}
		delete(h.routes, r.id)
		h.mu.Unlock()
	})
}

func (h *signInHost) destroy(guest, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.M.Destroy(ctx, id); err != nil && !errors.Is(err, vm.ErrUnknown) {
		log.Printf("signin: %s: destroy %s: %v", guest, id, err)
	}
}

// watch destroys r once its caller stops reading for lease, or at wall.
func (h *signInHost) watch(guest string, r *signInRun, lease, wall time.Duration) {
	deadline := time.Now().Add(wall)
	tick := time.NewTicker(min(lease/4, time.Second))
	defer tick.Stop()
	for {
		select {
		case <-r.end:
			return
		case now := <-tick.C:
			h.mu.Lock()
			idle := now.Sub(r.read)
			h.mu.Unlock()
			if idle >= lease || !now.Before(deadline) {
				h.stop(guest, r)
				return
			}
		}
	}
}

// Sweep destroys every sign-in machine the machine manager holds, before
// any sign-in is served: a machine left by a crash during a sign-in is
// reloaded Stopped, and nothing else ever destroys it (#3249, CAP-8). Its
// route was emptied with -signin-routes (prepareSignInRoutes), and Open
// gives it none, so it could not start again; only its disk is reclaimed.
// A failed destroy is logged and the rest go on.
func (h *signInHost) Sweep() {
	for _, id := range h.M.Machines() {
		if strings.HasPrefix(id, signInPrefix) {
			h.destroy("sweep", id)
		}
	}
}

// Shutdown destroys every sign-in machine and starts no more.
func (h *signInHost) Shutdown() {
	h.mu.Lock()
	h.closed = true
	runs := make(map[string]*signInRun, len(h.byGuest))
	for g, r := range h.byGuest {
		runs[g] = r
	}
	h.mu.Unlock()
	for g, r := range runs {
		h.stop(g, r)
	}
}

// signInArgs are the four ops' arguments.
type signInArgs struct {
	Guest string `json:"guest"`
}

// signInRouted is signinroute's answer.
type signInRouted struct {
	Route string `json:"route"`
}

// signInFlags checks -signin-sock, -signin-routes and -plan-uid: they go
// together, the socket has a directory of its own (sockets.Server locks
// it, so not -sockets'), the routes' directory is neither, and the plan
// clerk's uid is its own, distinct from the broker's and every other
// peer's. It returns that uid's primary group, which the socket and each
// route are given.
func signInFlags(sock, routes, sockDir string, planUID int, others ...int) (gid int, err error) {
	switch {
	case (sock == "") != (planUID < 0) || (sock == "") != (routes == ""):
		return -1, errors.New("-signin-sock, -signin-routes and -plan-uid go together")
	case sock == "":
		return -1, nil
	case !filepath.IsAbs(sock) || filepath.Dir(sock) == filepath.Clean(sockDir):
		return -1, errors.New("-signin-sock must be an absolute path in a directory of its own, not -sockets'")
	case !filepath.IsAbs(routes) || filepath.Clean(routes) != routes || routes == filepath.Dir(sock) || routes == filepath.Clean(sockDir):
		return -1, errors.New("-signin-routes must be a clean absolute directory of its own, not -signin-sock's or -sockets'")
	}
	for _, uid := range append(others, os.Getuid()) {
		if planUID == uid {
			return -1, errors.New("-plan-uid must name the model clerk's own uid, distinct from the broker's and every other peer's")
		}
	}
	u, err := user.LookupId(strconv.Itoa(planUID))
	if err != nil {
		return -1, fmt.Errorf("-plan-uid %d: %w", planUID, err)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return -1, fmt.Errorf("-plan-uid %d: group %q: %w", planUID, u.Gid, err)
	}
	return gid, nil
}

// serveSignIns serves h's four ops on sock (sockets.Server), admitting
// only h.UID, the socket 0660 to gid. stop closes it and destroys every
// sign-in machine.
func serveSignIns(sock string, gid int, h *signInHost) (stop func(), err error) {
	uid := h.UID
	arg := func(raw json.RawMessage) (signInArgs, error) {
		var a signInArgs
		if json.Unmarshal(raw, &a) != nil {
			return a, sockets.ErrMalformed
		}
		return a, nil
	}
	ops := map[string]sockets.Handler{
		"signinroute": func(_ context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			a, err := arg(raw)
			if err != nil {
				return nil, err
			}
			route, err := h.Route(a.Guest)
			if err != nil {
				return nil, err
			}
			return signInRouted{Route: route}, nil
		},
		"signinstart": func(ctx context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			a, err := arg(raw)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			return struct{}{}, h.Start(ctx, a.Guest)
		},
		"signinread": func(ctx context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			a, err := arg(raw)
			if err != nil {
				return nil, err
			}
			return h.Read(ctx, a.Guest)
		},
		"signinstop": func(_ context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			a, err := arg(raw)
			if err != nil {
				return nil, err
			}
			h.Stop(a.Guest)
			return struct{}{}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &sockets.Server{Dir: filepath.Dir(sock)}
	err = srv.Start(ctx, sockets.Endpoint{
		Name: filepath.Base(sock), Peer: sockets.Peer{Kind: "plan-clerk"}, PeerUID: &uid, PeerGID: &gid,
		MaxConns: 8, IdleTimeout: 30 * time.Second, Ops: ops,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return func() {
		cancel()
		srv.Wait()
		h.Shutdown()
	}, nil
}
