package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Provider worker routes (#1014 part c, A14, CRED-5).
//
// A provider worker is a machine that runs a provider's own agent (Codex)
// on the owner's plan. Its only way out is a route socket this process
// serves: the worker's forwarder relays the CLI's calls to it, and
// egress.NewWorkerRoute swaps placeholders for the real login at the
// provider's declared endpoints and nowhere else.
//
// The broker (agentosd) creates the machine, so it asks this process over
// the provider control socket to open the worker's route before the guest
// starts, and to close it when the machine goes. Each worker gets its own
// directory holding only its route socket; the broker mounts that
// directory, and only that one, into the worker. The directory is the
// worker's identity: the route is built for that worker's name, and
// nothing in a request can change it (egress K28). Before the machine
// starts the broker also fetches the worker's placeholder auth.json over the
// same socket (/seed), so the placeholders it seeds are the ones this
// process resolves.
//
// The owner's sign-in (#1264 c4e2, ONB step 6) runs the provider's CLI in a
// fresh worker whose route the broker opens with /signin instead: that
// route serves the sign-in endpoints only (WorkerRouteConfig.SignIn), so
// the login it stores is the one the owner approved on the provider's own
// page, and no run worker can store one. /signedin tells the broker
// whether that worker's own sign-in stored the login (the sign-in's only
// success signal), and /plan whether a plan is signed in and allowed
// private data (the runner's Granted and PrivateOK); neither carries a
// login value.

// Socket names for provider workers.
const (
	// ProviderSocket is the control socket; only the broker connects.
	ProviderSocket = "provider.sock"
	// RouteSocket is the socket inside each worker's directory.
	RouteSocket = "route.sock"
)

// providerPrefix names provider workers (vm.ProviderPrefix, pinned by test).
const providerPrefix = "pw-"

var providerRE = regexp.MustCompile(`^pw-[a-z0-9][a-z0-9-]{0,36}$`)

// providerIDRE is a provider's name (provagent's declaration ID).
var providerIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Bounds on the route sockets (CRED-8, K28). Each worker's socket accepts
// routeConns connections; more wait in the kernel's queue. Across every
// worker at most routeCalls calls are in flight, each holding at most one
// request body (egress.DefaultMaxBody); past that a call is refused with 503
// before its body is read. tests/test_egress_memory.py counts routeCalls
// in the vault process's memory ceiling.
const (
	routeConns = 8
	routeCalls = 8
	// routeReadTimeout bounds reading one request, headers and body.
	routeReadTimeout = time.Minute
)

// workerRoutes opens and closes provider workers' route sockets.
type workerRoutes struct {
	dir    string
	config func(worker string) (egress.WorkerRouteConfig, error)
	forget func(worker string)
	seed   func(worker string) (map[string][]byte, error)
	// usage is the provider's plan usage across every worker route
	// (egress.PlanUsage.Snapshot), served on /usage; nil serves none.
	usage func(provider string) egress.UsageSnapshot
	// plan answers /plan for a plan provider; nil answers nothing.
	plan func(provider string) (planState, error)
	// signedIn answers /signedin: whether worker's own sign-in committed
	// the plan login (PlanLogins.SignedInBy); nil answers false.
	signedIn func(worker string) bool
	conns    int
	calls    chan struct{}

	mu   sync.Mutex
	open map[string]*routeServer
}

type routeServer struct {
	dir string
	srv *http.Server
}

// newWorkerRoutes returns the set. Route directories are made under dir.
// config supplies a worker's route configuration and fails while the vault
// is locked; forget drops the worker's placeholders when its route closes
// for good (/close, shutdown), never on a reopen; seed returns the worker's
// placeholder files (PlanLogins.Seed).
func newWorkerRoutes(dir string, config func(string) (egress.WorkerRouteConfig, error), forget func(string), seed func(string) (map[string][]byte, error)) *workerRoutes {
	return &workerRoutes{
		dir: dir, config: config, forget: forget, seed: seed,
		conns: routeConns, calls: make(chan struct{}, routeCalls),
		open: map[string]*routeServer{},
	}
}

// planState is a plan's state as /plan answers it: whether the owner's
// login is stored, and whether the owner allowed it private data.
type planState struct {
	Granted   bool `json:"granted"`
	PrivateOK bool `json:"private_ok"`
}

// planProvider is the one plan provider the routes serve (egress.Codex).
const planProvider = "codex"

// handler serves POST /open, /signin, /signedin, /close and /seed with
// ?machine=<id>, POST /plan with ?provider=<plan>, and POST /usage with
// ?provider=<id> (RES-5: the pools as the broker's own connections last
// read them).
func (p *workerRoutes) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodPost:
			http.Error(w, "not found", http.StatusNotFound)
			return
		case r.URL.Path == "/plan":
			p.servePlan(w, r.URL.Query().Get("provider"))
			return
		case r.URL.Path == "/usage":
			provider := r.URL.Query().Get("provider")
			if p.usage == nil || !providerIDRE.MatchString(provider) {
				http.Error(w, "no usage for that provider", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(p.usage(provider))
			return
		case r.URL.Path != "/open" && r.URL.Path != "/signin" && r.URL.Path != "/signedin" && r.URL.Path != "/close" && r.URL.Path != "/seed":
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		id := r.URL.Query().Get("machine")
		if !providerRE.MatchString(id) {
			http.Error(w, "not a provider worker", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/close":
			p.close(id)
			w.WriteHeader(http.StatusOK)
		case "/signedin":
			// From memory, not the vault: the record of this worker's
			// commit, which /close forgets.
			json.NewEncoder(w).Encode(map[string]bool{"stored": p.signedIn != nil && p.signedIn(id)})
		case "/seed":
			if p.seed == nil {
				http.Error(w, "no seed", http.StatusNotFound)
				return
			}
			files, err := p.seed(id)
			if errors.Is(err, egress.ErrVaultLocked) {
				http.Error(w, errRouteLocked.Error(), http.StatusServiceUnavailable)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(files)
		default:
			dir, err := p.openRoute(id, r.URL.Path == "/signin")
			if errors.Is(err, errRouteLocked) {
				// One line: modelroute.RouteControl maps the 503 to
				// modelroute.ErrVaultLocked.
				http.Error(w, errRouteLocked.Error(), http.StatusServiceUnavailable)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"dir": dir})
		}
	})
}

var errRouteLocked = errors.New("the vault is locked; no provider route can open")

// servePlan answers provider's plan state as JSON.
func (p *workerRoutes) servePlan(w http.ResponseWriter, provider string) {
	if provider != planProvider || p.plan == nil {
		http.Error(w, "not a plan provider", http.StatusBadRequest)
		return
	}
	s, err := p.plan(provider)
	if errors.Is(err, egress.ErrVaultLocked) {
		http.Error(w, errRouteLocked.Error(), http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "plan state unreadable", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(s)
}

// openRoute makes the worker's directory and serves its route in it. An
// open worker's route is replaced (a restart) and keeps its placeholders.
// signIn opens the sign-in endpoints instead of the run endpoints.
func (p *workerRoutes) openRoute(id string, signIn bool) (string, error) {
	cfg, err := p.config(id)
	if err != nil {
		return "", errors.Join(errRouteLocked, err)
	}
	cfg.SignIn = signIn
	h, err := egress.NewWorkerRoute(cfg)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked(id)
	if err := runDir(p.dir); err != nil {
		return "", err
	}
	dir := filepath.Join(p.dir, id)
	// A directory a crashed process left would make Mkdir fail; p.dir is
	// ours (runDir), so nothing in it is another uid's.
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	// 0700 and 0600 whatever the umask: no other host uid may reach the
	// route (K28). runsc reaches it through the worker's mount as root.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	path := filepath.Join(dir, RouteSocket)
	ln, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	// Closing ln must not unlink path: a Serve that exits late on a
	// replaced route would otherwise delete a reopen's new route.sock
	// (K28). stopLocked, closeAll and the error paths remove the
	// directory, socket included.
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		os.RemoveAll(dir)
		return "", fmt.Errorf("route %s: listener is %T, not a unix listener", id, ln)
	}
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		os.RemoveAll(dir)
		return "", err
	}
	srv := newServer(p.bounded(h))
	srv.ReadTimeout = routeReadTimeout
	go srv.Serve(newLimitListener(ln, p.conns))
	p.open[id] = &routeServer{dir: dir, srv: srv}
	return dir, nil
}

// bounded refuses a call with 503 while routeCalls calls are in flight
// across every worker route, before the call's body is read.
func (p *workerRoutes) bounded(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case p.calls <- struct{}{}:
			defer func() { <-p.calls }()
			h.ServeHTTP(w, r)
		default:
			http.Error(w, "egress busy: too many provider calls", http.StatusServiceUnavailable)
		}
	})
}

// close ends id's route for good and forgets its placeholders.
func (p *workerRoutes) close(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked(id)
	p.forgetLocked(id)
}

// stopLocked stops serving id's route and removes its directory; the
// worker's placeholders stay (a reopen is the same worker restarting).
func (p *workerRoutes) stopLocked(id string) {
	rs, ok := p.open[id]
	if !ok {
		return
	}
	rs.srv.Close()
	os.RemoveAll(rs.dir)
	delete(p.open, id)
}

func (p *workerRoutes) forgetLocked(id string) {
	if p.forget != nil {
		p.forget(id)
	}
}

// closeAll closes every route and forgets its worker (shutdown).
func (p *workerRoutes) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.open {
		p.stopLocked(id)
		p.forgetLocked(id)
	}
}

// limitListener accepts at most n connections at once; more wait in the
// kernel's queue and cost this process nothing (guest/plane.go's pattern).
type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func newLimitListener(l net.Listener, n int) *limitListener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// loginStore is the open vault as the plan logins use it, or
// egress.ErrVaultLocked while it is not open.
func (c *custody) loginStore() (egress.LoginStore, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open || c.v == nil {
		return nil, egress.ErrVaultLocked
	}
	return c.v, nil
}

// planState reads provider's plan state: granted once its login is stored
// (as a stored API key grants its provider), private_ok with the owner's
// per-plan mark. egress.ErrVaultLocked while the vault is not open.
func (c *custody) planState(logins *egress.PlanLogins, provider string) (planState, error) {
	granted, err := logins.Signed(provider)
	if err != nil {
		return planState{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open || c.v == nil {
		return planState{}, egress.ErrVaultLocked
	}
	return planState{Granted: granted, PrivateOK: hasKind(c.v, PrivateOKPrefix+provider, KindPrivateOK)}, nil
}

// workerRouteRoot is the directory under the run directory that holds the
// per-worker route directories.
const workerRouteRoot = "workers"

// serveWorkerRoutes opens the provider control socket in dir for the
// broker's uid and serves worker routes until the returned closer is
// closed; closing it closes every route. Each route swaps in the plan login
// the open vault holds (custody.loginStore) and dials through the process's
// address guard (DEV-2).
func serveWorkerRoutes(dir string, c *custody, brokerUID int) (io.Closer, error) {
	logins := egress.NewPlanLogins(c.loginStore, map[string]string{})
	// up stays nil in the shipped build: the route dials through the guard.
	up := c.modelTransport
	if up == nil {
		up = planUpstream(c.guard)
	}
	usage := &egress.PlanUsage{}
	if err := runDir(dir); err != nil {
		return nil, err
	}
	// Route directories a crashed process left are cleared: their workers'
	// mounts then point at nothing, which fails closed (K28).
	if err := os.RemoveAll(filepath.Join(dir, workerRouteRoot)); err != nil {
		return nil, err
	}
	p := newWorkerRoutes(filepath.Join(dir, workerRouteRoot), func(worker string) (egress.WorkerRouteConfig, error) {
		if _, err := c.loginStore(); err != nil {
			return egress.WorkerRouteConfig{}, err
		}
		return codexRouteConfig(worker, logins, up, c.guard, noAudit{}, usage), nil
	}, logins.Forget, func(worker string) (map[string][]byte, error) {
		return logins.Seed("codex", worker)
	})
	p.usage = usage.Snapshot
	p.plan = func(provider string) (planState, error) { return c.planState(logins, provider) }
	p.signedIn = func(worker string) bool { return logins.SignedInBy(planProvider, worker) }
	ln, err := listen(dir, ProviderSocket, brokerUID)
	if err != nil {
		return nil, err
	}
	srv := newServer(p.handler())
	go srv.Serve(ln)
	return closerFunc(func() error {
		err := srv.Close()
		p.closeAll()
		return err
	}), nil
}

// codexRouteConfig is one worker's Codex route as the vault process serves
// it: every reading the route sees on the broker's own connection, and every
// refused login, is fed to usage, which /usage serves to admission (RES-5,
// CRED-5). The tests build their routes through it, so they cannot drift
// from what ships.
func codexRouteConfig(worker string, logins egress.PlanLoginStore, tr http.RoundTripper, guard *netguard.Policy, audit egress.Auditor, usage *egress.PlanUsage) egress.WorkerRouteConfig {
	return egress.WorkerRouteConfig{
		Route: egress.Codex(), Worker: worker, Logins: logins,
		Transport: tr, Guard: guard, Audit: audit,
		Quota: func(q egress.QuotaReading) {
			log.Printf("plan quota %s %s: %.1f%% used, exhausted=%v", q.Worker, q.Pool, q.UsedPercent, q.Exhausted)
			usage.Quota(q)
		},
		Signal: func(s egress.PlanSignal) {
			log.Printf("plan signal %s %s: %s", s.Provider, s.Worker, s.Kind)
			usage.Signal(s)
		},
		Meter: func(u egress.PlanUse) {
			log.Printf("plan use %s %s: HTTP %d, %d bytes out, %d bytes in", u.Worker, u.Endpoint, u.Status, u.RequestBytes, u.ResponseBytes)
		},
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
