package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/ghbmrk/agentos/broker/egress"
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
// nothing in a request can change it (egress K28).

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

// workerRoutes opens and closes provider workers' route sockets.
type workerRoutes struct {
	dir    string
	config func(worker string) (egress.WorkerRouteConfig, error)
	forget func(worker string)

	mu   sync.Mutex
	open map[string]*routeServer
}

type routeServer struct {
	dir string
	srv *http.Server
}

// newWorkerRoutes returns the set. Route directories are made under dir.
// config supplies a worker's route configuration and fails while the vault
// is locked; forget drops the worker's placeholders when its route closes.
func newWorkerRoutes(dir string, config func(string) (egress.WorkerRouteConfig, error), forget func(string)) *workerRoutes {
	return &workerRoutes{dir: dir, config: config, forget: forget, open: map[string]*routeServer{}}
}

// handler serves POST /open and POST /close with ?machine=<id>.
func (p *workerRoutes) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || (r.URL.Path != "/open" && r.URL.Path != "/close") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		id := r.URL.Query().Get("machine")
		if !providerRE.MatchString(id) {
			http.Error(w, "not a provider worker", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/close" {
			p.close(id)
			w.WriteHeader(http.StatusOK)
			return
		}
		dir, err := p.openRoute(id)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errRouteLocked) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, err.Error(), status)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"dir": dir})
	})
}

var errRouteLocked = errors.New("the vault is locked; no provider route can open")

// openRoute makes the worker's directory and serves its route in it. An
// open worker's route is replaced (a restart).
func (p *workerRoutes) openRoute(id string) (string, error) {
	cfg, err := p.config(id)
	if err != nil {
		return "", errors.Join(errRouteLocked, err)
	}
	h, err := egress.NewWorkerRoute(cfg)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked(id)
	if err := runDir(p.dir); err != nil {
		return "", err
	}
	dir := filepath.Join(p.dir, id)
	// 0755: the guest's uid reads the directory through the read-only
	// mount; the socket in it is what carries the route.
	if err := os.Mkdir(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, RouteSocket)
	ln, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		os.RemoveAll(dir)
		return "", err
	}
	srv := newServer(h)
	go srv.Serve(ln)
	p.open[id] = &routeServer{dir: dir, srv: srv}
	return dir, nil
}

func (p *workerRoutes) close(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked(id)
}

func (p *workerRoutes) closeLocked(id string) {
	rs, ok := p.open[id]
	if !ok {
		return
	}
	rs.srv.Close()
	os.RemoveAll(rs.dir)
	delete(p.open, id)
	if p.forget != nil {
		p.forget(id)
	}
}

// closeAll closes every route (shutdown).
func (p *workerRoutes) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.open {
		p.closeLocked(id)
	}
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
	if err := runDir(dir); err != nil {
		return nil, err
	}
	p := newWorkerRoutes(filepath.Join(dir, workerRouteRoot), func(worker string) (egress.WorkerRouteConfig, error) {
		if _, err := c.loginStore(); err != nil {
			return egress.WorkerRouteConfig{}, err
		}
		return egress.WorkerRouteConfig{
			Route: egress.Codex(), Worker: worker, Logins: logins,
			Transport: c.modelTransport, Guard: c.guard, Audit: noAudit{},
			Quota: func(q egress.QuotaReading) {
				log.Printf("plan quota %s %s: %.1f%% used, exhausted=%v", q.Worker, q.Pool, q.UsedPercent, q.Exhausted)
			},
			Meter: func(u egress.PlanUse) {
				log.Printf("plan use %s %s: HTTP %d, %d bytes out, %d bytes in", u.Worker, u.Endpoint, u.Status, u.RequestBytes, u.ResponseBytes)
			},
		}, nil
	}, logins.Forget)
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

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
