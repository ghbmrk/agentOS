// Package guest serves the broker's guest interface (SPEC v0.12 ARC-6) to
// agent machines, one Unix socket per machine (PLAN P1-7).
//
// Each machine gets a broker-held directory holding one socket,
// broker.sock, which the runtime mounts read-only into that machine's
// sandbox and nowhere else (vm.Services). Identity therefore comes from the
// listener a request arrived on, never from anything the guest sends. The
// socket serves exactly the ARC-6 services:
//
//	/model/<adapter>/...  (a) model access: the OP-8 meter, then model egress
//	/mcp                  (b) broker tools over MCP (streamable HTTP, JSON)
//	/owner/next, /owner/reply
//	                      (c) owner messages into the guest's inbound API,
//	                          fetched by the guest's bridge, replies back
//
// (d), uncredentialed egress by data label, is not served yet: every
// machine is closed to everything else (ASSUMPTIONS.md G6).
//
// Guest configuration is defense in depth only (ARC-7): nothing here trusts
// a header, token, or body field for identity, limits, or routing.
//
// The package is not on the control path (ARC-2): STOP, STATUS, and
// admission never import it.
package guest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// Socket is the socket's file name inside a machine's services directory.
const Socket = "broker.sock"

// Machines is the part of the machine manager (vm.Manager) the plane uses.
type Machines interface {
	// Step takes the per-step file-system snapshot (REV-1).
	Step(ctx context.Context, id string) error
	// RaisePrivate raises a machine's label to private (REV-5).
	RaisePrivate(id string) error
	// Lineage names the machine id descends from by fork, or id itself.
	Lineage(id string) (string, error)
}

// Effects is the part of the journal engine broker tools use.
type Effects interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Dispatch(ctx context.Context, id string) (journal.Status, error)
	Get(id string) (journal.Status, error)
}

// Config configures New.
type Config struct {
	// Dir holds one directory per machine; created 0700, broker-held, and
	// never mounted whole into any guest.
	Dir      string
	Machines Machines
	Effects  Effects
	// Route picks the executor for an effect on account; false means no
	// adapter is connected for it and the request is refused.
	Route func(account string) (executor string, ok bool)
	// Label reports a machine's data label (REV-5), recorded on each
	// intent it submits. Nil, or an empty answer, records "private": an
	// unknown label is never reported as public.
	Label func(machine string) string
	// Model returns machine's model egress (the egress proxy's handler).
	// Nil answers 503: no model access.
	Model func(machine string) http.Handler
	// Meter meters every model call (OP-8). Required when Model is set:
	// model egress is never served unmetered.
	Meter *meter.Meter
	// OwnerReply receives a guest's reply to an owner message. It is
	// guest-written text: the owner channel filters it before it goes out
	// (CH-19). Nil drops replies.
	OwnerReply func(machine, msgID, text string)
	// Logf reports broker-side faults (a failed snapshot). Nil is silent.
	Logf func(format string, args ...any)
	// MaxConns caps one machine's concurrent requests; default 8.
	MaxConns int
}

// Plane serves every machine's socket. It implements vm.Services.
type Plane struct {
	cfg Config
	mu  sync.Mutex
	ms  map[string]*machine
}

type machine struct {
	id   string
	dir  string
	srv  *http.Server
	slot chan struct{}
	box  *inbox
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// New checks cfg and creates Dir.
func New(cfg Config) (*Plane, error) {
	if cfg.Dir == "" || cfg.Machines == nil || cfg.Effects == nil {
		return nil, errors.New("guest: Dir, Machines, and Effects are required")
	}
	if cfg.Model != nil && cfg.Meter == nil {
		return nil, errors.New("guest: model egress needs the OP-8 meter")
	}
	if cfg.Route == nil {
		cfg.Route = func(string) (string, bool) { return "", false }
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 8
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	return &Plane{cfg: cfg, ms: map[string]*machine{}}, nil
}

// Open starts serving machine id and returns its services directory. It is
// idempotent: a machine that restarts keeps its socket and its inbox.
func (p *Plane) Open(id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", fmt.Errorf("guest: bad machine id %q", id)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if m := p.ms[id]; m != nil {
		return m.dir, nil
	}
	dir := filepath.Join(p.cfg.Dir, id)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, Socket))
	if err != nil {
		return "", err
	}
	m := &machine{id: id, dir: dir, slot: make(chan struct{}, p.cfg.MaxConns), box: newInbox()}
	m.srv = &http.Server{
		Handler:           p.handler(m),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
	}
	go m.srv.Serve(l)
	p.ms[id] = m
	return dir, nil
}

// Close stops serving machine id and removes its directory. Idempotent.
func (p *Plane) Close(id string) {
	p.mu.Lock()
	m := p.ms[id]
	delete(p.ms, id)
	p.mu.Unlock()
	if m == nil {
		return
	}
	m.box.close()
	m.srv.Close()
	os.RemoveAll(m.dir)
}

// Shutdown closes every machine's socket.
func (p *Plane) Shutdown() {
	p.mu.Lock()
	ids := make([]string, 0, len(p.ms))
	for id := range p.ms {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	for _, id := range ids {
		p.Close(id)
	}
}

func (p *Plane) get(id string) *machine {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ms[id]
}

// handler is machine m's whole surface. Anything else is 404.
func (p *Plane) handler(m *machine) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/model/", http.StripPrefix("/model", p.model(m.id)))
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) { p.mcp(m.id, w, r) })
	mux.HandleFunc("/owner/next", func(w http.ResponseWriter, r *http.Request) { p.ownerNext(m, w, r) })
	mux.HandleFunc("/owner/reply", func(w http.ResponseWriter, r *http.Request) { p.ownerReply(m, w, r) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case m.slot <- struct{}{}:
			defer func() { <-m.slot }()
		default:
			http.Error(w, "too many requests in flight", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (p *Plane) model(id string) http.Handler {
	if p.cfg.Model == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no model egress is configured", http.StatusServiceUnavailable)
		})
	}
	return p.cfg.Meter.Wrap(id, p.cfg.Model(id))
}

// step snapshots machine id after a broker tool call (REV-1, vm V3). A
// failed snapshot is a broker fault: it is reported, and the tool result
// still goes back, since the effect it describes has already happened.
func (p *Plane) step(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.cfg.Machines.Step(ctx, id); err != nil {
		p.cfg.Logf("guest %s: step snapshot after tool call failed: %v", id, err)
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
