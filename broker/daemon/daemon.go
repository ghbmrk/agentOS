// Package daemon wires the broker skeleton together: the journal engine,
// control words, admission, and the sockets (PLAN P1-2).
//
// It runs with no model, no guest runtime, no executor, and no network.
// Those arrive in later packages through the sockets and the journal's
// Executor and Policy interfaces; none of them is needed for STOP, RESUME,
// STATUS, or HELP (CH-2, ARC-2).
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// OwnerSocket is where the owner channel (the modem, or its simulator in
// P1-5) delivers owner texts.
const OwnerSocket = "owner.sock"

// ownerIdle closes an owner-socket connection that sends nothing for this
// long, so a stuck or hostile bridge cannot hold all 8 slots and lock the
// owner out (CH-2). The bridge opens a connection per message (B11).
var ownerIdle = 60 * time.Second

// GuestSocket is the socket file handed to agent machine id.
func GuestSocket(id string) string { return "guest-" + id + ".sock" }

// Config configures Run.
type Config struct {
	JournalPath string
	SocketDir   string
	OwnerNumber string
	// ModemUID is the only uid allowed on the owner socket: the modem
	// bridge, which runs as its own user (SO_PEERCRED, B8).
	ModemUID int
	// Machines gets one guest socket each. IDs are [a-z0-9-], unique.
	Machines []string
	// Auth overrides the default, which knows the owner's number and keeps
	// sessions locked until the owner channel (P1-5) can unlock them.
	Auth      control.Auth
	Admission admission.Config
	// Preempter stops experiments for higher classes (RES-1). Nil refuses
	// preemption. The VM lifecycle manager (vm.Manager) supplies it.
	Preempter admission.Preempter
	// Pressure is memory pressure (PSI some avg10, %); above MaxPressure
	// only foreground is admitted (RES-2). Nil disables the check.
	Pressure    func() float64
	MaxPressure float64
}

// Daemon is a running broker.
type Daemon struct {
	engine *journal.Engine
	store  *journal.FileStore
	srv    *sockets.Server
	adm    *admission.Controller
	done   chan struct{}
}

// denyAll is the policy until grants exist (P1-3): nothing is authorized.
type denyAll struct{}

func (denyAll) Check(context.Context, journal.Phase, journal.Intent) error {
	return errors.New("no grants are configured")
}

// redactAll journals no free text at all until the vault (P1-3) supplies a
// redactor that knows the vault values and the CH-19 patterns.
func redactAll(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// ownerOnly is the default Auth.
type ownerOnly struct{ number string }

func (a ownerOnly) IsOwner(from string) bool       { return from == a.number }
func (a ownerOnly) SessionUnlocked(time.Time) bool { return false }

// noPreempt refuses preemption when no machine manager is configured.
type noPreempt struct{}

func (noPreempt) Preempt(id string) error {
	return fmt.Errorf("cannot stop %s: no machine manager", id)
}

// Run opens the journal (replaying it, OP-4), starts the sockets, and serves
// until ctx is done.
func Run(ctx context.Context, cfg Config) (*Daemon, error) {
	if cfg.OwnerNumber == "" && cfg.Auth == nil {
		return nil, errors.New("daemon: owner number required")
	}
	if cfg.Auth == nil {
		cfg.Auth = ownerOnly{cfg.OwnerNumber}
	}
	seen := map[string]bool{}
	for _, id := range cfg.Machines {
		if !validID(id) || seen[id] {
			return nil, fmt.Errorf("daemon: bad or duplicate machine id %q", id)
		}
		seen[id] = true
	}
	pre := cfg.Preempter
	if pre == nil {
		pre = noPreempt{}
	}
	adm, err := admission.New(cfg.Admission, pre)
	if err != nil {
		return nil, err
	}
	adm.Pressure, adm.MaxPressure = cfg.Pressure, cfg.MaxPressure
	store, err := journal.OpenFile(cfg.JournalPath)
	if err != nil {
		return nil, err
	}
	eng, err := journal.Open(store, denyAll{}, map[string]journal.Executor{}, redactAll)
	if err != nil {
		store.Close()
		return nil, err
	}
	h := &control.Handler{Engine: eng, Auth: cfg.Auth, Machines: adm.Summary}

	modem := cfg.ModemUID
	eps := []sockets.Endpoint{{
		Name:        OwnerSocket,
		Peer:        sockets.Peer{Kind: "owner"},
		PeerUID:     &modem,
		MaxConns:    8,
		IdleTimeout: ownerIdle,
		Ops: map[string]sockets.Handler{
			"message": func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
				var m struct{ From, Text string }
				if err := json.Unmarshal(args, &m); err != nil {
					return nil, sockets.Code("bad message")
				}
				return map[string][]string{"replies": h.Handle(ctx, m.From, m.Text)}, nil
			},
		},
	}}
	for _, id := range cfg.Machines {
		eps = append(eps, sockets.Endpoint{
			Name:        GuestSocket(id),
			Peer:        sockets.Peer{Kind: "guest", ID: id},
			MaxConns:    4,
			IdleTimeout: 30 * time.Second,
			Ops: map[string]sockets.Handler{
				"whoami": func(_ context.Context, p sockets.Peer, _ json.RawMessage) (any, error) { return p, nil },
			},
		})
	}
	srv := &sockets.Server{Dir: cfg.SocketDir}
	if err := srv.Start(ctx, eps...); err != nil {
		store.Close()
		return nil, err
	}
	d := &Daemon{engine: eng, store: store, srv: srv, adm: adm, done: make(chan struct{})}
	go func() {
		srv.Wait()
		store.Close()
		close(d.done)
	}()
	return d, nil
}

func validID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

// Engine is the daemon's journal engine.
func (d *Daemon) Engine() *journal.Engine { return d.engine }

// Admission is the daemon's admission controller, for the VM lifecycle
// manager to admit and release machines through.
func (d *Daemon) Admission() *admission.Controller { return d.adm }

// Wait returns after ctx is done and every socket and the journal are closed.
func (d *Daemon) Wait() { <-d.done }
