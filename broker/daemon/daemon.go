// Package daemon wires the broker skeleton together: the journal engine,
// control words, admission, the owner channel (P1-5), and the sockets (PLAN
// P1-2).
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
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
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
	// ModemGID, if set, is the bridge's group: the owner socket is given
	// it, mode 0660, so the bridge can connect as its own user (security
	// R3 on #170). Unset, the socket is 0600 (same-uid tests only).
	ModemGID *int
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
	// OwnerState, when set, puts the owner channel (P1-5) in front of the
	// control words: it becomes the Auth, and owns codes, approvals, and
	// session unlock. Its state lives in this file.
	OwnerState string
	// OwnerSecrets are the high-tier verifiers from the vault (CRED-8).
	// agentosd leaves them empty: the seeds stay in the vault process
	// (egress K7). With no verifier the channel refuses every high-tier
	// code rather than accept a guessable one.
	OwnerSecrets ownerch.Secrets
	// OwnerVerifier checks code-generator codes in the vault process,
	// which holds the seed (egress K7); it takes the place of
	// OwnerSecrets.TOTPSeed.
	OwnerVerifier ownerch.Verifier
	// Modem, when set, is served by the owner channel as well as the owner
	// socket, and carries its outbound texts.
	Modem modem.Modem
	// OwnerOps are more ops on the owner socket: the modem bridge's
	// (modemlink.Link.Ops, P2-3w). They cannot replace "message". Each
	// runs with a context that ends if the bridge hangs up first, so the
	// outbox's long poll hands no text to a dead bridge.
	OwnerOps map[string]sockets.Handler
	// BridgeOnly drops "message" from the owner socket, leaving OwnerOps:
	// with the modem bridge on, owner texts arrive only through its
	// checked "inbound" op (security F1 on #170). "message" stays for
	// simulator and test builds.
	BridgeOnly bool
	// Agent receives the owner's task chat: the guest plane's owner inbox
	// for the agent's machine (ARC-6 (c)). Nil: no agent running.
	Agent control.Agent
	// AgentStatus, when it returns a line, takes the place of the machine
	// counts in STATUS: why the owner's agent machine is not running, in
	// fixed plain words. Empty while it runs.
	AgentStatus func() string
	// Grants configures the approval policy: each executor's declared
	// operations and verbs (Declared), adapter verifiers, the local
	// confirmation page, reply composers, request pacing.
	Grants grants.Config
	// Executors are the adapters' executors, by name; each needs its
	// declaration in Grants.Declared. None exist before P2-6/P2-7.
	Executors map[string]journal.Executor
	// Recall runs the broker's recall rollback intents (grants
	// RecallExecutor, recalltool W10) once the owner approves them. Nil:
	// none can run.
	Recall journal.Executor
	// BrokerExecutors are the broker's own setting executors (the change
	// pipeline and the loop scheduler, W3). They declare no operations: no
	// grant can name them, and only the intents the gate's Changes and
	// Loops policies allow reach them.
	BrokerExecutors map[string]journal.Executor
	// Settings answers an owner text that is a box setting (the loop
	// scheduler's Text) and HelpExtra is appended to HELP; Narrows marks
	// the settings that run in a locked session (owner.Config).
	Settings  func(ctx context.Context, msg string, unlocked bool) (reply string, ok bool)
	HelpExtra string
	Narrows   func(msg string) bool
	// Answer takes the owner's replies to agents' questions before they
	// reach the agent (question.Book.Answer, W9). Nil: none.
	Answer func(ctx context.Context, msg string) (reply string, ok bool)
	// Notes are STATUS's exception lines (control.Handler.Notes); recall
	// adds one while an agent holds a record the owner deleted (W10).
	Notes []func() string
	// PageSocket, when set, serves localui.sock: the box's Wi-Fi page's ops
	// on the owner channel (localapi, P2-2w). It needs OwnerState.
	PageSocket *PageSocket
	// Redactor scrubs journaled free text. Nil journals none at all until
	// the vault's redactor (CRED-7 values plus CH-19 patterns) is wired
	// with the vault unlock (P2-4).
	Redactor journal.Redactor
}

// PageSocket is the local UI's socket. The local UI runs as its own user and
// decodes untrusted input, so it is treated as compromised: agentosd
// mints and checks its session tokens and counts its wrong codes
// (localsrv; Security L1, L2 on the P2-2w plan).
type PageSocket struct {
	// UID is the only uid allowed on the socket (SO_PEERCRED).
	UID int
	// GID, if set, is the local UI's group: the socket is given it, mode
	// 0660. Unset, the socket is 0600 (same-uid tests only).
	GID *int
	// LineNote is the owner line's note (modemlink.Link.OwnerLineNote);
	// nil without the modem bridge.
	LineNote func() string
}

// Daemon is a running broker.
type Daemon struct {
	engine *journal.Engine
	gate   *grants.Gate
	store  *journal.FileStore
	owner  *ownerch.Channel
	srv    *sockets.Server
	adm    *admission.Controller
	done   chan struct{}
}

// redactAll journals no free text at all until the vault (P1-3) supplies a
// redactor that knows the vault values and the CH-19 patterns.
func redactAll(s string) string {
	if s == "" {
		return ""
	}
	return Redacted
}

// Redacted is what the default redactor stores for any free text, so a
// reader of the journal (the skill compiler) can tell a value it never
// kept from a real one.
const Redacted = "[redacted]"

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
	// The policy is the grants gate (OP-5, REV-2): with no grants every
	// effect is refused, and every irreversible effect a grant allows is
	// asked of the owner unless a pre-allowance covers it.
	gcfg := cfg.Grants
	execs := map[string]journal.Executor{}
	for name, ex := range cfg.Executors {
		if name == grants.ExecutorName || name == grants.RecallExecutor {
			store.Close()
			return nil, fmt.Errorf("daemon: executor name %q is reserved", name)
		}
		if gcfg.Declared[name] == nil {
			store.Close()
			return nil, fmt.Errorf("daemon: executor %q declares no operations (ADP-2)", name)
		}
		execs[name] = ex
	}
	for name, ex := range cfg.BrokerExecutors {
		switch {
		case name == grants.ExecutorName, name == grants.RecallExecutor:
			store.Close()
			return nil, fmt.Errorf("daemon: executor name %q is reserved", name)
		case execs[name] != nil:
			store.Close()
			return nil, fmt.Errorf("daemon: executor %q is both an adapter and the broker's", name)
		}
		execs[name] = ex
	}
	gate := grants.New(gcfg)
	execs[grants.ExecutorName] = gate
	if cfg.Recall != nil {
		execs[grants.RecallExecutor] = cfg.Recall
	}
	red := cfg.Redactor
	if red == nil {
		red = redactAll
	}
	eng, err := journal.Open(store, gate, execs, red)
	if err != nil {
		store.Close()
		return nil, err
	}
	machines := adm.Summary
	if cfg.AgentStatus != nil {
		machines = func() string {
			if l := cfg.AgentStatus(); l != "" {
				return l
			}
			return adm.Summary()
		}
	}
	h := &control.Handler{Engine: eng, Auth: cfg.Auth, Agent: cfg.Agent, Machines: machines, Notes: cfg.Notes,
		Settings: cfg.Settings, HelpExtra: cfg.HelpExtra, Answer: cfg.Answer}
	handle := h.Handle
	var ch *ownerch.Channel
	if cfg.OwnerState != "" {
		if ch, err = ownerch.New(ownerch.Config{
			Owner: cfg.OwnerNumber, Modem: cfg.Modem, Engine: eng, Agent: cfg.Agent,
			Machines: machines, Notes: cfg.Notes, Secrets: cfg.OwnerSecrets, Verifier: cfg.OwnerVerifier, Store: ownerch.FileStore{Path: cfg.OwnerState},
			Decide: gate.Decide, Narrow: gate.Narrow, Reissue: gate.Reissue,
			Settings: cfg.Settings, HelpExtra: cfg.HelpExtra, Narrows: cfg.Narrows, Answer: cfg.Answer,
		}); err != nil {
			store.Close()
			return nil, err
		}
		handle = ch.Handle
	}
	// Attach before the owner channel boots: Boot's restart decisions, its
	// re-issue hand-over (grants GR10), and every guest effect go through
	// the gate.
	if ch != nil {
		gate.Attach(eng, ch)
	} else {
		gate.Attach(eng, nil)
	}

	var modemUID *int
	if cfg.ModemUID >= 0 {
		modemUID = &cfg.ModemUID
	}
	eps := []sockets.Endpoint{{
		Name:        OwnerSocket,
		Peer:        sockets.Peer{Kind: "owner"},
		PeerUID:     modemUID,
		PeerGID:     cfg.ModemGID,
		MaxConns:    8,
		IdleTimeout: ownerIdle,
		Ops: map[string]sockets.Handler{
			"message": func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
				var m struct{ From, Text string }
				if err := json.Unmarshal(args, &m); err != nil {
					return nil, sockets.Code("bad message")
				}
				return map[string][]string{"replies": handle(ctx, m.From, m.Text)}, nil
			},
		},
	}}
	if cfg.BridgeOnly {
		delete(eps[0].Ops, "message")
	}
	for op, h := range cfg.OwnerOps {
		if _, taken := eps[0].Ops[op]; !taken && op != "message" {
			eps[0].Ops[op] = h
			if eps[0].HangupOps == nil {
				eps[0].HangupOps = map[string]bool{}
			}
			eps[0].HangupOps[op] = true
		}
	}
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
	if cfg.PageSocket != nil {
		if ch == nil {
			store.Close()
			return nil, errors.New("daemon: the local UI's socket needs the owner channel (OwnerState)")
		}
		ui := localsrv.New(localsrv.Config{Owner: ch, LineNote: cfg.PageSocket.LineNote})
		uid := cfg.PageSocket.UID
		eps = append(eps, sockets.Endpoint{
			Name:        localapi.Socket,
			Peer:        sockets.Peer{Kind: "localui"},
			PeerUID:     &uid,
			PeerGID:     cfg.PageSocket.GID,
			MaxConns:    8,
			IdleTimeout: 30 * time.Second,
			Ops:         ui.Ops(),
		})
	}
	srv := &sockets.Server{Dir: cfg.SocketDir}
	if err := srv.Start(ctx, eps...); err != nil {
		store.Close()
		return nil, err
	}
	d := &Daemon{engine: eng, gate: gate, store: store, srv: srv, adm: adm, owner: ch, done: make(chan struct{})}
	if ch != nil {
		go serveOwner(ctx, ch, cfg.Modem != nil)
	}
	go gate.Run(ctx, 0)
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

// serveOwner runs the owner channel: on the modem when there is one (Run
// reports what a restart dropped, then serves texts and ticks), otherwise
// only the restart report and the minute tick that expires requests.
func serveOwner(ctx context.Context, ch *ownerch.Channel, hasModem bool) {
	if hasModem {
		ch.Run(ctx)
		return
	}
	ch.Boot()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ch.Tick()
		}
	}
}

// Owner is the owner channel, or nil when OwnerState is unset.
func (d *Daemon) Owner() *ownerch.Channel { return d.owner }

// Gate is the approval policy: the guest plane's Effects and Route.
func (d *Daemon) Gate() *grants.Gate { return d.gate }

// Engine is the daemon's journal engine.
func (d *Daemon) Engine() *journal.Engine { return d.engine }

// Admission is the daemon's admission controller, for the VM lifecycle
// manager to admit and release machines through.
func (d *Daemon) Admission() *admission.Controller { return d.adm }

// Wait returns after ctx is done and every socket and the journal are closed.
func (d *Daemon) Wait() { <-d.done }
