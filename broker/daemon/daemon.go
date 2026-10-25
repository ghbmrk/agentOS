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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon/journalowner"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/journal/check"
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

// settleWait and settleMaxWait pace startup reconciliation (OP-4): asked
// again after settleWait while evidence is unavailable, doubling to
// settleMaxWait.
var settleWait, settleMaxWait = 2 * time.Second, 5 * time.Minute

// GuestSocket is the socket file handed to agent machine id.
func GuestSocket(id string) string { return "guest-" + id + ".sock" }

// journalRefusals journals each protocol refusal on machine id's socket,
// coalesced per machine and code as egress denials are, so a guest
// looping on bad frames cannot fill the journal. The code rides in
// Operation as a token ("unknown-op"), since the journal may redact the
// reason. A failed write is dropped: the refusal already stopped the
// frame.
func journalRefusals(eng *journal.Engine, gate *journal.EgressGate, id string) func(sockets.Peer, sockets.Code) {
	return func(_ sockets.Peer, c sockets.Code) {
		n := journal.EgressNote{Machine: id, Adapter: sockets.RefusalNote, Operation: c.Token(), Reason: sockets.RefusalNote + ": " + string(c)}
		if gate.Admit(&n) {
			eng.RecordEgress(n)
		}
	}
}

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
	// OwnerDrainOps are the owner socket's ops still served while the
	// shutdown drain runs (modemlink.DrainOps: the bridge's outbox, sent
	// and state), so a text the owner channel started is still handed to
	// the bridge and its result heard. Every other op on every socket is
	// refused from the stop on (errStopping).
	OwnerDrainOps []string
	// OwnerDrainLive says a modem bridge is still there to take the
	// drain's texts (modemlink.Link.Bridged); once it says no, the drain
	// ends rather than wait out its bound. Nil: the drain waits for its
	// texts up to the bound (a direct modem).
	OwnerDrainLive func() bool
	// SendDrain bounds the shutdown drain (0: ownerch.SendDrain; tests set
	// it shorter).
	SendDrain time.Duration
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
	// Kernel, when set, is the kernel's owner seam: STOP, RESUME, STATUS
	// and RETRY reach it too (#2783). Nil: no kernel.
	Kernel KernelOwner
	// PageSocket, when set, serves localui.sock: the box's Wi-Fi page's ops
	// on the owner channel (localapi, P2-2w). It needs OwnerState.
	PageSocket *PageSocket
	// Redactor scrubs journaled free text. Nil journals none at all until
	// the vault's redactor (CRED-7 values plus CH-19 patterns) is wired
	// with the vault unlock (P2-4).
	Redactor journal.Redactor
	// Now is the clock the journal stamps records with; nil is time.Now
	// in UTC, the journal's own default.
	// An adapter that reads the journal's records against its own clock
	// is given the same function (SR3-mail-w2 W2-c).
	Now func() time.Time
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
	// Line is the owner line's note, last outage and counts (from the
	// modem link); nil without the modem bridge.
	Line func() localapi.Line
	// AdoptSIM records the SIM the page showed as the owner line's once the
	// owner's code is checked (modemlink.Link.Adopt, P2-2w d2b); nil
	// without the modem bridge, which refuses the op.
	AdoptSIM func(tag string) error
	// DescribeRoot, when set, serves changing where updates come from on
	// the page (OSS-10, follow.Executor.Describe): the page's request is
	// then submitted to the gate as a follow intent, which the broker
	// executor named grants.FollowExecutor must run. Nil refuses both ops.
	DescribeRoot func(ctx context.Context, root []byte, chain [][]byte) (localapi.RootSummary, error)
	// Forget, when set, lists the owner's recent tasks on the page and
	// asks to forget one through FORGET's own ask (W3-forget-b3r); nil
	// refuses both ops.
	Forget PageForget
	// RotateAPNet writes a rotated card's Wi-Fi network for agentos-ap
	// (REC-4, #1191), taking it from the vault process's hold of the
	// latest Wi-Fi commit (#1522); nil refuses the op.
	RotateAPNet func() error
	// PlanSignIn signs a signed-out plan in again from the page (#1264).
	PlanSignIn localsrv.PlanSignIn
	// Accounts are the account clerks' sign-ins the Connect page reaches,
	// by account ID (#3006); nil refuses both ops.
	Accounts map[string]localsrv.AccountSignIn
}

// PageForget is FORGET as the page serves it; unlocked is whether the
// owner's session is unlocked, as FORGET by text is given.
type PageForget interface {
	PageTasks(unlocked bool) localapi.ForgetTasks
	PageForget(ctx context.Context, goal string, unlocked bool) string
}

// The page's fixed replies to a follow request: the gate's reason is not
// shown (L3 SHOULD 3 on #148).
const (
	FollowAsked   = "Asked. Approve it on the Approvals page with a code from your code generator; nothing changes until you do."
	FollowRefused = "Not asked: I refused this request."
)

// FollowRefusedName is the reply to a name the gate does not admit.
var FollowRefusedName = fmt.Sprintf("Not asked: use a name of at most %d characters and %d digits, with no spaces at either end, that doesn't start %q.",
	grants.MaxFollowName, grants.MaxFollowDigits, grants.ReservedFollowName)

// Daemon is a running broker.
type Daemon struct {
	engine *journal.Engine
	owned  control.Engine
	gate   *grants.Gate
	store  *journal.FileStore
	owner  *ownerch.Channel
	srv    *sockets.Server
	adm    *admission.Controller
	retry  *retrier
	done   chan struct{}
}

// RetryWaiting lists what RETRY offers (OP-2): the parked effects, whose
// outcome stayed unknown, then the effects a check proved were not done
// and whose resend was refused (journal.Engine.NotResent). The digest
// names the same list.
func (d *Daemon) RetryWaiting() []journal.ParkedIntent { return d.retry.waiting() }

// OnRetryRefused sets f to run when an owner retry of an unclear effect
// is refused (OP-2c), so the effect is listed again in the next digest.
func (d *Daemon) OnRetryRefused(f func()) {
	d.retry.mu.Lock()
	d.retry.onRefused = f
	d.retry.mu.Unlock()
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
	if cfg.PageSocket != nil && cfg.PageSocket.DescribeRoot != nil && cfg.BrokerExecutors[grants.FollowExecutor] == nil {
		return nil, fmt.Errorf("daemon: following a root on the page needs the broker executor %q", grants.FollowExecutor)
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
	// The gate asks on the box's Wi-Fi page exactly when agentosd serves
	// it (P2-2w): asked there with no page, a change could never be
	// answered, so it is refused with the reason that says so.
	gcfg.LocalUI = cfg.PageSocket != nil
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
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	eng, err := journal.Open(store, gate, execs, red, journal.WithClock(now))
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
	// The journal check rides STATUS as a note: silent while the journal
	// keeps the floor invariants, one line naming the rule when it does not.
	// A restart fence startup reconcile has not lifted rides it too (#1373).
	notes := append(append([]func() string{check.Note(eng)}, unconfirmedNotes(eng)...), cfg.Notes...)
	// The owner commands drive the kernel's owner seam as well as the
	// journal engine when a kernel is configured (#2783).
	var owned control.Engine = journalowner.Engine{Engine: eng}
	if cfg.Kernel != nil {
		b := &bothStops{Engine: journalowner.Engine{Engine: eng}, k: cfg.Kernel}
		owned, notes = b, append([]func() string{b.note}, notes...)
	}
	h := &control.Handler{Engine: owned, Auth: cfg.Auth, Agent: cfg.Agent, Machines: machines, Notes: notes,
		Settings: cfg.Settings, HelpExtra: cfg.HelpExtra, Answer: cfg.Answer}
	handle := h.Handle
	var ch *ownerch.Channel
	rt := newRetrier(ctx, eng, gate)
	rt.k = cfg.Kernel
	if cfg.OwnerState != "" {
		if ch, err = ownerch.New(ownerch.Config{
			Owner: cfg.OwnerNumber, Modem: cfg.Modem, Engine: owned, Agent: cfg.Agent,
			Machines: machines, Notes: notes, Secrets: cfg.OwnerSecrets, Verifier: cfg.OwnerVerifier, Store: ownerch.FileStore{Path: cfg.OwnerState},
			Decide: rt.decide(gate.Decide), Narrow: gate.Narrow, Reissue: gate.Reissue, Retry: rt.items,
			Settings: cfg.Settings, HelpExtra: cfg.HelpExtra, Narrows: cfg.Narrows, Answer: cfg.Answer,
		}); err != nil {
			store.Close()
			return nil, err
		}
		handle = ch.Handle
		rt.mu.Lock()
		rt.inform = ch.Inform
		rt.mu.Unlock()
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
	refusals := &journal.EgressGate{}
	for _, id := range cfg.Machines {
		eps = append(eps, sockets.Endpoint{
			Refused:     journalRefusals(eng, refusals, id),
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
		lcfg := localsrv.Config{Owner: ch, Line: cfg.PageSocket.Line, AdoptSIM: cfg.PageSocket.AdoptSIM,
			Paused: func() []localapi.PausedGrant { return pausedGrants(gate) }, AskResume: func(ctx context.Context, id, pause string) (string, error) {
				return askResume(ctx, gate, id, pause)
			}}
		lcfg.RotateAPNet = cfg.PageSocket.RotateAPNet
		lcfg.PlanSignIn = cfg.PageSocket.PlanSignIn
		lcfg.Accounts = cfg.PageSocket.Accounts
		if f := cfg.PageSocket.Forget; f != nil {
			lcfg.ForgetTasks, lcfg.Forget = f.PageTasks, f.PageForget
		}
		if cfg.PageSocket.DescribeRoot != nil {
			lcfg.DescribeRoot, lcfg.Follow = cfg.PageSocket.DescribeRoot, pageFollow(gate)
		}
		ui := localsrv.New(lcfg)
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
	// Shutdown is staged (owner O34). At the stop every op refuses new
	// calls and those in flight return; the sockets, and the owner
	// socket's drain ops (the modem bridge's outbox), stay up while the
	// owner channel drains its texts in flight, then close.
	entry := &stage{}
	for i := range eps {
		for op, h := range eps[i].Ops {
			if i == 0 && slices.Contains(cfg.OwnerDrainOps, op) {
				continue
			}
			eps[i].Ops[op] = entry.wrap(ctx, h)
		}
	}
	sockCtx, endSockets := context.WithCancel(context.WithoutCancel(ctx))
	srv := &sockets.Server{Dir: cfg.SocketDir}
	if err := srv.Start(sockCtx, eps...); err != nil {
		endSockets()
		store.Close()
		return nil, err
	}
	drain := cfg.SendDrain
	if drain <= 0 {
		drain = ownerch.SendDrain
	}
	d := &Daemon{engine: eng, owned: owned, gate: gate, store: store, srv: srv, adm: adm, owner: ch, retry: rt, done: make(chan struct{})}
	if ch != nil {
		go serveOwner(ctx, ch, cfg.Modem != nil)
	}
	go gate.Run(ctx, 0)
	// A restart fences each account an in-flight effect may have landed on
	// (OP-4). Evidence from the executors lifts it: one crash mid-dispatch
	// must not hold the broker account forever. Nothing is re-executed
	// unless a check or the service's idempotency key makes it safe; what
	// stays unclear is parked for the digest and rechecked each round
	// (OP-2).
	go settleLoop(ctx, eng, settleEvery, settleWait, settleMaxWait, gate.Dispatch)
	go func() {
		<-ctx.Done()
		// No page call, guest call or owner text starts now, and the ones
		// in flight have returned; the texts a page call started after its
		// reply (lock, wrong code, sign-in) get up to the drain bound,
		// while the owner socket still hands them to the modem bridge,
		// before the sockets close, Wait returns and agentosd exits (owner
		// O34). With no bridge left on the owner socket (OwnerDrainLive),
		// as when systemd stopped it first, the drain ends at once.
		entry.shut()
		if ch != nil {
			ch.DrainSends(drain, cfg.OwnerDrainLive)
		}
		endSockets()
		srv.Wait()
		store.Close()
		close(d.done)
	}()
	return d, nil
}

// errStopping refuses a call that arrives once agentosd is stopping. The
// modem bridge sends a refused inbound text again (bridgeproto.Retryable),
// so the next start takes it rather than an inbox nobody reads.
const errStopping = sockets.Code("stopping")

// stage holds the ops that end at the stop, before the sockets close.
type stage struct {
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

// wrap serves h until stop or shut, with a context that also ends at
// stop; afterwards it refuses (errStopping). A call that arrives after the
// stop but before shut is refused too: its handler would run with a
// context already ended, and an inbound text it took would go to an inbox
// nobody reads (Security S6 on #1746).
func (s *stage) wrap(stop context.Context, h sockets.Handler) sockets.Handler {
	return func(ctx context.Context, p sockets.Peer, args json.RawMessage) (any, error) {
		s.mu.Lock()
		if s.closed || stop.Err() != nil {
			s.mu.Unlock()
			return nil, errStopping
		}
		s.active.Add(1)
		s.mu.Unlock()
		defer s.active.Done()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(stop, cancel)()
		return h(ctx, p, args)
	}
}

// shut refuses new calls and returns once the calls in flight have
// returned.
func (s *stage) shut() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.active.Wait()
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

// Owned is what the owner commands drive: STOP, RESUME and STATUS.
func (d *Daemon) Owned() control.Engine { return d.owned }

// Admission is the daemon's admission controller, for the VM lifecycle
// manager to admit and release machines through.
func (d *Daemon) Admission() *admission.Controller { return d.adm }

// Wait returns after ctx is done and every socket and the journal are closed.
func (d *Daemon) Wait() { <-d.done }

// pausedGrants are the gate's paused grants as the page shows them
// (W5a-resume).
func pausedGrants(g *grants.Gate) []localapi.PausedGrant {
	var out []localapi.PausedGrant
	for _, p := range g.Paused() {
		out = append(out, localapi.PausedGrant{ID: p.ID, What: p.What, By: p.By, Pause: p.Pause})
	}
	return out
}

// askResume asks to resume a paused grant from the page and says where the
// owner approves it. A grant no longer paused as the page showed it is
// told in fixed words; any other failure stays the socket's fixed code.
func askResume(ctx context.Context, g *grants.Gate, id, pause string) (string, error) {
	if _, err := g.AskResume(ctx, id, pause); errors.Is(err, grants.ErrPauseChanged) {
		return "That grant is no longer paused as this page showed it. Reload the page.", nil
	} else if err != nil {
		return "", err
	}
	return "Asked to resume " + id + ". It shows under Approvals shortly; approve it there with a code from your code generator.", nil
}

// pageFollow submits the page's request to follow a held root: a follow
// intent under a fresh nonce, which the gate asks of the owner on the page
// at the high tier (GR26).
func pageFollow(g *grants.Gate) func(ctx context.Context, name, digest string) (string, error) {
	return func(ctx context.Context, name, digest string) (string, error) {
		in := grants.FollowIntent(followNonce(), name, digest)
		st, err := g.Submit(in)
		if err == nil && st.State == journal.Pending {
			st, err = g.Authorize(ctx, in.ID)
		}
		switch {
		case err != nil:
			return "", err
		case st.State == journal.Pending:
			return FollowAsked, nil
		case st.State == journal.Denied && name != "" && !grants.FollowNameOK(name):
			return FollowRefusedName, nil
		case st.State == journal.Denied:
			return FollowRefused, nil
		}
		return "", errors.New("daemon: follow request " + string(st.State))
	}
}

// followNonce is 16 random bytes in lower-case hex, the form
// grants.FollowID admits (OSS-10w L3).
func followNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return hex.EncodeToString(b)
}

// KernelOwner is the kernel's owner seam as the owner commands call it
// (owner/kernelsock.Owner, #2783). STOP, RESUME, STATUS and RETRY go to it
// as well as to the journal engine while both run actions: STOP narrows
// both, so nothing either holds starts again until RESUME; STATUS counts
// the steps either has not settled; RETRY offers the parked effects and
// steps of both.
type KernelOwner interface {
	Stop(context.Context) error
	Resume(context.Context) error
	Stopped(context.Context) (bool, error)
	SetupOpen(context.Context) (bool, error)
	Status(context.Context) ([]KernelStep, error)
	// Retry returns KernelRefused for the kernel's refusal and
	// ErrKernelLost for an answer that never came.
	Retry(ctx context.Context, plan string, index int) error
}

// KernelStep is a step the kernel's log has not settled
// (owner/kernelsock.Step, which agentosd converts: the control path links
// no socket client): its outcome is unknown, it is parked for the owner's
// RETRY, or its clerk was not reached.
type KernelStep struct {
	Plan   string
	Index  int
	Verb   string
	Clerk  string
	Phase  string // KernelUnknown, KernelParked or KernelUnsent
	Detail string
	Retry  bool  // the owner may RETRY it
	SentAt int64 // when it was first sent (unix ms), which RETRY names
	// What the owner's RETRY tier is judged on (CH-10, CH-11): the step's
	// spend in minor units, whether its verb moves money, its recipient.
	Amount     int64
	Money      bool
	Recipient  string
	PlanStatus string // KernelPlanActive, or how the plan ended
}

// KernelStep's phases and its live plan status.
const (
	KernelUnknown    = "unknown"
	KernelParked     = "parked"
	KernelUnsent     = "unsent"
	KernelPlanActive = "active"
)

// KernelRefused is the kernel's refusal of a call, in its own words.
type KernelRefused struct{ Text string }

func (r KernelRefused) Error() string { return "daemon: the kernel refused: " + r.Text }

// ErrKernelLost is a kernel call whose answer never came: it may or may
// not have taken effect.
var ErrKernelLost = errors.New("daemon: the kernel's answer was lost; it may or may not have taken effect")

// kernelFor bounds each owner command's kernel leg (its call and the
// setupinfo check after a refusal): STOP and RESUME run under the lock
// that orders them (control.Handler mu, owner.Channel stopMu), so a kernel
// that takes a call and never answers must not hold the owner's next STOP
// longer than this. A timeout is a failed STOP or RESUME, the safe way.
var kernelFor = 2 * time.Second

// kernelUnreached is STATUS's note while the kernel's stop cannot be read.
const kernelUnreached = "Part of me is not answering, so a STOP may not have reached it. Reply STOP again later."

// kernelUnlisted is STATUS's note while the kernel's stop reads but its
// unsettled steps do not: the counts may leave some out.
const kernelUnlisted = "Part of me is not answering, so I may have left some actions out of this. Text STATUS again later."

// bothStops is control.Engine over the journal engine and the kernel.
type bothStops struct {
	control.Engine
	k KernelOwner

	mu       sync.Mutex
	unread   bool // the last read of the kernel's stop failed
	unlisted bool // the last read of the kernel's unsettled steps failed
}

// Stop records a STOP in the journal and on the kernel, and reports done
// only when both recorded it (CH-2). A kernel waiting for setup holds no
// plan and runs nothing, so its refusal is not a failure; one that cannot
// be reached is, since it may hold plans it runs again once it answers.
func (b *bothStops) Stop(ctx context.Context) (control.StopReport, error) {
	rep, err := b.Engine.Stop(ctx)
	return rep, errors.Join(err, b.kernel(ctx, b.k.Stop))
}

// Resume lifts the kernel's STOP first: if that fails the journal stays
// stopped too, so RESUME fails whole and is sent again. A RESUME that
// fails after the kernel may have taken it (its answer lost, or the
// journal's write failed) STOPs the kernel again, so "Still stopped." holds
// for both. A STOP only the kernel holds leaves the journal as it is.
func (b *bothStops) Resume() error {
	if err := b.kernel(context.Background(), b.k.Resume); err != nil {
		return errors.Join(err, b.kernel(context.Background(), b.k.Stop))
	}
	if !b.Engine.Stopped() {
		return nil
	}
	if err := b.Engine.Resume(); err != nil {
		return errors.Join(err, b.kernel(context.Background(), b.k.Stop))
	}
	return nil
}

// kernel runs a STOP or RESUME on the kernel; a setup-only kernel's
// refusal is nothing to stop or lift.
func (b *bothStops) kernel(ctx context.Context, f func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, kernelFor)
	defer cancel()
	err := f(ctx)
	if err != nil {
		if open, oerr := b.k.SetupOpen(ctx); oerr == nil && open {
			return nil
		}
	}
	return err
}

// Stopped is true when either is stopped. A kernel whose stop cannot be
// read is never reported stopped: STATUS would tell the owner nothing runs
// while the journal's actions do. STATUS names it instead (note). The
// kernel is read even while the journal is stopped, so a STOP whose kernel
// leg failed is named too (#3077 Security later 2).
func (b *bothStops) Stopped() bool {
	ctx, cancel := context.WithTimeout(context.Background(), kernelFor)
	defer cancel()
	stopped, err := b.k.Stopped(ctx)
	unread := err != nil
	if unread {
		open, oerr := b.k.SetupOpen(ctx)
		stopped, unread = false, oerr != nil || !open
	}
	b.mu.Lock()
	b.unread = unread
	b.mu.Unlock()
	return b.Engine.Stopped() || stopped
}

// List is the journal's actions, then the kernel's unsettled steps as
// STATUS counts them (#2783 b): a step whose outcome is unknown, parked
// or not, may have happened; one whose clerk was not reached waits to run
// while its plan is active, and is left out once the plan has ended, since
// it never acted. A kernel whose steps cannot be read adds none, and
// STATUS names it (note), unless it is waiting for setup, as Stopped
// reads it: a setup-only kernel, or a box with no sealed store, holds none.
func (b *bothStops) List() []control.Status {
	out := b.Engine.List()
	ctx, cancel := context.WithTimeout(context.Background(), kernelFor)
	defer cancel()
	steps, err := b.k.Status(ctx)
	unlisted := err != nil
	if unlisted {
		open, oerr := b.k.SetupOpen(ctx)
		unlisted = oerr != nil || !open
	}
	b.mu.Lock()
	b.unlisted = unlisted
	b.mu.Unlock()
	for _, s := range steps {
		ph := control.Unsettled
		if s.Phase == KernelUnsent {
			if s.PlanStatus != KernelPlanActive {
				continue
			}
			ph = control.Held
		}
		out = append(out, control.Status{ID: s.Plan, Action: s.Verb, Account: s.Clerk, Phase: ph})
	}
	return out
}

// note is STATUS's line while the last read of the kernel's stop, or of
// its unsettled steps, failed; STATUS reads Stopped and List before its
// notes.
func (b *bothStops) note() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.unread:
		return kernelUnreached
	case b.unlisted:
		return kernelUnlisted
	}
	return ""
}
