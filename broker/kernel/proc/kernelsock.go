package proc

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The kernel process's sockets (MIG-4-run slice 3): the frozen seam
// (docs/LANES.md) served to the processes outside it. Each socket admits one
// uid and serves one side's closed table of calls, so the owner side cannot
// meter spend and the model clerk cannot STOP, issue or extend: a call a
// side's table lacks is refused and logs nothing. One connection carries one
// call, {op, args}, answered {result} or {refusal} or {error}. Every call
// runs under the kernel's one lock at the kernel process's own clock, never
// a time the caller gives, so no caller can date a use outside a cap's
// window. A read is encoded under the lock, so what crosses the socket is a
// copy and the caller holds nothing of the live state (#2706 Security).

const maxKernelAnswer = 4 << 20

// Side is one caller's closed table of the seam's calls.
type Side struct {
	name string
	ops  map[string]op
	// procOps are calls the kernel process makes itself, taking its lock
	// only for their kernel steps: the backup calls write to a target
	// outside it, so STOP never waits on one (backup.go).
	procOps map[string]procOp
}

type op func(k *kernel.Kernel, now int64, args json.RawMessage) (any, error)

type procOp func(h *Kernel, now int64, args json.RawMessage) (any, error)

type kernelCall struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

type kernelAnswer struct {
	Result  json.RawMessage `json:"result,omitempty"`
	Refusal *key.Refusal    `json:"refusal,omitempty"`
	Error   string          `json:"error,omitempty"`
	Is      string          `json:"is,omitempty"` // the wireErrors sentinel Error wraps, if any
}

// act is a call that changes the log, made with its decoded arguments.
func act[A any](f func(k *kernel.Kernel, now int64, a A) error) op {
	return func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		return nil, f(k, now, a)
	}
}

// read is a call that changes nothing.
func read[A, R any](f func(s *kernel.State, now int64, a A) R) op {
	return func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		return f(k.State(), now, a), nil
	}
}

// refusal is r as an error, nil when r is.
func refusal(r *key.Refusal) error {
	if r == nil {
		return nil
	}
	return r
}

// ErrArgs is a socket call whose arguments do not decode.
var ErrArgs = errors.New("run: the call's arguments do not decode")

type (
	stepArgs struct {
		Plan  string `json:"plan"`
		Index int    `json:"index"`
	}
	// retryArgs names the dispatch attempt the owner's RETRY was asked
	// about, which the kernel refuses once it moved (CH-10).
	retryArgs struct {
		Plan    string `json:"plan"`
		Index   int    `json:"index"`
		Attempt int    `json:"attempt"`
	}
	issueArgs struct {
		Cosigns []key.Cosign `json:"cosigns"`
		Keys    []key.Key    `json:"keys"`
	}
	lineArgs struct {
		Percent int64        `json:"percent"`
		Cosigns []key.Cosign `json:"cosigns"`
	}
	spentArgs struct {
		Since int64 `json:"since"`
	}
	extendArgs struct {
		Ext  key.Key `json:"ext"`
		Plan string  `json:"plan"`
	}
	poolArgs struct {
		Pool    string                 `json:"pool"`
		Reserve int64                  `json:"reserve,omitempty"`
		Cosigns []key.Cosign           `json:"cosigns,omitempty"`
		Windows []kernel.WindowReading `json:"windows,omitempty"`
	}
	approveArgs struct {
		Task     string              `json:"task"`
		Approval kernel.TaskApproval `json:"approval"`
	}
	spendArgs struct {
		Plan   string       `json:"plan"`
		Seq    uint64       `json:"seq,omitempty"` // the admission a meter settles
		Route  string       `json:"route,omitempty"`
		Amount int64        `json:"amount"`
		Source string       `json:"source,omitempty"`
		Rf     *key.Refusal `json:"refusal,omitempty"`
	}
	enrolled struct {
		Enrolled   []key.Enrollment `json:"enrolled"`
		Unenrolled []key.PublicKey  `json:"unenrolled"`
	}
	taskRead struct {
		Task *kernel.Task `json:"task"` // nil: not live
	}
	// resumeArgs names the STOP a RESUME lifts (kernel.State.Stops, #3078).
	resumeArgs struct {
		Stops uint64 `json:"stops"`
	}
	// changesRead is the key's changes view and the STOPs logged, which a
	// RESUME names.
	changesRead struct {
		key.Changes
		Stops uint64 `json:"stops"`
	}
	targetArgs struct {
		Target kernel.BackupTarget `json:"target"`
		Cosign key.Cosign          `json:"cosign"`
	}
	// certifyArgs is the page's serving public key, PKIX DER.
	certifyArgs struct {
		Key []byte `json:"key"`
	}
	untargetArgs struct {
		Name string `json:"name"`
	}
	grantRead struct {
		From int64 `json:"from"`
		OK   bool  `json:"ok"`
	}
	// labelArgs is a name the owner looks for (kernel.Named).
	labelArgs struct {
		Label string `json:"label"`
	}
	// namedRead is the subjects a name found, and those whose labels could
	// not be read: IDs only, never a label's text.
	namedRead struct {
		Found  []string `json:"found"`
		Unread []string `json:"unread"`
	}
	recallRead struct {
		Recall *kernel.Recall `json:"recall"` // nil: no such subject
	}
	// eraseRead is what an erase reached. Err is set when a step after the
	// logged erase failed: the subject is erased all the same.
	eraseRead struct {
		Confirmation kernel.Confirmation `json:"confirmation"`
		Err          string              `json:"err,omitempty"`
		Is           string              `json:"is,omitempty"` // as kernelAnswer.Is
	}
	// rotateArgs is a rotation an anchor signed: next is the new key's
	// recipient ID, "" when the card is lost.
	rotateArgs struct {
		Next   string     `json:"next"`
		Cosign key.Cosign `json:"cosign"`
	}
	approvalRead struct {
		Approval []byte `json:"approval"`
	}
	// recoveryCardRead is the new recovery key, seal.RecoveryLen bytes.
	recoveryCardRead struct {
		Key []byte `json:"key"`
	}
	// recipientArgs is the new recipient in its wire form and its approval.
	recipientArgs struct {
		Recipient []byte `json:"recipient"`
		Approval  []byte `json:"approval"`
	}
	// edgeArgs is an edge key: the one the link asks about or the owner
	// cuts.
	edgeArgs struct {
		Key ed25519.PublicKey `json:"key"`
	}
	// edgeEnrollArgs is the page step's enrolment: the candidate's key and
	// a hardware key's signature over kernel.EdgeEnrollHash.
	edgeEnrollArgs struct {
		Key    ed25519.PublicKey `json:"key"`
		Cosign key.Cosign        `json:"cosign"`
	}
	// candidateArgs is a hello the link read: the edge's key, the
	// connection's exporter value and the key's signature over HelloMsg.
	candidateArgs struct {
		Key   ed25519.PublicKey `json:"key"`
		Nonce []byte            `json:"nonce"`
		Sig   []byte            `json:"sig"`
	}
	signArgs struct {
		Msg []byte `json:"msg"`
	}
	none struct{}
)

// EdgeKey is what the log says of an edge key now: Live, the core serves
// it; Revoked, it was revoked or replaced in this log, so its hello is
// dropped (EDGE-link-core decision 5).
type EdgeKey struct {
	Live    bool `json:"live"`
	Revoked bool `json:"revoked"`
}

// OwnerSide is the owner side's table (sub B: owner, localui, localsrv,
// control, question, cmd/agentosd): the owner seam's actions and its reads.
var OwnerSide = Side{name: "owner", ops: map[string]op{
	"submit": act(func(k *kernel.Kernel, now int64, p kernel.Plan) error { return k.Submit(now, p) }),
	"retry":  act(func(k *kernel.Kernel, now int64, a retryArgs) error { return k.Retry(now, a.Plan, a.Index, a.Attempt) }),
	"cancel": act(func(k *kernel.Kernel, now int64, a stepArgs) error { return k.Cancel(now, a.Plan) }),
	"undo":   act(func(k *kernel.Kernel, now int64, a stepArgs) error { return k.Undo(now, a.Plan, a.Index) }),
	"enroll": act(func(k *kernel.Kernel, now int64, e key.Enrollment) error { return k.Enroll(now, e) }),
	"unenroll": act(func(k *kernel.Kernel, now int64, u key.Unenrollment) error {
		return k.Unenroll(now, u)
	}),
	"extend":  act(func(k *kernel.Kernel, now int64, a extendArgs) error { return k.Extend(now, a.Ext, a.Plan) }),
	"setline": act(func(k *kernel.Kernel, now int64, a lineArgs) error { return k.SetLine(now, a.Percent, a.Cosigns...) }),
	"reserve": act(func(k *kernel.Kernel, now int64, a poolArgs) error {
		return k.Reserve(now, a.Pool, a.Reserve, a.Cosigns...)
	}),
	"issue": act(func(k *kernel.Kernel, now int64, a issueArgs) error { return k.Issue(now, a.Cosigns, a.Keys...) }),
	"approvetask": act(func(k *kernel.Kernel, now int64, a approveArgs) error {
		return k.ApproveTask(now, a.Task, a.Approval)
	}),
	"approvecode": act(func(k *kernel.Kernel, now int64, a kernel.CodeApproval) error { return k.ApproveCode(now, a) }),
	"revoke":      act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Revoke(now, id) }),
	"pause":       act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Pause(now, id) }),
	"unpause":     act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Unpause(now, id) }),
	"stop":        act(func(k *kernel.Kernel, now int64, _ none) error { return k.Stop(now) }),
	"resume":      act(func(k *kernel.Kernel, now int64, a resumeArgs) error { return k.Resume(now, a.Stops) }),
	"setupinfo": func(k *kernel.Kernel, _ int64, _ json.RawMessage) (any, error) {
		return SetupInfo{Open: k.State().SetupOpen(), Box: k.Box()}, nil
	},

	"status":      read(func(s *kernel.State, _ int64, _ none) []kernel.Unsettled { return s.Status() }),
	"linechanges": read(func(s *kernel.State, _ int64, _ none) int { return s.LineChanges() }),
	"spendheld":   read(func(s *kernel.State, _ int64, _ none) map[string]kernel.SpendHold { return s.SpendHeld }),
	"pools":       read(func(s *kernel.State, now int64, _ none) map[string]kernel.Pool { return s.PoolsAt(now) }),
	"spent":       read(func(s *kernel.State, _ int64, a spentArgs) map[string]int64 { return s.Spent(a.Since) }),
	"anchors":     read(func(s *kernel.State, _ int64, _ none) []key.PublicKey { return s.Anchors }),
	"enrollments": read(func(s *kernel.State, _ int64, _ none) enrolled {
		es, un := s.Enrollments()
		return enrolled{es, un}
	}),
	"changes": read(func(s *kernel.State, _ int64, _ none) changesRead { return changesRead{*s.ChangesView(), s.Stops} }),
	"plan":    read(func(s *kernel.State, _ int64, id string) kernel.PlanView { return s.PlanView(id) }),
	"granted": read(func(s *kernel.State, _ int64, id key.ID) grantRead {
		from, ok := s.Granted(id)
		return grantRead{from, ok}
	}),
	"task": read(func(s *kernel.State, now int64, id string) taskRead {
		if t, ok := s.Task(id, now); ok {
			return taskRead{&t}
		}
		return taskRead{}
	}),
	"untarget": act(func(k *kernel.Kernel, now int64, a untargetArgs) error { return k.Untarget(now, a.Name) }),

	// The edge (HW-15): the page step enrols the candidate the link port
	// logged, on a hardware key's signature, and the owner cuts an edge.
	"edgeenroll": act(func(k *kernel.Kernel, now int64, a edgeEnrollArgs) error { return k.EdgeEnroll(now, a.Key, a.Cosign) }),
	"edgerevoke": act(func(k *kernel.Kernel, now int64, a edgeArgs) error { return k.EdgeRevoke(now, a.Key) }),

	// Erase by name (LOG-4, KRN-forget): IDs, counts and stores cross, never
	// sealed plaintext. No side has a read of content (CH-25).
	"named": func(k *kernel.Kernel, _ int64, raw json.RawMessage) (any, error) {
		var a labelArgs
		if err := json.Unmarshal(raw, &a); err != nil || a.Label == "" || len(a.Label) > MaxLabel {
			return nil, ErrArgs
		}
		found, unread, err := k.Named(a.Label)
		if err != nil {
			return nil, err
		}
		return namedRead{found, unread}, nil
	},
	"recall": read(func(s *kernel.State, _ int64, sub string) recallRead {
		if r, ok := s.Recall(sub); ok {
			return recallRead{&r}
		}
		return recallRead{}
	}),
	"unerased":    read(func(s *kernel.State, _ int64, _ none) []kernel.Unerased { return s.Unerased() }),
	"erasedreads": read(func(s *kernel.State, _ int64, _ none) []kernel.ErasedRead { return s.ErasedReads() }),
}, procOps: map[string]procOp{
	"backuptarget": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var a targetArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		return nil, h.AddBackupTarget(now, a.Target, a.Cosign)
	},
	"backup": func(h *Kernel, now int64, _ json.RawMessage) (any, error) { return h.Backup(now) },
	// erase waits for backup re-seals without the lock (Kernel.Erase).
	"erase": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var sub string
		if err := json.Unmarshal(raw, &sub); err != nil {
			return nil, ErrArgs
		}
		c, err := h.Erase(now, sub)
		if c.Subject == "" {
			return nil, err
		}
		r := eraseRead{Confirmation: c}
		if err != nil {
			r.Err, r.Is = err.Error(), wireIs(err)
		}
		return r, nil
	},
	"backups": func(h *Kernel, _ int64, _ json.RawMessage) (any, error) { return h.Backups() },
	// Recovery-key rotation (REC-4, D-201): the anchor's tap gets a
	// head-signed approval; the recipient switches only on one.
	"recoveryrotate": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var a rotateArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		b, err := h.RecoveryRotate(now, a.Next, a.Cosign)
		if err != nil {
			return nil, err
		}
		return approvalRead{b}, nil
	},
	"recipient": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var a recipientArgs
		if err := json.Unmarshal(raw, &a); err != nil || len(a.Approval) > handoff.MaxApproval {
			return nil, ErrArgs
		}
		return nil, h.SwitchRecipient(now, a.Recipient, a.Approval)
	},
	// The lost-card route (D-201 route B): the key the unlock step made at
	// this boot, for the new card, until the owner confirms it.
	"recoverycard": func(h *Kernel, _ int64, _ json.RawMessage) (any, error) {
		b, err := h.RecoveryCard()
		if err != nil {
			return nil, err
		}
		return recoveryCardRead{b}, nil
	},
	"recoverycarddone": func(h *Kernel, _ int64, _ json.RawMessage) (any, error) {
		h.RecoveryCardDone()
		return nil, nil
	},
	"setup": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var f kernel.FirstAnchors
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, ErrArgs
		}
		return nil, h.Setup(now, f)
	},
	"certify": func(h *Kernel, now int64, raw json.RawMessage) (any, error) {
		var a certifyArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		return h.Certify(now, a.Key)
	},
}}

// MeterSide is the model clerk's table (clerk/model, #2572): the metering
// seam and nothing else.
var MeterSide = Side{name: "meter", ops: map[string]op{
	"admitspend": func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a spendArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		ad, r := k.AdmitSpend(now, a.Plan, a.Amount)
		if r != nil {
			return nil, r
		}
		return ad, nil
	},
	"meter": act(func(k *kernel.Kernel, now int64, a spendArgs) error {
		return k.Meter(now, kernel.Admitted{Plan: a.Plan, Seq: a.Seq}, a.Route, a.Amount, a.Source)
	}),
	"hold":      act(func(k *kernel.Kernel, now int64, a spendArgs) error { return k.Hold(now, a.Plan, a.Rf) }),
	"admitpool": act(func(k *kernel.Kernel, now int64, a poolArgs) error { return refusal(k.AdmitPool(now, a.Pool)) }),
	"readpool": act(func(k *kernel.Kernel, now int64, a poolArgs) error {
		return k.ReadPool(now, a.Pool, a.Windows)
	}),
}}

// LinkSide is agentos-link's table (EDGE-link-core c2b, #3458): the core's
// link key, which never leaves this process, signs the link's TLS
// handshakes; the link asks what the log says of each edge key and reports
// the hellos it reads. Its socket admits the link's uid alone, so a
// candidate the page step can enrol came from the link port and nowhere
// else (decision 8), and no other side has a link call.
var LinkSide = Side{name: "link", ops: map[string]op{
	"edgekey": func(k *kernel.Kernel, _ int64, raw json.RawMessage) (any, error) {
		var a edgeArgs
		// A key of any other length is never live: an empty one would
		// equal no live edge.
		if err := json.Unmarshal(raw, &a); err != nil || len(a.Key) != ed25519.PublicKeySize {
			return nil, ErrArgs
		}
		return EdgeKey{Live: k.LiveEdge().Equal(a.Key), Revoked: k.State().EdgeRevoked(a.Key)}, nil
	},
	"edgecandidate": act(func(k *kernel.Kernel, now int64, a candidateArgs) error {
		return k.EdgeCandidate(now, a.Key, a.Nonce, a.Sig)
	}),
}, procOps: map[string]procOp{
	// The link key is the kernel process's, not the kernel's: these
	// take no lock.
	"linkkey": func(h *Kernel, _ int64, _ json.RawMessage) (any, error) { return h.LinkKey() },
	"linksign": func(h *Kernel, _ int64, raw json.RawMessage) (any, error) {
		var a signArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ErrArgs
		}
		return h.LinkSign(a.Msg)
	},
}}

type (
	// sealArgs is an item for the side's own store: its subject, its
	// class and its plaintext.
	sealArgs struct {
		Subject string `json:"subject"`
		Class   string `json:"class"`
		Data    []byte `json:"data"`
	}
	// readForArgs names an item and the agent session's lineage it is
	// read for (D-169).
	readForArgs struct {
		Hash    kernel.Hash `json:"hash"`
		Lineage string      `json:"lineage"`
	}
)

// ContentSide is one content clerk's table (KRN-content, LOG-4): it opens
// subjects, seals into store, its own, and reads that store's items for an
// agent session's lineage, which the log records first so an erase rewinds
// it (kernel.ReadFor, D-169). Its socket admits that clerk's uid alone,
// never the owner side's, the model clerk's or the link's (cmd/agentos-kernel),
// and no planner reaches a kernel socket, so sealed plaintext crosses to
// the clerk that sealed it and to no one else. Erase stays the owner's.
func ContentSide(store string) Side {
	return Side{name: "content", ops: map[string]op{
		"opensubject": func(k *kernel.Kernel, now int64, _ json.RawMessage) (any, error) {
			return k.OpenSubject(now)
		},
		"seal": func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
			var a sealArgs
			if err := json.Unmarshal(raw, &a); err != nil || len(a.Data) > MaxItem {
				return nil, ErrArgs
			}
			return k.Seal(now, a.Subject, store, a.Class, a.Data)
		},
		"readfor": func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
			var a readForArgs
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, ErrArgs
			}
			// Another store's item reads as no item, whatever else is
			// wrong with the call: the zero hash names no item, so its
			// answer is an unknown item's, and the clerk learns nothing
			// of what other clerks hold (#3560 Security finding 1).
			if in, ok := k.State().ItemStore(a.Hash); ok && in != store {
				a.Hash = kernel.Hash{}
			}
			return k.ReadFor(now, a.Hash, a.Lineage)
		},
	}}
}

// ListenKernel opens one side's socket on the kernel process, admitting only
// that side's uid.
func ListenKernel(path string, uid int) (net.Listener, error) {
	return sockets.ListenPeers(path, uid)
}

// ServeKernel answers side's calls to h on ln until ln closes, each on its
// own connection, so a slow caller never delays STOP; the kernel's lock
// orders them. clock is the kernel process's.
func ServeKernel(ln net.Listener, h *Kernel, side Side, clock func() int64) error {
	return ServeConns(ln, MaxConns, func(conn net.Conn) { serveKernel(conn, h, side, clock) })
}

// MaxConns bounds the calls one socket serves at once. More wait in the
// listener's backlog, holding none of the process's descriptors, so a side
// that floods its own socket cannot starve another side's (KRN-7).
const MaxConns = 16

// ServeConns runs handle on each connection ln accepts, at most n at once,
// until ln closes. Any other accept error (no descriptor free, a connection
// aborted) is waited out, never the end of the socket, so the owner's STOP
// still lands once a flood ends.
func ServeConns(ln net.Listener, n int, handle func(net.Conn)) error {
	slots := make(chan struct{}, n)
	wait := 5 * time.Millisecond
	for {
		slots <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(wait)
			wait = min(2*wait, time.Second)
			continue
		}
		wait = 5 * time.Millisecond
		go func() {
			defer func() { <-slots }()
			handle(conn)
		}()
	}
}

// MaxLabel bounds the name a named call looks for, in bytes.
const MaxLabel = 256

// SetupInfo is what the setup page needs before the owner's keys sign:
// whether setup is still open, and the box's head key they sign over.
type SetupInfo struct {
	Open bool              `json:"open"`
	Box  ed25519.PublicKey `json:"box"`
}

// setupOps are the only calls a kernel with no anchors serves: the setup
// step, what it signs over, STATUS (#2905 open point 2), and the page's
// serving certificate, since setup's passkeys are made on that page (CH-9).
var setupOps = map[string]bool{"owner/setup": true, "owner/setupinfo": true, "owner/status": true, "owner/certify": true}

// ErrSetupOnly refuses every other call until setup has logged the owner's
// hardware keys.
var ErrSetupOnly = errors.New("run: I am waiting for setup; I take only your two hardware keys until then")

func serveKernel(conn net.Conn, h *Kernel, side Side, clock func() int64) {
	ServeOne(conn, func(name string, args json.RawMessage) (out json.RawMessage, err error) {
		f, ok := side.ops[name]
		if p, own := side.procOps[name]; own {
			if err := h.With(func(k *kernel.Kernel) error {
				if len(k.State().Anchors) == 0 && !setupOps[side.name+"/"+name] {
					return ErrSetupOnly
				}
				return nil
			}); err != nil {
				return nil, err
			}
			res, err := p(h, clock(), args)
			if err != nil || res == nil {
				return nil, err
			}
			return json.Marshal(res)
		}
		if !ok {
			return nil, errors.New("run: the " + side.name + " socket has no call " + name)
		}
		err = h.With(func(k *kernel.Kernel) error {
			if len(k.State().Anchors) == 0 && !setupOps[side.name+"/"+name] {
				return ErrSetupOnly
			}
			res, err := f(k, clock(), args)
			if err == nil && res != nil {
				// Encoded under the lock: the caller gets a copy.
				out, err = json.Marshal(res)
			}
			return err
		})
		return out, err
	})
}

// ServeOne answers the one call on conn with handle's result.
func ServeOne(conn net.Conn, handle func(op string, args json.RawMessage) (json.RawMessage, error)) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var in kernelCall
	if json.NewDecoder(io.LimitReader(conn, maxCall)).Decode(&in) != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	var out kernelAnswer
	res, err := handle(in.Op, in.Args)
	var rf *key.Refusal
	switch {
	case err == nil:
		out.Result = res
	case errors.As(err, &rf):
		out.Refusal = rf
		if rf == nil || rf.Code == "" {
			out.Refusal, out.Error = nil, "run: a refusal with no code"
		}
	case err.Error() != "":
		out.Error, out.Is = err.Error(), wireIs(err)
	default:
		// Never an empty answer, which would read as success.
		out.Error = "run: an error with no text"
	}
	b, _ := json.Marshal(out)
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(append(b, '\n'))
}

// ErrLost is a call whose answer never came: it may or may not have taken
// effect. The owner side reads the state the call would change (Changes,
// Plan, Granted, SpendHeld, LineChanges, Pools, Enrollments, Task) before
// acting again; a read can simply be made again.
var ErrLost = errors.New("run: the answer was lost; it may or may not have taken effect")

// ErrUnreachable is a call that was never sent: no process listens on the
// socket, or another uid holds it.
var ErrUnreachable = errors.New("run: the socket could not be reached; nothing was sent")

// ErrTooLarge is a call past what the socket reads (maxCall): it was never
// sent.
var ErrTooLarge = errors.New("run: the call is too large for the socket; nothing was sent")

// wireErrors are the errors a socket's answer names by their text, so the
// caller gets the same value back and errors.Is works across the socket,
// also for an error that wraps one (kernel.ErrRetryRefused with its code):
// that crosses with its own text, naming the sentinel it wraps. Any other
// error crosses as its text alone.
var (
	wireList   []error
	wireErrors = map[string]error{}
)

func init() {
	wireList = []error{
		kernel.ErrDuplicatePlan, kernel.ErrRetryRefused, kernel.ErrNeedsCosign, kernel.ErrLine, kernel.ErrNotEnrolled, kernel.ErrNotParked,
		kernel.ErrNotUnenrolled, kernel.ErrRetryMoved,
		kernel.ErrNotText, kernel.ErrNotAGrant, kernel.ErrLife, kernel.ErrTask, kernel.ErrTaskOpen, kernel.ErrTaskApproval,
		kernel.ErrBroken, kernel.ErrNotAdmitted, key.ErrMalformed, key.ErrWrongOwner, key.ErrBadSig, key.ErrLoosens, key.ErrNotHolder,
		key.ErrUnknownKind, key.ErrUncaveated, ErrArgs, kernel.ErrSetupClosed, kernel.ErrSetupKeys, ErrSetupOnly,
		kernel.ErrReserveSig, kernel.ErrTargetSig, kernel.ErrTarget, kernel.ErrTargetExists, kernel.ErrNoTarget,
		kernel.ErrContentClosed, kernel.ErrSubject, kernel.ErrErased, kernel.ErrLabel,
		kernel.ErrStore, kernel.ErrSubjectKey, kernel.ErrItem, kernel.ErrLineage,
		kernel.ErrRotateSig, kernel.ErrRotate, ErrApprovalStale, ErrNotApproved, handoff.ErrApproval, handoff.ErrApprovalExpired, ErrNoRecoveryCard,
		kernel.ErrEdgeKey, kernel.ErrEdgeSig, kernel.ErrEdgeRevoked, kernel.ErrEdgeCandidate, kernel.ErrEdgeHello, kernel.ErrEdgeBusy, kernel.ErrEdgeLive,
		ErrNoLinkKey, ErrLinkSign, kernel.ErrNoChecker, kernel.ErrCodeApproval,
		ErrNoRecipient, ErrNoAuthority, ErrPageRestore, pageca.ErrKey, pageca.ErrExpired, ErrBackupsOff, ErrNoBackupTarget, ErrTargetInKernel, ErrTargetNotDir,
	}
	for _, e := range wireList {
		wireErrors[e.Error()] = e
	}
}

// WireErrors adds sentinels that cross a socket by their text, as the ones
// above do. The clerks' processes (broker/clerk/run) add their own, which
// this package cannot name without linking their code (#2892). Call it only
// from an init function, before any socket is served or called.
func WireErrors(errs ...error) {
	for _, e := range errs {
		wireList = append(wireList, e)
		wireErrors[e.Error()] = e
	}
}

// wireIs is the text of the first wireErrors sentinel err is, "" when none:
// for an errors.Join of two, the first in wireList.
func wireIs(err error) string {
	for _, e := range wireList {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ""
}

// fromWire is the error a socket's answer names by its text and the
// sentinel it wraps.
func fromWire(text, is string) error {
	if e, ok := wireErrors[text]; ok {
		return e
	}
	if e, ok := wireErrors[is]; ok {
		return wrapped{text, e}
	}
	return errors.New(text)
}

// wrapped is an error that crossed a socket wrapping a wireErrors sentinel.
type wrapped struct {
	text string
	is   error
}

func (w wrapped) Error() string { return w.text }
func (w wrapped) Unwrap() error { return w.is }

// Conn is how a process reaches a socket of the kernel's process or of the
// model clerk's.
type Conn struct {
	Socket  string
	UID     int           // the serving process's uid: the only peer it calls
	Timeout time.Duration // for the whole call; 0 is one minute
}

// Call makes one call; out, when not nil, receives its result.
func (c Conn) Call(op string, args, out any) error {
	b, err := json.Marshal(kernelCall{op, mustRaw(args)})
	if err != nil {
		return err
	}
	if len(b)+1 > maxCall {
		// The server would read only part of it, and the call would
		// read as lost though it was never taken (#2742 item 9).
		return ErrTooLarge
	}
	d := c.Timeout
	if d == 0 {
		d = time.Minute
	}
	conn, err := net.DialTimeout("unix", c.Socket, 10*time.Second)
	if err != nil {
		return ErrUnreachable
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != c.UID {
		return ErrUnreachable
	}
	conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrLost
	}
	var a kernelAnswer
	if json.NewDecoder(io.LimitReader(conn, maxKernelAnswer)).Decode(&a) != nil {
		return ErrLost
	}
	switch {
	case a.Refusal != nil:
		return a.Refusal
	case a.Error != "":
		return fromWire(a.Error, a.Is)
	case out != nil:
		return json.Unmarshal(a.Result, out)
	}
	return nil
}

func mustRaw(v any) json.RawMessage {
	if v == nil {
		v = none{}
	}
	b, _ := json.Marshal(v)
	return b
}

// asRefusal is err as the *key.Refusal it carries, nil when it carries none
// (a lost answer or a broken socket refuses with CBroken, so no metered call
// starts on a ledger it could not reach).
func asRefusal(err error) *key.Refusal {
	if err == nil {
		return nil
	}
	var rf *key.Refusal
	if errors.As(err, &rf) {
		return rf
	}
	return &key.Refusal{Code: kernel.CBroken, Detail: err.Error()}
}

// Owner is the owner seam over the kernel process's owner socket.
type Owner struct{ Conn }

func (o Owner) Submit(p kernel.Plan) error { return o.Call("submit", p, nil) }
func (o Owner) Retry(plan string, index, attempt int) error {
	return o.Call("retry", retryArgs{plan, index, attempt}, nil)
}
func (o Owner) Cancel(plan string) error { return o.Call("cancel", stepArgs{Plan: plan}, nil) }
func (o Owner) Undo(plan string, index int) error {
	return o.Call("undo", stepArgs{plan, index}, nil)
}
func (o Owner) Enroll(e key.Enrollment) error { return o.Call("enroll", e, nil) }
func (o Owner) Unenroll(u key.Unenrollment) error {
	return o.Call("unenroll", u, nil)
}
func (o Owner) Extend(ext key.Key, plan string) error {
	return o.Call("extend", extendArgs{ext, plan}, nil)
}
func (o Owner) SetLine(percent int64, cos ...key.Cosign) error {
	return o.Call("setline", lineArgs{percent, cos}, nil)
}

// Reserve sets what is kept of pool for the owner. A lowering needs a live
// passkey's cosign over kernel.ReserveHash, else kernel.ErrReserveSig, and a
// big one a second, one an anchor, else kernel.ErrNeedsCosign (RES-5a).
func (o Owner) Reserve(pool string, reserve int64, cos ...key.Cosign) error {
	return o.Call("reserve", poolArgs{Pool: pool, Reserve: reserve, Cosigns: cos}, nil)
}
func (o Owner) Issue(cos []key.Cosign, keys ...key.Key) error {
	return o.Call("issue", issueArgs{cos, keys}, nil)
}
func (o Owner) ApproveTask(id string, a kernel.TaskApproval) error {
	return o.Call("approvetask", approveArgs{id, a}, nil)
}
func (o Owner) ApproveCode(a kernel.CodeApproval) error { return o.Call("approvecode", a, nil) }
func (o Owner) Revoke(id key.ID) error                  { return o.Call("revoke", id, nil) }
func (o Owner) Pause(id key.ID) error                   { return o.Call("pause", id, nil) }
func (o Owner) Unpause(id key.ID) error                 { return o.Call("unpause", id, nil) }
func (o Owner) Stop() error                             { return o.Call("stop", nil, nil) }

// Resume lifts the STOP whose count it names (Changes's stops).
func (o Owner) Resume(stops uint64) error { return o.Call("resume", resumeArgs{stops}, nil) }

// Setup logs the owner's first hardware keys on a setup-only kernel.
func (o Owner) Setup(f kernel.FirstAnchors) error { return o.Call("setup", f, nil) }

// SetupInfo reads whether setup is open and the box key it signs over.
func (o Owner) SetupInfo() (i SetupInfo, err error) { err = o.Call("setupinfo", nil, &i); return }

func (o Owner) Status() (u []kernel.Unsettled, err error) { err = o.Call("status", nil, &u); return }
func (o Owner) LineChanges() (n int, err error)           { err = o.Call("linechanges", nil, &n); return }
func (o Owner) SpendHeld() (m map[string]kernel.SpendHold, err error) {
	err = o.Call("spendheld", nil, &m)
	return
}

// Pools is every pool as it stands now: its windows, the live reserve, a
// lowering still in its hold and when it goes live, and the change count a
// lowering signs.
func (o Owner) Pools() (m map[string]kernel.Pool, err error) { err = o.Call("pools", nil, &m); return }

// Spent is metered spend per route since a time, for the last two days only.
func (o Owner) Spent(since int64) (m map[string]int64, err error) {
	err = o.Call("spent", spentArgs{since}, &m)
	return
}

// Anchors is the owner's hardware keys as setup logged them, in order: the
// owner side lists them and finds which one signed an enrollment (#2779a).
func (o Owner) Anchors() (a []key.PublicKey, err error) { err = o.Call("anchors", nil, &a); return }

func (o Owner) Enrollments() ([]key.Enrollment, []key.PublicKey, error) {
	var e enrolled
	err := o.Call("enrollments", nil, &e)
	return e.Enrolled, e.Unenrolled, err
}

// Changes is the revocations, pauses and STOP in force.
func (o Owner) Changes() (c key.Changes, err error) { err = o.Call("changes", nil, &c); return }

// Plan is plan id's view: its status, a rejection's code and its steps'
// results (kernel.PlanView); ok is false when the log has no such plan.
func (o Owner) Plan(id string) (v kernel.PlanView, ok bool, err error) {
	err = o.Call("plan", id, &v)
	return v, v.Status != "", err
}

// Granted is when key id's grant is live from, if it is granted.
func (o Owner) Granted(id key.ID) (from int64, ok bool, err error) {
	var r grantRead
	err = o.Call("granted", id, &r)
	return r.From, r.OK, err
}

// Task is task id while it is live on the kernel's clock.
func (o Owner) Task(id string) (kernel.Task, bool, error) {
	var t taskRead
	if err := o.Call("task", id, &t); err != nil || t.Task == nil {
		return kernel.Task{}, false, err
	}
	return *t.Task, true, nil
}

// BackupTarget adds a backup destination on an anchor's signature over
// kernel.BackupTargetHash.
func (o Owner) BackupTarget(t kernel.BackupTarget, c key.Cosign) error {
	return o.Call("backuptarget", targetArgs{t, c}, nil)
}

// EdgeEnroll makes edge, the candidate the link port logged, the live edge
// on a hardware key's signature c over kernel.EdgeEnrollHash.
func (o Owner) EdgeEnroll(edge ed25519.PublicKey, c key.Cosign) error {
	return o.Call("edgeenroll", edgeEnrollArgs{edge, c}, nil)
}

// EdgeRevoke cuts edge for good, with no replacement.
func (o Owner) EdgeRevoke(edge ed25519.PublicKey) error {
	return o.Call("edgerevoke", edgeArgs{edge}, nil)
}

// Untarget stops new backups to a destination; its backups keep their
// erase reach.
func (o Owner) Untarget(name string) error { return o.Call("untarget", untargetArgs{name}, nil) }

// Backup takes one backup now to every current destination.
func (o Owner) Backup() (t []Taken, err error) { err = o.Call("backup", nil, &t); return }

// Backups is the recipient's ID, every destination and every kept backup.
func (o Owner) Backups() (v BackupsView, err error) { err = o.Call("backups", nil, &v); return }

// RecoveryRotate asks for a recovery-key approval on an anchor's signature
// c over kernel.RecoveryRotateHash(old, next), old the recipient the
// kernel holds (Backups' Recipient): next is the new key's recipient ID,
// or "" when the card is lost. The approval is handoff.Approval's form.
func (o Owner) RecoveryRotate(next string, c key.Cosign) ([]byte, error) {
	var r approvalRead
	err := o.Call("recoveryrotate", rotateArgs{next, c}, &r)
	return r.Approval, err
}

// SwitchRecipient makes r, in its wire form, the backup recipient, on the
// card-route approval RecoveryRotate gave for it.
func (o Owner) SwitchRecipient(r, approval []byte) error {
	return o.Call("recipient", recipientArgs{r, approval}, nil)
}

// RecoveryCard is the recovery key the unlock step made at this boot on
// the lost-card route, for the new card; ErrNoRecoveryCard once confirmed.
func (o Owner) RecoveryCard() ([]byte, error) {
	var r recoveryCardRead
	err := o.Call("recoverycard", nil, &r)
	return r.Key, err
}

// RecoveryCardDone wipes it, once the owner has confirmed the card.
func (o Owner) RecoveryCardDone() error { return o.Call("recoverycarddone", nil, nil) }

// Certify signs the page's serving key, PKIX DER (Kernel.Certify).
func (o Owner) Certify(pub []byte) (c Certified, err error) {
	err = o.Call("certify", certifyArgs{pub}, &c)
	return
}

// Named is the live subjects a label reads as (kernel.Named): those found,
// and those whose labels could not be read. A blank label is
// kernel.ErrLabel. Invalid UTF-8 is ErrArgs here, since JSON would carry it
// as U+FFFD and match a label the owner did not type (LOG-4).
func (o Owner) Named(label string) (found, unread []string, err error) {
	if !utf8.ValidString(label) {
		return nil, nil, ErrArgs
	}
	var r namedRead
	err = o.Call("named", labelArgs{label}, &r)
	return r.Found, r.Unread, err
}

// Recall is what the box knows of subject; ok is false when it has none.
func (o Owner) Recall(subject string) (kernel.Recall, bool, error) {
	var r recallRead
	if err := o.Call("recall", subject, &r); err != nil || r.Recall == nil {
		return kernel.Recall{}, false, err
	}
	return *r.Recall, true, nil
}

// Erase erases subject. A Confirmation with its Subject set means the
// erase is logged, even with an error: a step after it failed, and Tick
// retries it.
func (o Owner) Erase(subject string) (kernel.Confirmation, error) {
	var r eraseRead
	if err := o.Call("erase", subject, &r); err != nil {
		return kernel.Confirmation{}, err
	}
	if r.Err == "" {
		return r.Confirmation, nil
	}
	return r.Confirmation, fromWire(r.Err, r.Is)
}

// Unerased is every erase a store or the key table has not confirmed.
func (o Owner) Unerased() (u []kernel.Unerased, err error) { err = o.Call("unerased", nil, &u); return }

// ErasedReads is each lineage that read an erased subject's item, at its
// first read: what agentosd rewinds (D-169).
func (o Owner) ErasedReads() (r []kernel.ErasedRead, err error) {
	err = o.Call("erasedreads", nil, &r)
	return
}

// Meter is the metering seam over the kernel process's meter socket: a
// model.Ledger for the model clerk's process. The now each method takes is
// ignored, since the kernel's clock decides. A lost Meter answer is retried
// by the clerk (model.Clerk owes it); the kernel settles an admission once,
// so a retry of one that landed is refused (kernel.ErrNotAdmitted) and the
// clerk counts it recorded.
type Meter struct{ Conn }

func (m Meter) AdmitSpend(_ int64, plan string, amount int64) (kernel.Admitted, *key.Refusal) {
	var a kernel.Admitted
	if r := asRefusal(m.Call("admitspend", spendArgs{Plan: plan, Amount: amount}, &a)); r != nil {
		return kernel.Admitted{}, r
	}
	return a, nil
}
func (m Meter) Meter(_ int64, a kernel.Admitted, route string, amount int64, source string) error {
	return m.Call("meter", spendArgs{Plan: a.Plan, Seq: a.Seq, Route: route, Amount: amount, Source: source}, nil)
}
func (m Meter) Hold(_ int64, plan string, rf *key.Refusal) error {
	return m.Call("hold", spendArgs{Plan: plan, Rf: rf}, nil)
}
func (m Meter) AdmitPool(_ int64, pool string) *key.Refusal {
	return asRefusal(m.Call("admitpool", poolArgs{Pool: pool}, nil))
}
func (m Meter) ReadPool(_ int64, pool string, windows []kernel.WindowReading) error {
	return m.Call("readpool", poolArgs{Pool: pool, Windows: windows}, nil)
}

// Content is a content clerk's seam over its content socket (ContentSide).
type Content struct{ Conn }

// OpenSubject opens a new subject and returns its ID.
func (c Content) OpenSubject() (sub string, err error) {
	err = c.Call("opensubject", nil, &sub)
	return
}

// Seal seals data as an item of subject, of class, in the clerk's own
// store, and returns its hash.
func (c Content) Seal(subject, class string, data []byte) (h kernel.Hash, err error) {
	if len(data) > MaxItem {
		return h, ErrArgs
	}
	err = c.Call("seal", sealArgs{subject, class, data}, &h)
	return
}

// ReadFor opens the item named h, of the clerk's own store, for the agent
// session of lineage; the kernel logs the read first.
func (c Content) ReadFor(h kernel.Hash, lineage string) (data []byte, err error) {
	err = c.Call("readfor", readForArgs{h, lineage}, &data)
	return
}
