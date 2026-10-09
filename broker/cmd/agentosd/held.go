package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Held mode: what agentosd runs instead of starting while a restore the
// forget log's check held is pending (W3-forget-b1-7; security C3, #409
// UX U2). Like setup mode, it opens nothing on the restored tree (no
// recall, machines, learning or owner-channel state) and serves only
// owner.sock, with the daemon's peer checks: the modem bridge's ops, and
// "message" where the daemon would serve it. It texts the owner what holds
// the restore, takes their answer from the owner's number alone, one reply
// at a time, and ends once the answer releases the restore.
const (
	// heldReplyMax: a longer reply is no choice (#436 L3 point 8); a
	// choice is one letter, or "reply" and one.
	heldReplyMax = 64
	// heldFallback is the notice when the marker's does not fit a text.
	heldFallback = "Restore on hold: your agent stays stopped. Nothing can be done until an update."
	heldIdle     = 60 * time.Second // the daemon's owner socket's
	heldResend   = 10 * time.Second
)

// heldLink is the modem bridge's end in agentosd (modemlink.Link).
type heldLink interface {
	Send(to, text string) error
	Inbox() <-chan modem.SMS
	Ops() map[string]sockets.Handler
}

type heldMode struct {
	Learn            string // the learning plane's directory, which holds the marker
	Dir              string // socket directory
	Owner            string
	PeerUID, PeerGID *int     // the modem bridge's, as on the daemon's owner socket
	Link             heldLink // nil without -modem-bridge
	Message          bool     // serve "message": no bridge, or -owner-message
	Retry            time.Duration
	Logf             func(string, ...any)
}

// heldOwner is the number a held box texts: -owner, else the one setup's
// finished record names (setup mode's own source).
func heldOwner(flagOwner string, rec localsrv.RecordStore) (string, error) {
	if flagOwner != "" {
		return flagOwner, nil
	}
	r, err := rec.Load()
	if err != nil {
		return "", err
	}
	if !r.Finished {
		return "", errors.New("no -owner and setup never finished: no one to text")
	}
	return r.Owner, nil
}

// run serves the held mode until the owner's answer releases the restore
// (nil) or ctx ends (its error).
func (m heldMode) run(ctx context.Context) error {
	if m.Retry == 0 {
		m.Retry = heldResend
	}
	h := &heldReplies{dir: m.Learn, logf: m.Logf}
	released := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	ep := sockets.Endpoint{Name: daemon.OwnerSocket, Peer: sockets.Peer{Kind: "owner"}, PeerUID: m.PeerUID, PeerGID: m.PeerGID,
		MaxConns: 8, IdleTimeout: heldIdle, Ops: map[string]sockets.Handler{}}
	// up hears the bridge report the owner line usable. The first text
	// waits for it: a send before it fails as down and counts as a missed
	// text, which the link would then report to the owner.
	up := make(chan struct{}, 1)
	if m.Link != nil {
		ep.HangupOps = map[string]bool{}
		for op, hd := range m.Link.Ops() {
			if op != "message" {
				ep.Ops[op], ep.HangupOps[op] = hd, true
			}
		}
		if state := ep.Ops[bridgeproto.OpState]; state != nil {
			ep.Ops[bridgeproto.OpState] = func(ctx context.Context, p sockets.Peer, args json.RawMessage) (any, error) {
				res, err := state(ctx, p, args)
				var st bridgeproto.State
				if err == nil && json.Unmarshal(args, &st) == nil && st.OwnerLine == bridgeproto.StateOK {
					select {
					case up <- struct{}{}:
					default:
					}
				}
				return res, err
			}
		}
	}
	if m.Message {
		ep.Ops["message"] = func(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			var msg struct{ From, Text string }
			if err := json.Unmarshal(args, &msg); err != nil {
				return nil, sockets.Code("bad message")
			}
			var replies []string
			if msg.From == m.Owner {
				text, rel := h.reply(msg.Text)
				if text != "" {
					replies = append(replies, text)
				}
				if rel {
					release()
				}
			}
			return map[string][]string{"replies": replies}, nil
		}
	}
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	srv := &sockets.Server{Dir: m.Dir}
	if err := srv.Start(sctx, ep); err != nil {
		return err
	}
	var wg sync.WaitGroup
	if m.Link != nil {
		wg.Add(2)
		go func() { defer wg.Done(); m.open(sctx, h, up) }()
		go func() { defer wg.Done(); m.answer(sctx, h, release) }()
	}
	var err error
	select {
	case <-released:
	case <-ctx.Done():
		err = ctx.Err()
	}
	stop()
	wg.Wait()
	srv.Wait()
	return err
}

// open sends the first text once the bridge reports the owner line
// usable, and again after Retry and the next report if it did not go.
func (m heldMode) open(ctx context.Context, h *heldReplies, up <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-up:
		}
		text := h.opening()
		if text == "" || m.Link.Send(m.Owner, text) == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.Retry):
		}
	}
}

// answer answers the owner line's texts until one releases the restore.
// The link's inbox holds only the owner's (modemlink checks the sender);
// the check here keeps it so whatever fills the inbox.
func (m heldMode) answer(ctx context.Context, h *heldReplies, release func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case sms := <-m.Link.Inbox():
			if sms.Alphanumeric || sms.From != m.Owner {
				continue
			}
			text, rel := h.reply(sms.Text)
			if text != "" {
				if err := m.Link.Send(m.Owner, text); err != nil {
					m.logf("held restore: text to the owner: %v", err)
				}
			}
			if rel {
				release()
				return
			}
		}
	}
}

func (m heldMode) logf(format string, args ...any) {
	if m.Logf != nil {
		m.Logf(format, args...)
	}
}

// heldReplies takes the owner's replies one at a time (#436 L3 point 5):
// answerHeld reads the question, then writes it.
type heldReplies struct {
	mu       sync.Mutex
	dir      string
	logf     func(string, ...any)
	released bool
	// broken: an answer could not be saved. The restore stays held, and
	// no later answer counts on this start, so a disk that fails writes
	// cannot give more than one guess.
	broken bool
}

// opening is the first text: the question, the wrong-answer text once the
// question is closed, or the marker's notice when there is no question.
func (h *heldReplies) opening() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return ""
	}
	if h.broken {
		return heldNotice(h.dir)
	}
	text, ok, err := heldText(h.dir)
	if err != nil || !ok {
		return heldNotice(h.dir)
	}
	return text
}

// reply answers one of the owner's texts; released reports the restore
// let go. A control word (STOP, STATUS) is no choice either: the agent is
// not running, so the held text is the answer to both.
func (h *heldReplies) reply(msg string) (text string, released bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return "", true
	}
	if h.broken {
		return heldNotice(h.dir), false
	}
	if len(msg) > heldReplyMax {
		msg = ""
	}
	text, released, err := answerHeld(h.dir, msg)
	switch {
	case released:
		if err != nil {
			h.log("held restore: released, but the question stays: %v", err)
		}
		h.released = true
		return text, true
	case errors.Is(err, errNoQuestion) || errors.Is(err, errBadQuestion):
		return heldNotice(h.dir), false
	case err != nil:
		h.log("held restore: the owner's answer was not saved: %v", err)
		h.broken = true
		return heldNotice(h.dir), false
	}
	return text, false
}

func (h *heldReplies) log(format string, args ...any) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}

// heldNotice is the marker's notice (recovery.PendingNotice), or
// heldFallback when it does not read or does not fit a text (CH-12:
// GSM-7, at most three segments).
func heldNotice(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, forgetLogFile+".pending"))
	if err != nil {
		return heldFallback
	}
	_, notice, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	notice = strings.TrimSpace(notice)
	if n, gsm7 := modem.Segments(notice); notice == "" || !gsm7 || n > 3 {
		return heldFallback
	}
	return notice
}
