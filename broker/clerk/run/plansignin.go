package run

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// The owner's plan sign-in and the plan route's owner calls, on the model
// clerk process's owner socket (MIG-4-plan-login-c, #3104, CLK-7, PLN-5).
// planbegin starts the provider CLI's device-code sign-in in a sandbox of
// the guest host's and returns the provider's page and the code the CLI
// printed; planstate reads the route; planresume is the owner's PLAN <plan>
// ON after a refused login; planremove drops the login. The sign-in CLI is
// a sign-in guest of the plan login clerk (plan.Login.BeginSignIn), so its
// only way out is its own endpoint in this process (ServePlan), and the
// login it gets is placeholders. Success is the plan login clerk's record
// that this guest's code exchange committed the login (plan.Login.SignedIn):
// a login stored before, the CLI's exit status and anything it prints do not
// count.

// SignInWorkers is the guest host's (#2780(b)): it runs the plan CLI's
// device-code sign-in.
type SignInWorkers interface {
	// Start runs the sign-in CLI as guest in a fresh sandbox whose only
	// route out is guest's plan endpoint in this process (ServePlan). It
	// returns once ctx ends.
	Start(ctx context.Context, guest string) (SignInWorker, error)
}

// SignInWorker is one running sign-in CLI.
type SignInWorker interface {
	// Read returns what the CLI has printed so far and whether it has
	// exited, and returns once ctx ends. Its text is the guest's: only the
	// code is taken from it.
	Read(ctx context.Context) (printed string, exited bool)
	// Stop destroys the sandbox.
	Stop()
}

// SignInPrompt is how the plan's sign-in CLI shows its link and code.
type SignInPrompt struct {
	// Links are the links the CLI may print before its code, the
	// endpoint's own included. The owner is shown Page, never what was
	// printed.
	Links []string
	Page  string
	// From is the provider, for the page's "This code is from <From>, not
	// from your code generator" (§12.1 step 6).
	From string
}

// CodexSignIn is Codex CLI 0.162.1's device-code sign-in, its issuer
// pointed at the guest's endpoint (#809).
func CodexSignIn() SignInPrompt {
	return SignInPrompt{
		Links: []string{"http://127.0.0.1:18432/codex/device", "https://auth.openai.com/codex/device"},
		Page:  "https://auth.openai.com/codex/device",
		From:  "OpenAI",
	}
}

// SignInTimes bound a sign-in: Link is how long the CLI has to print its
// link and code, Wall how long the owner has to approve it (the code's own
// life), and Poll how often the worker is read. Zero is the default. The
// owner side's call timeout must exceed Link.
type SignInTimes struct{ Poll, Link, Wall time.Duration }

func (t SignInTimes) orDefault() SignInTimes {
	if t.Poll <= 0 {
		t.Poll = time.Second
	}
	if t.Link <= 0 {
		t.Link = 45 * time.Second
	}
	if t.Wall <= 0 {
		t.Wall = 15 * time.Minute
	}
	return t
}

// The owner calls' details, carrying no value (CLK-4).
const (
	DPlanNotAllowed = "plan-not-allowed" // the provider's terms bar the plan route: the API key route only
	DPlanConsent    = "plan-consent"     // an unconfirmed route without the owner's consent; nothing sent
	DSignInBusy     = "signin-busy"      // a sign-in already waits for the owner, or planremove runs
	DSignInCode     = "signin-code"      // the CLI printed another code than the provider gave it
	DSignInFailed   = "signin-failed"    // the CLI did not start, or ended without the login
	DSignInTimedOut = "signin-timed-out" // no code in time, or the owner did not approve it in time
	DSignInStopped  = "signin-stopped"   // planremove ended the sign-in
	DSignedIn       = "signedin"         // this sign-in committed the login
	DRequalify      = "requalify"        // only a release reopens the route
)

// signInCode is a device code as the provider prints it.
var signInCode = regexp.MustCompile(`\A[A-Z0-9-]{4,16}\z`)

// ansi is a terminal escape sequence, stripped before the output is read.
var ansi = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")

// maxPrinted bounds the CLI's output the clerk reads.
const maxPrinted = 64 << 10

// Code reads the code from what the CLI printed: the first code-shaped
// token after the first of p's links. ok is false when either is missing.
func (p SignInPrompt) Code(printed string) (code string, ok bool) {
	if len(printed) > maxPrinted {
		printed = printed[:maxPrinted]
	}
	toks := strings.Fields(ansi.ReplaceAllString(printed, ""))
	for i, t := range toks {
		if !slices.Contains(p.Links, t) {
			continue
		}
		for _, c := range toks[i+1:] {
			if signInCode.MatchString(c) {
				return c, true
			}
		}
		return "", false
	}
	return "", false
}

// PlanHost is the plan route's owner side in the model clerk's process.
type PlanHost struct {
	Login *plan.Login
	// APIs are the clerk's API-key routes, whose keys the owner side sets
	// on the same socket (MIG-4-exit m1); nil serves no key call.
	APIs    *model.APIs
	Prompt  SignInPrompt
	Workers SignInWorkers
	Times   SignInTimes

	mu       sync.Mutex
	cur      *planSignIn
	removing int    // Removes running: a Begin waits them out (DSignInBusy)
	last     string // how the last sign-in ended, a D* detail
}

// planSignIn is the sign-in that waits for the owner.
type planSignIn struct {
	guest, code string
	cancel      context.CancelFunc
	done        chan struct{}
}

// PlanState is the route as the owner's page shows it.
type PlanState struct {
	Mode     plan.Mode `json:"mode"`
	SignedIn bool      `json:"signedIn"` // a login is stored
	Stopped  string    `json:"stopped"`  // why the route is down, or ""
	// While a sign-in waits for the owner: the provider's page, its code
	// and whom the code is from.
	Signing bool   `json:"signing"`
	Page    string `json:"page,omitempty"`
	Code    string `json:"code,omitempty"`
	From    string `json:"from,omitempty"`
	// Last is how the last sign-in ended: DSignedIn, a DSignIn* detail,
	// or "".
	Last string `json:"last,omitempty"`
}

// PlanBegun is planbegin's answer: the page and code, or a detail.
type PlanBegun struct {
	Page   string `json:"page,omitempty"`
	Code   string `json:"code,omitempty"`
	From   string `json:"from,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func signInGuest() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "signin-" + hex.EncodeToString(b)
}

// Begin starts a sign-in and returns the provider's page and the CLI's
// code once it has printed them, within Times.Link. The code is shown only
// if it is the user code the plan login clerk forwarded to this sign-in's
// guest (plan.Login.UserCode). The CLI then waits for the owner, past this
// call, until it commits the login, exits, Wall passes or Remove ends it;
// its sandbox is destroyed on every path.
func (h *PlanHost) Begin(ctx context.Context) PlanBegun {
	if h.Login.Mode() == plan.NotAllowed {
		return PlanBegun{Detail: DPlanNotAllowed}
	}
	if s := h.Login.Stopped(); s == plan.StopUnswappable {
		return PlanBegun{Detail: plan.DStopped + " " + s}
	}
	h.mu.Lock()
	if h.cur != nil || h.removing > 0 {
		h.mu.Unlock()
		return PlanBegun{Detail: DSignInBusy}
	}
	bg, cancel := context.WithCancel(context.Background())
	s := &planSignIn{guest: signInGuest(), cancel: cancel, done: make(chan struct{})}
	h.cur = s
	h.mu.Unlock()

	t := h.Times.orDefault()
	// The CLI's start and its link are bounded by Link and end with the
	// sign-in, whatever ctx is.
	lctx, lcancel := context.WithTimeout(bg, t.Link)
	defer lcancel()
	defer context.AfterFunc(ctx, lcancel)()
	var w SignInWorker
	var code string
	detail := DSignInFailed
	err := h.Login.BeginSignIn(s.guest)
	switch {
	case errors.Is(err, plan.ErrStopped):
		detail = plan.DStopped + " " + plan.StopUnswappable
	case err != nil:
	default:
		w, err = h.Workers.Start(lctx, s.guest)
		switch {
		case err == nil && w != nil:
			code, detail = h.awaitCode(lctx, bg, w, t)
		case lctx.Err() != nil:
			detail = DSignInTimedOut
		}
	}
	if code != "" && code != h.Login.UserCode(s.guest) {
		code, detail = "", DSignInCode
	}
	h.mu.Lock()
	if bg.Err() != nil {
		// Remove ended the sign-in: its code is not shown.
		code, detail = "", DSignInStopped
	}
	s.code = code
	h.mu.Unlock()
	if code == "" {
		if w != nil {
			w.Stop()
		}
		h.end(s, detail)
		return PlanBegun{Detail: detail}
	}
	go h.await(bg, s, w, t)
	return PlanBegun{Page: h.Prompt.Page, Code: code, From: h.Prompt.From}
}

// awaitCode reads the CLI's output until it shows its link and code, the
// CLI exits, or ctx, bounded by t.Link, ends.
func (h *PlanHost) awaitCode(ctx, bg context.Context, w SignInWorker, t SignInTimes) (string, string) {
	for {
		printed, exited := w.Read(ctx)
		if code, ok := h.Prompt.Code(printed); ok {
			return code, ""
		}
		if exited {
			return "", DSignInFailed
		}
		select {
		case <-ctx.Done():
			if bg.Err() != nil {
				return "", DSignInStopped
			}
			return "", DSignInTimedOut
		case <-time.After(t.Poll):
		}
	}
}

// await waits for the owner's approval. The CLI's exit is read before the
// last check of the record, and the clerk commits a login before the CLI
// sees it, so that check is final.
func (h *PlanHost) await(ctx context.Context, s *planSignIn, w SignInWorker, t SignInTimes) {
	detail := DSignInTimedOut
	defer func() {
		w.Stop()
		h.end(s, detail)
	}()
	deadline := time.Now().Add(t.Wall)
	for {
		_, exited := w.Read(ctx)
		if h.Login.SignedIn(s.guest) {
			detail = DSignedIn
			return
		}
		switch {
		case exited:
			detail = DSignInFailed
			return
		case !time.Now().Before(deadline):
			return
		}
		select {
		case <-ctx.Done():
			detail = DSignInStopped
			return
		case <-time.After(t.Poll):
		}
	}
}

// end forgets the sign-in guest and records how its sign-in ended. A code
// exchange that committed before Forget wins over detail, and one that
// answers after it is dropped (plan.DEnded), so a late approval is never
// stored behind a timed-out sign-in.
func (h *PlanHost) end(s *planSignIn, detail string) {
	if h.Login.Forget(s.guest) {
		detail = DSignedIn
	}
	s.cancel()
	h.mu.Lock()
	if h.cur == s {
		h.cur = nil
		h.last = detail
	}
	h.mu.Unlock()
	close(s.done)
}

// State reads the route. It reads no token.
func (h *PlanHost) State() PlanState {
	st := PlanState{Mode: h.Login.Mode(), SignedIn: h.Login.Signed(), Stopped: h.Login.Stopped()}
	h.mu.Lock()
	defer h.mu.Unlock()
	st.Last = h.last
	if s := h.cur; s != nil && s.code != "" {
		st.Signing, st.Page, st.Code, st.From = true, h.Prompt.Page, s.code, h.Prompt.From
	}
	return st
}

// Resume is the owner's PLAN <plan> ON after a refused login, whose caller
// has proved the owner (CH-10): "" or DRequalify.
func (h *PlanHost) Resume() (string, error) {
	err := h.Login.Resume()
	if errors.Is(err, plan.ErrRequalify) {
		return DRequalify, nil
	}
	return "", err
}

// Remove ends any sign-in, waiting for its sandbox to go, and deletes the
// login. No sign-in begins while it runs.
func (h *PlanHost) Remove() error {
	h.mu.Lock()
	s := h.cur
	if s != nil {
		s.cancel()
	}
	h.removing++
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.removing--
		h.mu.Unlock()
	}()
	if s != nil {
		<-s.done
	}
	return h.Login.Remove()
}

// ListenPlanOwner opens the model clerk process's plan owner socket,
// admitting only the owner side's uid, which is never the planner's or a
// guest's.
func ListenPlanOwner(path string, ownerUID int) (net.Listener, error) {
	return proc.ListenKernel(path, ownerUID)
}

// ServePlanOwner answers the owner side's plan calls to h on ln until ln
// closes.
func ServePlanOwner(ln net.Listener, h *PlanHost) error {
	return proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var res any
			if strings.HasPrefix(op, "apikey") {
				return serveKeyCall(h.APIs, op, raw)
			}
			switch op {
			case "planbegin":
				res = h.Begin(context.Background())
			case "planstate":
				res = h.State()
			case "planresume":
				d, err := h.Resume()
				if err != nil {
					return nil, err
				}
				res = d
			case "planremove":
				if err := h.Remove(); err != nil {
					return nil, err
				}
				return nil, nil
			default:
				return nil, errors.New("run: the plan owner socket has no call " + op)
			}
			return json.Marshal(res)
		})
	})
}

// keyArgs is an owner key call's arguments.
type keyArgs struct {
	Provider string `json:"provider"`
	Key      string `json:"key,omitempty"`
	Private  bool   `json:"private,omitempty"`
}

// serveKeyCall answers the owner side's API-key calls: apikeyset stores a
// provider's key and its private-data label, apikeyprivate changes only the
// label, apikeyremove removes the key, and apikeystate lists every declared
// provider's key without it (CLK-1). An error names no value.
func serveKeyCall(a *model.APIs, op string, raw json.RawMessage) (json.RawMessage, error) {
	var k keyArgs
	if a == nil || json.Unmarshal(raw, &k) != nil {
		return nil, errors.New("run: the plan owner socket has no call " + op)
	}
	var err error
	switch op {
	case "apikeyset":
		err = a.SetKey(k.Provider, k.Key, k.Private)
	case "apikeyprivate":
		err = a.SetPrivate(k.Provider, k.Private)
	case "apikeyremove":
		err = a.RemoveKey(k.Provider)
	case "apikeystate":
		st, err := a.State()
		if err != nil {
			return nil, errKeyStore
		}
		return json.Marshal(st)
	default:
		return nil, errors.New("run: the plan owner socket has no call " + op)
	}
	if errors.Is(err, model.ErrKeyForm) {
		return nil, model.ErrKeyForm
	}
	if err != nil {
		return nil, errKeyStore
	}
	return nil, nil
}

// errKeyStore is a key call the sealed store could not carry out; nothing
// changed.
var errKeyStore = errors.New("run: the API keys could not be opened or written; nothing changed")

// PlanOwner is the owner side's caller of the plan route. Its Timeout must
// exceed the host's SignInTimes.Link.
type PlanOwner struct{ proc.Conn }

// Begin starts the plan's sign-in: the provider's page and code, or a
// detail.
func (o PlanOwner) Begin() (b PlanBegun, err error) {
	err = o.Call("planbegin", nil, &b)
	return
}

func (o PlanOwner) State() (st PlanState, err error) {
	err = o.Call("planstate", nil, &st)
	return
}

// Resume reopens a route the provider refused the login on: "" or
// DRequalify.
func (o PlanOwner) Resume() (detail string, err error) {
	err = o.Call("planresume", nil, &detail)
	return
}

func (o PlanOwner) Remove() error { return o.Call("planremove", nil, nil) }

// SetKey stores provider's API key and whether its routes may see private
// data.
func (o PlanOwner) SetKey(provider, key string, private bool) error {
	return o.Call("apikeyset", keyArgs{provider, key, private}, nil)
}

// SetPrivate changes only the private-data label of provider's key.
func (o PlanOwner) SetPrivate(provider string, private bool) error {
	return o.Call("apikeyprivate", keyArgs{Provider: provider, Private: private}, nil)
}

func (o PlanOwner) RemoveKey(provider string) error {
	return o.Call("apikeyremove", keyArgs{Provider: provider}, nil)
}

// KeyState lists every declared provider's key, never the key itself.
func (o PlanOwner) KeyState() (st []model.KeyState, err error) {
	err = o.Call("apikeystate", nil, &st)
	return
}
