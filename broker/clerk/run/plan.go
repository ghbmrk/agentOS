package run

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// A plan CLI guest's model endpoint (MIG-4-plan-login-b, PLN-5(a), CLK-7).
// It is served in the model clerk's process, the only one that holds a plan
// login, on a socket that admits only the guest's uid. The guest's CLI
// speaks its provider's own HTTP API to it, holding placeholders; the plan
// login clerk checks and forwards each request, and the model clerk admits
// each model call against the plan's caps and pool before it is sent and
// meters it when it ends (LOG-7, RES-5).

// PlanGuest is one guest's endpoint.
type PlanGuest struct {
	Login *plan.Login
	Clerk *model.Clerk
	// Guest is the guest's name at Login: its placeholders are its own.
	Guest string
	// Plan is the kernel plan its calls are charged to, and Route the
	// model clerk's route for this login, which names its pool.
	Plan, Route string
	// Context is the provider's declared context window in tokens: no
	// call's input passes it. MaxOut is its declared most output tokens a
	// call returns, reasoning included. The CLI sets no cap of its own, so
	// these bound a call (MIG-4-plan-bound).
	Context, MaxOut int64
	// Consent reports whether the owner's logged consent to an unconfirmed
	// plan route stands now (CLK-7); nil is no consent. It is read at each
	// request, so a withdrawal stops the route before its next call.
	Consent func() bool
	// Clock is the model clerk process's wall clock in unix ms. It orders
	// the clerk's own owed log writes (the kernel dates every one), and it
	// dates a pool reading: a missing or past reset becomes Clock plus the
	// pool's declared window, and an owed reading is dropped at its reset.
	Clock func() int64
}

// ListenPlan opens a guest's model endpoint, admitting only its uid.
func ListenPlan(path string, guestUID int) (net.Listener, error) {
	return sockets.ListenPeers(path, guestUID)
}

// planConns bounds the connections one guest's endpoint serves at once.
const planConns = 16

// ServePlan serves g's endpoint on ln until ln closes.
func ServePlan(ln net.Listener, g PlanGuest) error {
	// A model endpoint with no clerk, clock, window or output limit could
	// meter no call: it is refused here, so a host's misconfiguration
	// shows at start, not as every call's unrecorded-spend refusal.
	if g.Clerk == nil || g.Clock == nil || g.Context <= 0 || g.MaxOut <= 0 {
		ln.Close()
		return errPlanBound
	}
	return servePlan(ln, g)
}

// errPlanBound is a PlanGuest declared without what bounds its calls.
var errPlanBound = errors.New("run: a plan guest endpoint needs its model clerk, clock, context window and output limit")

// servePlan serves g's endpoint on ln. A sign-in guest's endpoint meters no
// call, so it is served with no clerk; a model call on it is refused.
func servePlan(ln net.Listener, g PlanGuest) error {
	srv := &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// A guest's malformed request is its own; its text stays out of
		// the clerk's log.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	err := srv.Serve(&limitListener{Listener: ln, slots: make(chan struct{}, planConns)})
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// errCut is a call that was sent and did not end in a whole 2xx answer
// with no usage reported: it is charged the admitted worst case.
var errCut = errors.New("run: the model call did not complete")

func (g PlanGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if detail := g.gate(); detail != "" {
		http.Error(w, "agentos: "+detail, planStatus(detail))
		return
	}
	resp, detail := g.Login.Do(r.Context(), g.Guest, r, g.meter)
	if detail != "" {
		http.Error(w, "agentos: "+detail, planStatus(detail))
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		w.Header()[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// gate is the CLK-7 mode gate, before anything is read or sent: a permitted
// route is open; an unconfirmed one serves its sign-in guest, so the owner
// can sign in before being asked, and runs only while consent stands; a
// route the terms bar serves nothing.
func (g PlanGuest) gate() string {
	switch g.Login.Mode() {
	case plan.Permitted:
		return ""
	case plan.Unconfirmed:
		if g.Login.Signing(g.Guest) || g.Consent != nil && g.Consent() {
			return ""
		}
		return DPlanConsent
	}
	return DPlanNotAllowed
}

// meter admits one model call of g's at the most its usage can be, and
// settles it when it ends. An unrecorded settlement is the clerk's to retry:
// it makes no further call until the log has it.
func (g PlanGuest) meter(body []byte) (func(plan.Used), string) {
	if g.Context <= 0 {
		return nil, DPlanMeter
	}
	adm, err := g.Clerk.Admit(g.Clock(), g.Plan, g.Route, g.inBound(body), g.MaxOut)
	if err != nil {
		var rf *key.Refusal
		if errors.As(err, &rf) && rf != nil {
			return nil, DPlanRefused + " " + rf.Code
		}
		return nil, DPlanMeter
	}
	return func(u plan.Used) {
		// The clerk's own count of a whole answer is its bytes at four a
		// token, which its event framing inflates; the provider returns
		// no more than MaxOut.
		_ = adm.Settle(g.Clock(), usage(u), min(model.Count(u.Bytes), g.MaxOut), ended(u))
	}, ""
}

// inBound is the most input tokens body can be: its bytes, since a token
// is at least one byte of the text it encodes, whatever the text; or the
// context window if smaller, or if body carries an image, whose tokens its
// bytes do not bound.
func (g PlanGuest) inBound(body []byte) int64 {
	var v any
	if json.Unmarshal(body, &v) != nil || hasImage(v) {
		return g.Context
	}
	return min(int64(len(body)), g.Context)
}

// hasImage reports whether v holds an object typed input_image.
func hasImage(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		if v["type"] == "input_image" {
			return true
		}
		for _, e := range v {
			if hasImage(e) {
				return true
			}
		}
	case []any:
		for _, e := range v {
			if hasImage(e) {
				return true
			}
		}
	}
	return false
}

// usage is what the call's answer reported, for the model clerk.
func usage(u plan.Used) model.Usage {
	m := model.Usage{In: u.In, Out: u.Out, Reported: u.Reported}
	if u.Pool != nil {
		m.Pool = &model.PoolReading{Used: u.Pool.Used, ResetAt: u.Pool.ResetAt}
	}
	return m
}

func ended(u plan.Used) error {
	switch {
	case !u.Sent:
		return model.ErrNotSent
	case u.Done:
		return nil
	}
	return errCut
}

// The endpoint's own details, beside the plan login clerk's.
const (
	DPlanRefused = "plan-refused" // the kernel refused the spend or the pool; then its code. Nothing sent.
	DPlanMeter   = "plan-meter"   // the call could not be admitted (unrecorded spend, no route); nothing sent
)

// planStatus is the HTTP status a guest sees for a detail. The detail
// names a rule, never a value (CLK-4).
func planStatus(detail string) int {
	switch {
	case planHas(detail, DPlanRefused):
		return http.StatusTooManyRequests
	case planHas(detail, plan.DStopped), planHas(detail, DPlanMeter), planHas(detail, DPlanConsent), planHas(detail, DPlanNotAllowed):
		return http.StatusServiceUnavailable
	case planHas(detail, clerk.DBlocked), planHas(detail, clerk.DNoAnswer):
		return http.StatusBadGateway
	}
	return http.StatusForbidden
}

func planHas(detail, code string) bool {
	return len(detail) >= len(code) && detail[:len(code)] == code && (len(detail) == len(code) || detail[len(code)] == ' ')
}

// limitListener holds Accept while every slot is taken: more connections
// wait in the backlog, holding none of the process's descriptors.
type limitListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &slotConn{Conn: c, free: func() { <-l.slots }}, nil
}

type slotConn struct {
	net.Conn
	once sync.Once
	free func()
}

func (c *slotConn) Close() error {
	c.once.Do(c.free)
	return c.Conn.Close()
}
