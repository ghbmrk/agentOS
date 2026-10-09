// Package modelroute forwards each agent machine's model route (ARC-6 a)
// from the guest plane to the vault process, agentos-egress, which holds
// the unlocked vault and runs the credentialed egress proxy (P2-4).
//
// agentosd links this package and never the vault or the proxy (vault V2,
// daemon TestDaemonLinksNoCredentialCustody). The vault process accepts
// connections on its model socket from the broker's uid only, so it can
// take the broker's word for which machine a request is from and that
// machine's REV-5 label. Both are set here from the broker's own state and
// replace anything the guest sent. The vault process reports a denial in a
// response header, which is removed here and handed to the broker's
// journal (egress E6) under the machine this side forwarded for. A served
// call's provider-reported usage comes back in a response trailer, which
// is removed here and reported to the OP-8 meter (meter.Report).
package modelroute

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// Headers between the broker and the vault process. Every header with the
// Agentos- prefix is the broker's: a guest's copies are dropped.
const (
	HeaderMachine = "Agentos-Machine"
	HeaderLabel   = "Agentos-Label"
	HeaderDenial  = "Agentos-Egress-Denial"
	HeaderUsage   = "Agentos-Usage"
	// HeaderAttempts is how many attempts past the first the vault
	// process's router may send for the call, failing over: as many as
	// the call's meter holds, up to MaxRetries (SR3-7-f1b). Missing or
	// unreadable, it is none.
	HeaderAttempts = "Agentos-Attempts"
	// HeaderRule carries, for a replay machine only, the routing rule of
	// the tree under evaluation (base64 of its JSON); see Evaluation.
	HeaderRule   = "Agentos-Rule"
	headerPrefix = "Agentos-"
)

// EvalPrefix starts every replay machine's ID (vm.EvalPrefix). Only such
// machines get the evaluation route, and the vault process applies a rule
// only for them.
const EvalPrefix = "eval-"

// BuilderPrefix starts every Loop 1 builder machine's ID (loopbuild,
// W3-builder). The vault process gives such machines the grants of
// -builder-from, always as private (C-3c-6), never grants of their own.
const BuilderPrefix = "lb-"

// ReasonEvalCeiling is the vault process's denial reason when a tree under
// evaluation routes to a model priced above the active rule's dearest
// route, or to one with no known price. The broker reports such a tree as
// not evaluated, never as passing or failing (security C1 on #62).
const ReasonEvalCeiling = "evaluation route over the active price ceiling"

// MaxRule bounds a forwarded routing rule.
const MaxRule = 16 << 10

// Denial is one refused request, as the vault process reports it. It
// carries no header or body content. Machine is ignored on receipt: the
// broker knows which machine it forwarded for.
type Denial struct {
	Machine   string `json:"machine,omitempty"`
	Adapter   string `json:"adapter,omitempty"`
	Operation string `json:"operation,omitempty"`
	Method    string `json:"method"`
	Status    int    `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

// Usage is the HeaderUsage trailer: a served call's usage as the router
// measured it (route.Usage) and the provider that served it, whose cache
// weights the meter applies, with every attempt it failed over from
// (Failed; SR3-7-f1c). Unserved says no route served the call: only its
// failed attempts are charged. None says no attempt was sent upstream
// (the router refused the call itself), so the meter keeps its own count.
// It carries no content.
type Usage struct {
	Provider    string `json:"provider"`
	Input       int64  `json:"input"`
	Output      int64  `json:"output"`
	CacheRead   int64  `json:"cache_read"`
	CacheWrite  int64  `json:"cache_write"`
	Reported    bool   `json:"reported"`
	Complete    bool   `json:"complete"`
	OutputChars int64  `json:"output_chars"`

	Failed   []meter.Attempt `json:"failed,omitempty"`
	Unserved bool            `json:"unserved,omitempty"`
	None     bool            `json:"none,omitempty"`
}

// MaxRetries bounds HeaderAttempts.
const MaxRetries = 3

// maxUsage bounds the usage trailer.
const maxUsage = 4 << 10

// Config configures Forward.
type Config struct {
	// Socket is the vault process's model socket.
	Socket string
	// Label returns a machine's current REV-5 label. Anything other than
	// "public" is sent as "private".
	Label func(machine string) string
	// Denied receives each denial for the journal.
	Denied func(machine string, d Denial)
	// Logf reports forwarding faults. Nil is silent.
	Logf func(format string, args ...any)
	// OverCeiling is told, for Evaluation only, which replay machine the
	// vault process refused with ReasonEvalCeiling, so the evaluator ends
	// that run as not evaluated (replay.Evaluator.OverPriceCeiling).
	// Evaluation requires it: without it every call answers 503.
	OverCeiling func(machine string)
	// Retries is the most attempts past the first the owner's rule lets
	// a call spend (Spare.Retries), read on each call, so it must not
	// block. The meter holds no more than that, nor MaxRetries. Nil, or
	// a negative answer (unknown), holds MaxRetries (SR3-7-f2).
	Retries func() int
}

// Forward returns the guest plane's Model function: one handler per
// machine, forwarding to the vault process. If that process is down the
// guest gets 503, as when the vault is locked.
func Forward(cfg Config) func(machine string) http.Handler {
	fwd := forward(cfg)
	return func(machine string) http.Handler { return fwd(machine, false, nil) }
}

// Evaluation returns the replay plane's model access (LOOP-5): machine's
// calls go to the vault process like a live machine's, always labelled
// private (owner task data, REV-5), carrying rule, the routing rule of the
// tree under evaluation, or none to use the active one. The vault process
// applies it within the owner's grants, which are its own configuration
// (replay K1). A machine outside EvalPrefix, a rule over MaxRule, or a
// Config without OverCeiling gets 503 and nothing is forwarded. A refusal
// with ReasonEvalCeiling is reported to OverCeiling before Denied.
func Evaluation(cfg Config) func(machine string, rule []byte) http.Handler {
	fwd := forward(cfg)
	return func(machine string, rule []byte) http.Handler {
		if cfg.OverCeiling == nil || !strings.HasPrefix(machine, EvalPrefix) || len(rule) > MaxRule {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "no evaluation model route", http.StatusServiceUnavailable)
			})
		}
		return fwd(machine, true, rule)
	}
}

func forward(cfg Config) func(machine string, eval bool, rule []byte) http.Handler {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", cfg.Socket)
		},
		DisableCompression: true,
		MaxIdleConns:       16,
		IdleConnTimeout:    90 * time.Second,
		Proxy:              nil,
		// The vault process clips what it reports (a denial reason
		// to 1 KiB); a larger header block is not its.
		MaxResponseHeaderBytes: 64 << 10,
	}
	return func(machine string, eval bool, rule []byte) http.Handler {
		rp := &httputil.ReverseProxy{
			Transport:     tr,
			FlushInterval: -1,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", "agentos-egress", "agentos-egress"
				dropOurs(pr.Out.Header)
				label := "private"
				if !eval && cfg.Label(machine) == "public" {
					label = "public"
				}
				pr.Out.Header.Set(HeaderMachine, machine)
				pr.Out.Header.Set(HeaderLabel, label)
				// The meter holds each attempt past the first before the
				// vault process may send it; what is not spent is
				// refunded when the call settles. It holds none the owner's
				// rule cannot spend (SR3-7-f2).
				n, most := 0, MaxRetries
				if cfg.Retries != nil {
					if r := cfg.Retries(); r >= 0 {
						most = min(r, MaxRetries)
					}
				}
				for n < most && meter.Another(pr.In.Context()) {
					n++
				}
				pr.Out.Header.Set(HeaderAttempts, strconv.Itoa(n))
				if eval && rule != nil {
					pr.Out.Header.Set(HeaderRule, base64.StdEncoding.EncodeToString(rule))
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				raw := resp.Header.Get(HeaderDenial)
				_, announced := resp.Trailer[HeaderUsage]
				allowed, _ := strconv.Atoi(resp.Request.Header.Get(HeaderAttempts))
				dropOurs(resp.Header)
				dropOurs(resp.Trailer)
				// Trailer values arrive with the end of the body; strip
				// ours again once they have.
				resp.Body = &scrubTrailers{ReadCloser: resp.Body, resp: resp, ctx: resp.Request.Context(), announced: announced, allowed: allowed}
				if raw != "" {
					var d Denial
					if err := json.Unmarshal([]byte(raw), &d); err != nil {
						logf("model route %s: unreadable denial from the vault process", machine)
						d = Denial{Status: resp.StatusCode, Reason: "unreadable denial"}
					}
					d.Machine = machine
					if eval && d.Reason == ReasonEvalCeiling {
						cfg.OverCeiling(machine)
					}
					cfg.Denied(machine, d)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logf("model route %s: vault process: %v", machine, err)
				// No response came back, and this page is not model output
				// (OP-8 counts content, not the broker's text). A call that
				// could not connect never reached a provider; any other
				// failure (a timeout, a hang-up, a vault process that
				// died) may come after a provider billed output. The cap
				// counts what the provider may have billed, not what
				// reached the guest, so the meter charges the call's full
				// output reservation, and so each further attempt the
				// call was allowed (SR3-7-f1c). r is the request as sent,
				// so its allowance is the broker's.
				var op *net.OpError
				if errors.As(err, &op) && op.Op == "dial" {
					meter.Report(r.Context(), meter.Usage{NoResponse: true})
				} else {
					allowed, _ := strconv.Atoi(r.Header.Get(HeaderAttempts))
					unanswered(r.Context(), allowed)
				}
				http.Error(w, "model egress unavailable", http.StatusServiceUnavailable)
			},
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The guest's request body belongs to the outbound request
			// until the transport is done with it. In the default
			// half-duplex mode the server drains and closes that body as
			// soon as the response starts, which can land between the
			// transport sending the body and its final EOF read: the
			// read fails, the transport drops the connection, and the
			// stream is cut. A writer that wraps the server's without
			// Unwrap is left as it is: in agentosd, Forward is reached
			// through meter.Wrap, whose writer has none, so this is a
			// no-op there; that path is safe already because Wrap reads
			// the body in full and hands the proxy an in-memory copy.
			_ = http.NewResponseController(w).EnableFullDuplex()
			rp.ServeHTTP(w, r)
		})
	}
}

// scrubTrailers drops our headers from the response trailers once the body
// ends, before the reverse proxy copies the trailers to the guest. A body
// that ended cleanly reports its usage trailer to the meter first, on the
// metered call's context (the request's).
//
// When the vault process announced the trailer, a call whose trailer is
// missing or unusable, or whose body broke off or was left unread, may
// have reached a provider and spent every attempt it was allowed: the
// meter charges it as Unanswered, with each allowed attempt past the first
// as a failed one at the full reservation (SR3-7-f1c).
type scrubTrailers struct {
	io.ReadCloser
	resp      *http.Response
	ctx       context.Context
	done      bool
	announced bool // the vault process announced HeaderUsage
	allowed   int  // HeaderAttempts as sent
}

func (s *scrubTrailers) Read(b []byte) (int, error) {
	n, err := s.ReadCloser.Read(b)
	if err != nil && !s.done {
		s.done = true
		reported := false
		if raw := s.resp.Trailer.Get(HeaderUsage); err == io.EOF && raw != "" && len(raw) <= maxUsage {
			var u Usage
			if json.Unmarshal([]byte(raw), &u) == nil && u.valid(s.allowed) {
				reported = true
				if !u.None {
					meter.Report(s.ctx, meter.Usage{Provider: u.Provider, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead,
						CacheWrite: u.CacheWrite, Reported: u.Reported, Complete: u.Complete, OutputChars: u.OutputChars,
						Failed: u.Failed, Unserved: u.Unserved})
				}
			}
		}
		if !reported {
			s.unanswered()
		}
	}
	if err != nil {
		dropOurs(s.resp.Trailer)
	}
	return n, err
}

// Close charges a body left unread as unanswered.
func (s *scrubTrailers) Close() error {
	if !s.done {
		s.done = true
		s.unanswered()
	}
	return s.ReadCloser.Close()
}

// unanswered reports the worst the call may have spent, if the vault
// process announced a usage trailer.
func (s *scrubTrailers) unanswered() {
	if s.announced {
		unanswered(s.ctx, s.allowed)
	}
}

// unanswered reports the metered call on ctx as one that may have reached
// a provider and spent all allowed attempts past the first, each at its
// full reservation.
func unanswered(ctx context.Context, allowed int) {
	failed := make([]meter.Attempt, max(0, min(allowed, MaxRetries)))
	for i := range failed {
		failed[i] = meter.Attempt{Full: true}
	}
	meter.Report(ctx, meter.Usage{Unanswered: true, Failed: failed})
}

// valid refuses negative or absurd counts, which the meter would otherwise
// charge, and more failed attempts than the call was allowed.
func (u Usage) valid(allowed int) bool {
	if len(u.Failed) > allowed+1 || (u.None && (u.Unserved || len(u.Failed) > 0)) || (u.Unserved && len(u.Failed) == 0) {
		return false
	}
	counts := []int64{u.Input, u.Output, u.CacheRead, u.CacheWrite, u.OutputChars}
	for _, a := range u.Failed {
		if a.Status < 100 || a.Status > 599 {
			return false
		}
		counts = append(counts, a.Input, a.Output, a.CacheRead, a.CacheWrite, a.OutputChars)
	}
	for _, n := range counts {
		if n < 0 || n > 1e12 {
			return false
		}
	}
	return true
}

// dropOurs removes every Agentos- header, and the proxy's own denial mark
// (egress.DeniedHeader, X-Agentos-Egress-Denied).
func dropOurs(h http.Header) {
	for k := range h {
		if k := http.CanonicalHeaderKey(k); strings.HasPrefix(k, headerPrefix) || strings.HasPrefix(k, "X-"+headerPrefix) {
			delete(h, k)
		}
	}
}
