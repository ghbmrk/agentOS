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
	"io"
	"net"
	"net/http"
	"net/http/httputil"
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
	// HeaderRule carries, for a replay machine only, the routing rule of
	// the tree under evaluation (base64 of its JSON); see Evaluation.
	HeaderRule   = "Agentos-Rule"
	headerPrefix = "Agentos-"
)

// EvalPrefix starts every replay machine's ID (vm.EvalPrefix). Only such
// machines get the evaluation route, and the vault process applies a rule
// only for them.
const EvalPrefix = "eval-"

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
// weights the meter applies. It carries no content.
type Usage struct {
	Provider    string `json:"provider"`
	Input       int64  `json:"input"`
	Output      int64  `json:"output"`
	CacheRead   int64  `json:"cache_read"`
	CacheWrite  int64  `json:"cache_write"`
	Reported    bool   `json:"reported"`
	Complete    bool   `json:"complete"`
	OutputChars int64  `json:"output_chars"`
}

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
				if eval && rule != nil {
					pr.Out.Header.Set(HeaderRule, base64.StdEncoding.EncodeToString(rule))
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				raw := resp.Header.Get(HeaderDenial)
				dropOurs(resp.Header)
				dropOurs(resp.Trailer)
				// Trailer values arrive with the end of the body; strip
				// ours again once they have.
				resp.Body = &scrubTrailers{ReadCloser: resp.Body, resp: resp, ctx: resp.Request.Context()}
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
				// No response came back, so nothing a provider produced
				// reaches the guest; the meter must not charge this page
				// as output (OP-8 counts content, not the broker's text).
				meter.Report(r.Context(), meter.Usage{NoResponse: true})
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
type scrubTrailers struct {
	io.ReadCloser
	resp *http.Response
	ctx  context.Context
	done bool
}

func (s *scrubTrailers) Read(b []byte) (int, error) {
	n, err := s.ReadCloser.Read(b)
	if err != nil {
		if raw := s.resp.Trailer.Get(HeaderUsage); err == io.EOF && !s.done && raw != "" && len(raw) <= maxUsage {
			var u Usage
			if json.Unmarshal([]byte(raw), &u) == nil && u.valid() {
				meter.Report(s.ctx, meter.Usage{Provider: u.Provider, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead,
					CacheWrite: u.CacheWrite, Reported: u.Reported, Complete: u.Complete, OutputChars: u.OutputChars})
			}
		}
		s.done = true
		dropOurs(s.resp.Trailer)
	}
	return n, err
}

// valid refuses negative or absurd counts; the meter would otherwise charge
// them.
func (u Usage) valid() bool {
	for _, n := range []int64{u.Input, u.Output, u.CacheRead, u.CacheWrite, u.OutputChars} {
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
