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
// journal (egress E6) under the machine this side forwarded for.
package modelroute

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// Headers between the broker and the vault process. Every header with the
// Agentos- prefix is the broker's: a guest's copies are dropped.
const (
	HeaderMachine = "Agentos-Machine"
	HeaderLabel   = "Agentos-Label"
	HeaderDenial  = "Agentos-Egress-Denial"
	headerPrefix  = "Agentos-"
)

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
}

// Forward returns the guest plane's Model function: one handler per
// machine, forwarding to the vault process. If that process is down the
// guest gets 503, as when the vault is locked.
func Forward(cfg Config) func(machine string) http.Handler {
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
	}
	return func(machine string) http.Handler {
		return &httputil.ReverseProxy{
			Transport:     tr,
			FlushInterval: -1,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", "agentos-egress", "agentos-egress"
				dropOurs(pr.Out.Header)
				label := "private"
				if cfg.Label(machine) == "public" {
					label = "public"
				}
				pr.Out.Header.Set(HeaderMachine, machine)
				pr.Out.Header.Set(HeaderLabel, label)
			},
			ModifyResponse: func(resp *http.Response) error {
				raw := resp.Header.Get(HeaderDenial)
				dropOurs(resp.Header)
				if raw != "" {
					var d Denial
					if err := json.Unmarshal([]byte(raw), &d); err != nil {
						logf("model route %s: unreadable denial from the vault process", machine)
						d = Denial{Status: resp.StatusCode, Reason: "unreadable denial"}
					}
					d.Machine = machine
					cfg.Denied(machine, d)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logf("model route %s: vault process: %v", machine, err)
				http.Error(w, "model egress unavailable", http.StatusServiceUnavailable)
			},
		}
	}
}

func dropOurs(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), headerPrefix) {
			delete(h, k)
		}
	}
}
