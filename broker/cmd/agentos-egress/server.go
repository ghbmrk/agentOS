package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Socket names inside the run directory.
const (
	ModelSocket  = "model.sock"
	UnlockSocket = "unlock.sock"
	VerifySocket = "verify.sock"
)

var machineRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// modelHandler serves the model socket. Only the broker connects to it
// (peerListener), so the machine and label headers are the broker's word.
// Every call goes through the model router (P2-7), which sends it through
// the egress proxy over the open vault (egress K9). While the vault is not
// open every request gets 503.
func modelHandler(c *custody, rt *route.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machine := r.Header.Get(modelroute.HeaderMachine)
		if !machineRE.MatchString(machine) {
			http.Error(w, "no machine named", http.StatusBadRequest)
			return
		}
		label := "private"
		if r.Header.Get(modelroute.HeaderLabel) == egress.LabelPublic {
			label = egress.LabelPublic
		}
		p := c.model()
		if p == nil {
			http.Error(w, "the vault is locked; model egress is unavailable", http.StatusServiceUnavailable)
			return
		}
		var ca callAudit
		w.Header().Set("Trailer", modelroute.HeaderUsage)
		rt.HandlerFor(machine, label, p.HandlerFor(machine, label, &ca), ca.decide(w, r.Method)).ServeHTTP(w, r)
		if u := ca.usage(); u != "" {
			w.Header().Set(modelroute.HeaderUsage, u)
		}
	})
}

// callAudit carries one call's outcome back to the broker: a denial in a
// response header for its journal (egress E6), and a served call's
// provider-reported usage in a trailer for its OP-8 meter (K9).
type callAudit struct {
	mu     sync.Mutex
	denial *modelroute.Denial // the proxy's
	served *route.Decision
}

// Egress takes the proxy's decision. The proxy runs on its own goroutine
// inside the router, so this only records it.
func (a *callAudit) Egress(ev egress.Event) {
	if ev.Allowed {
		return
	}
	a.mu.Lock()
	a.denial = &modelroute.Denial{Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason}
	a.mu.Unlock()
}

// decide takes the router's decisions. The router audits a denial before
// writing its status line, so the header always goes out with it. A call
// the proxy refused reports the proxy's denial. Every refusal of the
// router's own is reported too (ADP-10): an undeclared or unclean path, an
// unknown class, a body it does not accept, no granted route allowed for
// the label, or every route exhausted; none of these reaches the proxy.
// method is the guest's; the operation is named only once the body parsed
// as a chat completion.
func (a *callAudit) decide(w http.ResponseWriter, method string) func(route.Decision) {
	return func(d route.Decision) {
		a.mu.Lock()
		defer a.mu.Unlock()
		var den *modelroute.Denial
		switch {
		case d.Outcome == route.Served:
			a.served = &d
		case d.Outcome == route.Denied && a.denial != nil:
			den = a.denial
		case d.Outcome == route.Denied:
			den = &modelroute.Denial{Adapter: "router", Method: method, Status: d.Status, Reason: d.Reason}
			if d.Class != "" {
				den.Operation = "chat_completions"
			}
		}
		if den == nil {
			return
		}
		out := *den
		out.Reason = clipReason(out.Reason)
		if b, err := json.Marshal(out); err == nil {
			w.Header().Set(modelroute.HeaderDenial, string(b))
		}
	}
}

// maxDenialReason bounds a reported denial reason, which can quote guest
// input: the reason's class comes before any quote, so clipping keeps it,
// and the denial header stays far below the broker's header limit.
const maxDenialReason = 1 << 10

// clipReason cuts r to maxDenialReason bytes on a rune boundary.
func clipReason(r string) string {
	if len(r) <= maxDenialReason {
		return r
	}
	return strings.ToValidUTF8(r[:maxDenialReason], "") + "…[clipped]"
}

// usage renders a served call's usage as the HeaderUsage trailer, with the
// serving provider so the meter weighs cached input at that provider's
// rates; "" if no call was served. Unreported usage still carries the
// output characters the router counted.
func (a *callAudit) usage() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.served == nil || a.served.Usage == nil {
		return ""
	}
	u := a.served.Usage
	provider, _, _ := strings.Cut(a.served.Route, "/")
	b, err := json.Marshal(modelroute.Usage{Provider: provider, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead,
		CacheWrite: u.CacheWrite, Reported: u.Reported, Complete: u.Complete, OutputChars: u.OutputChars})
	if err != nil {
		return ""
	}
	return string(b)
}

// maxUnlockBody bounds a request on the unlock socket.
const maxUnlockBody = 16 << 10

// unlockHandler serves the unlock socket: the local UI (P2-2) sends the
// scanned passphrase and the owner's approval code here.
func unlockHandler(c *custody) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, err error) {
		var ue *unlockErr
		if !errors.As(err, &ue) {
			ue = errInternal
		}
		reply(w, ue.status, map[string]string{"error": ue.msg})
	}
	read := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return false
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxUnlockBody)).Decode(v); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return false
		}
		return true
	}
	status := func(w http.ResponseWriter) {
		ph, exp := c.status()
		out := map[string]any{"state": ph.String()}
		if ph == pending {
			out["expires"] = exp.UTC().Format(time.RFC3339)
		}
		if c.pinWanted() {
			out["pin"] = true
		}
		// The local page words the fallback unlock from these, and
		// offers "Keep this PC trusted" on /confirm, never ticked by
		// default: these hints come from files on the drive.
		if changed, updated, sb := c.bootChange(); changed {
			out["boot_changed"] = true
			out["updated"] = updated
			out["secure_boot"] = sb
		}
		reply(w, http.StatusOK, out)
	}
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { status(w) })
	mux.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Passphrase string `json:"passphrase"`
		}
		if !read(w, r, &req) {
			return
		}
		ticket, err := c.unlock(req.Passphrase)
		if err != nil {
			fail(w, err)
			return
		}
		_, exp := c.status()
		reply(w, http.StatusOK, map[string]any{"state": pending.String(), "expires": exp.UTC().Format(time.RFC3339), "ticket": ticket})
	})
	mux.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ticket string `json:"ticket"`
			Code   string `json:"code"`
			// KeepTrusted: "Keep this PC trusted" after a changed
			// boot path (status boot_changed).
			KeepTrusted bool `json:"keep_trusted"`
		}
		if !read(w, r, &req) {
			return
		}
		kept, err := c.confirmKeep(req.Ticket, req.Code, req.KeepTrusted)
		if err != nil {
			fail(w, err)
			return
		}
		ph, _ := c.status()
		reply(w, http.StatusOK, map[string]any{"state": ph.String(), "kept_trusted": kept})
	})
	// Trusted hosts (CRED-8, CRED-9). The local UI's socket is the local
	// confirmation; the code is the approval.
	mux.HandleFunc("/unlock-pin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PIN string `json:"pin"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.unlockPIN(req.PIN); err != nil {
			fail(w, err)
			return
		}
		status(w)
	})
	mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		h, err := c.hosts()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"hosts": h})
	})
	mux.HandleFunc("/trust", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
			PIN  string `json:"pin"`
		}
		if !read(w, r, &req) {
			return
		}
		name, err := c.trust(req.Code, req.PIN)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"host": name})
	})
	mux.HandleFunc("/untrust", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
			ID   string `json:"id"`
		}
		if !read(w, r, &req) {
			return
		}
		if _, err := c.untrust(req.Code, req.ID); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/lock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		c.lock()
		status(w)
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.put(req.Name, []byte(req.Value)); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// verifyHandler serves the verify socket: agentosd's owner channel checks
// a high-tier code here (K7). It is a socket of its own, not a path on the
// model socket, because the model socket forwards whatever path a guest
// asks for. The answer is a step and a yes or no, never the seed.
//
// POST /recall-key hands agentosd the recall index's identity key (recall
// K5), only while the vault is open.
func verifyHandler(c *custody) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/recall-key" {
			key, err := c.recallKey()
			switch {
			case err == errLocked:
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
			case err != nil:
				http.Error(w, errInternal.Error(), http.StatusInternalServerError)
			default:
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(key)
			}
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/verify" {
			http.Error(w, "POST /verify or /recall-key only", http.StatusMethodNotAllowed)
			return
		}
		var req modelroute.VerifyRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		step, ok, err := c.verify(req.Code, req.After, req.Counted)
		var paused *pausedError
		switch {
		case err == nil:
		case err == errLocked:
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		case errors.As(err, &paused):
			w.Header().Set(modelroute.HeaderPausedUntil, paused.until.UTC().Format(time.RFC3339))
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		default:
			http.Error(w, errInternal.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(modelroute.VerifyResult{OK: ok, Step: step})
	})
}

// peerListener accepts only connections from one uid (SO_PEERCRED); every
// other connection is closed unread.
type peerListener struct {
	net.Listener
	uid int
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := sockets.PeerUID(c); ok && uid == l.uid {
			return c, nil
		}
		c.Close()
	}
}

// runDir creates dir 0711 (traversable, not listable), or checks that an
// existing one is a real directory owned by this uid and resets its mode.
// The sockets in it are reachable by path, and each admits one peer uid.
func runDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by uid %d", dir, os.Getuid())
	}
	return os.Chmod(dir, 0o711)
}

// listen opens dir/name for one peer uid.
func listen(dir, name string, uid int) (net.Listener, error) {
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return peerListener{ln, uid}, nil
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		IdleTimeout:       2 * time.Minute,
	}
}
