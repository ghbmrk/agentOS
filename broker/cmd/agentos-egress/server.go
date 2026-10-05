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
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
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
// While the vault is not open every request gets 503.
func modelHandler(c *custody) http.Handler {
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
		p.HandlerFor(machine, label, headerAudit{w}).ServeHTTP(w, r)
	})
}

// headerAudit returns a denial to the broker in a response header, for its
// journal (egress E6). Every denial is audited before the proxy writes its
// status line, so the header always goes out with it.
type headerAudit struct{ w http.ResponseWriter }

func (a headerAudit) Egress(ev egress.Event) {
	if ev.Allowed {
		return
	}
	b, err := json.Marshal(modelroute.Denial{Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason})
	if err == nil {
		a.w.Header().Set(modelroute.HeaderDenial, string(b))
	}
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
		code := http.StatusForbidden
		switch err {
		case errBusy, errNotPending, errLocked, errUnlockCancelled:
			code = http.StatusConflict
		case errTooManyWrong:
			code = http.StatusTooManyRequests
		case errBadCredential:
			code = http.StatusBadRequest
		case errInternal:
			code = http.StatusInternalServerError
		}
		reply(w, code, map[string]string{"error": err.Error()})
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
		if err := c.unlock(req.Passphrase); err != nil {
			fail(w, err)
			return
		}
		status(w)
	})
	mux.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.confirm(req.Code); err != nil {
			fail(w, err)
			return
		}
		status(w)
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
func verifyHandler(c *custody) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify" {
			http.Error(w, "POST /verify only", http.StatusMethodNotAllowed)
			return
		}
		var req modelroute.VerifyRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		step, ok, err := c.verify(req.Code, req.After)
		switch err {
		case nil:
		case errLocked:
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		case errTooManyWrong:
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
