// Package evalsock carries the change pipeline's evaluations (CHG-1,
// LOOP-5) from the learning process to agentosd, which owns the agent
// machines and runs each one as a counterfactual replay (package replay).
//
// The pipeline and loop scheduler link network clients, so ARC-2 keeps them
// out of agentosd; the machine manager stays in agentosd. This socket is the
// one seam between them. Client implements change.Evaluator for the
// pipeline; Server answers it in agentosd from a Runner (replay.Evaluator).
//
// A request carries the tree, the probe, the probe's task (the journal
// intent its case was recorded on, empty for a security fixture), and the
// pipeline's active tree under ActiveNamespaces only. agentosd reads the
// recorded effects from its own journal, so no journal data crosses the
// socket. The socket admits one peer uid (SO_PEERCRED).
package evalsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// ActiveNamespaces are the namespaces of the active tree a request carries:
// those a replay cannot exercise and so compares against the active tree
// (replay.Untested), plus routing, which an offline replay cannot exercise
// either. Other namespaces never cross the socket.
var ActiveNamespaces = []string{"config", "guest-image", "host-image", "routing"}

// MaxRequest bounds a request body.
const MaxRequest = 32 << 20

// Probe is change.Probe on the wire.
type Probe struct {
	ID    string `json:"id"`
	Input []byte `json:"input"`
}

// RunRequest asks for one replay of Probe on Tree.
type RunRequest struct {
	Tree   change.Tree `json:"tree"`
	Probe  Probe       `json:"probe"`
	Task   string      `json:"task,omitempty"`
	Active change.Tree `json:"active"`
}

// RunResponse is the guest's output, or why there is none.
type RunResponse struct {
	Output []byte `json:"output,omitempty"`
	Error  string `json:"error,omitempty"` // ErrorNotEvaluated or ErrorFailed
	Detail string `json:"detail,omitempty"`
}

const (
	ErrorNotEvaluated = "not_evaluated"
	ErrorFailed       = "failed"
)

// Runner runs one probe on a tree: replay.Evaluator.
type Runner interface {
	Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error)
}

// Server answers evaluation requests. Runs are serialized: one replay
// machine at a time, and Active and Task answer for the run in progress.
// Build it, hand Active and Task to the Runner's configuration, then set
// Runner before serving.
type Server struct {
	Runner Runner
	Logf   func(format string, args ...any)

	run    sync.Mutex // held for a whole run
	mu     sync.Mutex
	active change.Tree
	probe  string
	task   string
}

// Active returns the active tree's files in ns for the run in progress, as
// its request carried them; nothing outside ActiveNamespaces.
func (s *Server) Active(ns string) change.Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := change.Tree{}
	for p, b := range s.active {
		if first, _, _ := strings.Cut(p, "/"); first == ns {
			out[p] = b
		}
	}
	return out
}

// Task maps the probe in progress to the journal intent its case was
// recorded on (replay.JournalRecordings.Task). Any other probe has none,
// so its effects fail closed.
func (s *Server) Task(probeID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if probeID == "" || probeID != s.probe || s.task == "" {
		return "", false
	}
	return s.task, true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/run" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req RunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Probe.ID == "" {
		reply(w, http.StatusBadRequest, RunResponse{Error: ErrorFailed, Detail: "bad request"})
		return
	}
	for p := range req.Active {
		if first, _, _ := strings.Cut(p, "/"); !contains(ActiveNamespaces, first) {
			reply(w, http.StatusBadRequest, RunResponse{Error: ErrorFailed, Detail: "active tree outside the compared namespaces"})
			return
		}
	}
	if s.Runner == nil {
		reply(w, http.StatusServiceUnavailable, RunResponse{Error: ErrorFailed, Detail: "evaluator not running"})
		return
	}
	s.run.Lock()
	defer s.run.Unlock()
	s.mu.Lock()
	s.active, s.probe, s.task = req.Active, req.Probe.ID, req.Task
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active, s.probe, s.task = nil, "", ""
		s.mu.Unlock()
	}()
	out, err := s.Runner.Run(r.Context(), req.Tree, change.Probe{ID: req.Probe.ID, Input: req.Probe.Input})
	switch {
	case errors.Is(err, change.ErrNotEvaluated):
		reply(w, http.StatusUnprocessableEntity, RunResponse{Error: ErrorNotEvaluated, Detail: err.Error()})
	case err != nil:
		if s.Logf != nil {
			s.Logf("evaluation %s: %v", req.Probe.ID, err)
		}
		reply(w, http.StatusInternalServerError, RunResponse{Error: ErrorFailed, Detail: err.Error()})
	default:
		reply(w, http.StatusOK, RunResponse{Output: out})
	}
}

func reply(w http.ResponseWriter, code int, r RunResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(r)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Listen opens a Unix socket at path that admits only peer uid; every other
// connection is closed unread. The socket file is 0666 so that peer can
// reach it; the uid check is the control. Its directory is the caller's.
func Listen(path string, uid int) (net.Listener, error) {
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

// Serve serves s on ln until ctx ends.
func Serve(ctx context.Context, ln net.Listener, s *Server) error {
	hs := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		hs.Close()
	}()
	if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ClientConfig configures NewClient.
type ClientConfig struct {
	Socket string
	// ProbeTask is the pipeline's ProbeTask.
	ProbeTask func(probeID string) (string, bool)
	// Active is the pipeline's Files.
	Active func(ns string) change.Tree
	// Timeout bounds one request: a replay run (10 min) plus its destroy
	// (2 min) by default.
	Timeout time.Duration
}

// Client is the pipeline's change.Evaluator over the evaluation socket.
type Client struct {
	cfg ClientConfig
	c   *http.Client
}

// NewClient returns a Client for the evaluation socket.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 12 * time.Minute
	}
	return &Client{cfg: cfg, c: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.Socket)
		},
		Proxy: nil,
	}}}
}

// Run implements change.Evaluator. A tree agentosd cannot evaluate here
// returns an error wrapping change.ErrNotEvaluated; any other failure is a
// plain error, which the pipeline counts as a failure on that side.
func (c *Client) Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	req := RunRequest{Tree: t, Probe: Probe{ID: p.ID, Input: p.Input}, Active: change.Tree{}}
	if c.cfg.ProbeTask != nil {
		req.Task, _ = c.cfg.ProbeTask(p.ID)
	}
	if c.cfg.Active != nil {
		for _, ns := range ActiveNamespaces {
			for path, b := range c.cfg.Active(ns) {
				req.Active[path] = b
			}
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agentosd/run", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := c.c.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("evalsock: %w", err)
	}
	defer resp.Body.Close()
	var out RunResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxRequest)).Decode(&out); err != nil {
		return nil, fmt.Errorf("evalsock: status %d: %w", resp.StatusCode, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK && out.Error == "":
		return out.Output, nil
	case out.Error == ErrorNotEvaluated:
		return nil, fmt.Errorf("evalsock: %s: %w", out.Detail, change.ErrNotEvaluated)
	default:
		return nil, fmt.Errorf("evalsock: status %d: %s", resp.StatusCode, out.Detail)
	}
}
