package loopbuild

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Socket is the file name of a builder machine's broker socket, as for
// every agent machine (guest G1).
const Socket = "broker.sock"

// Bounds on what a builder submits (C-3c-4): it is clipped by refusal, so
// a builder that overreaches gets 413 or 422 and may submit again within
// its time.
const (
	MaxFiles          = 32
	MaxFileBytes      = 64 << 10
	MaxCandidateBytes = 512 << 10
	maxPath           = 160
	maxInFlight       = 4
	maxBriefSteps     = 256
)

// ClassNS is where a builder for each class may write. No other class has
// a builder: in particular none writes security, routing, update or image
// namespaces (C-3c-4).
var ClassNS = map[change.Class]string{
	change.ClassProcedure: "procedures",
	change.ClassSkill:     "skills",
	change.ClassContext:   "context",
}

// Brief is what GET /brief returns: the hypothesis and the explicit dev
// cases (change C17). Held-out cases never reach a builder (CHG-1).
type Brief struct {
	Signal string      `json:"signal"`
	Class  string      `json:"class"`
	Key    string      `json:"key"`
	Writes string      `json:"writes"` // the one namespace a candidate may write
	Steps  []BriefStep `json:"steps"`
	Cases  []BriefCase `json:"cases"`
	Limits BriefLimits `json:"limits"`
}

// BriefStep is one journal intent behind the hypothesis, as the journal
// keeps it (free text redacted).
type BriefStep struct {
	Task    string         `json:"task"`
	Account string         `json:"account"`
	Action  string         `json:"action"`
	State   string         `json:"state"`
	Params  map[string]any `json:"params,omitempty"`
}

// BriefCase is one explicit dev case.
type BriefCase struct {
	ID      string          `json:"id"`
	Input   json.RawMessage `json:"input,omitempty"`
	Expect  json.RawMessage `json:"expect,omitempty"`
	Outcome string          `json:"outcome,omitempty"`
}

// BriefLimits tells the builder the bounds its candidate must meet.
type BriefLimits struct {
	Files     int `json:"files"`
	FileBytes int `json:"file_bytes"`
	Bytes     int `json:"bytes"`
}

func newBrief(br loops.Brief, ns string) Brief {
	h := br.Hypothesis
	out := Brief{Signal: string(h.Signal), Class: string(h.Class), Key: h.Key, Writes: ns,
		Steps: []BriefStep{}, Cases: []BriefCase{},
		Limits: BriefLimits{Files: MaxFiles, FileBytes: MaxFileBytes, Bytes: MaxCandidateBytes}}
	// A task the owner accepted only implicitly is counted, never read
	// (C17; security F1 on #126): its steps keep their account, action and
	// state, but no values.
	implicit := map[string]bool{}
	for _, s := range h.Evidence {
		if strings.HasSuffix(s.Quality.Source, change.ImplicitSuffix) {
			implicit[loops.TaskKey(s.Intent)] = true
		}
	}
	for _, s := range h.Evidence {
		if len(out.Steps) == maxBriefSteps {
			break
		}
		if s.Intent.Account == journal.BrokerAccount {
			continue
		}
		task := loops.TaskKey(s.Intent)
		st := BriefStep{Task: task, Account: s.Intent.Account, Action: s.Intent.Action, State: string(s.State)}
		if !implicit[task] {
			st.Params = s.Intent.Params
		}
		out.Steps = append(out.Steps, st)
	}
	for _, c := range br.Dev {
		if c.Implicit {
			continue // count, not content (C17)
		}
		out.Cases = append(out.Cases, BriefCase{ID: c.ID, Input: raw(c.Input), Expect: raw(c.Expect), Outcome: string(c.Outcome)})
	}
	return out
}

// raw keeps b as JSON when it is JSON, else as a JSON string.
func raw(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, _ := json.Marshal(string(b))
	return s
}

// session is one job's machine as the broker serves it.
type session struct {
	b     *Builder
	id    string
	ns    string
	brief []byte

	mu       sync.Mutex
	dir      string
	srv      *http.Server
	slot     chan struct{}
	done     chan struct{}
	finished bool
	files    map[string][]byte
}

// end finishes the session if nothing has, so no candidate is taken after
// it, and returns the candidate if one was.
func (s *session) end() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished {
		s.finished = true
		close(s.done)
	}
	return s.files
}

// Services returns the vm.Services every machine's start goes through. A
// machine whose ID has the builder prefix gets its job's socket if a job
// is running it, and nothing otherwise: it is never handed to next, the
// guest plane, so a builder never reaches executors, the owner channel or
// managed_tree, even when created, forked or resumed by something else.
// Every other machine goes to next; nil next serves them nothing.
func (b *Builder) Services(next vm.Services) vm.Services { return services{b, next} }

type services struct {
	b    *Builder
	next vm.Services
}

func (v services) Open(id string) (string, error) {
	if !strings.HasPrefix(id, Prefix) {
		if v.next == nil {
			return "", nil
		}
		return v.next.Open(id)
	}
	return v.b.open(id)
}

func (v services) Close(id string) {
	if !strings.HasPrefix(id, Prefix) {
		if v.next != nil {
			v.next.Close(id)
		}
		return
	}
	v.b.closeSocket(id)
}

// Open and Close serve only builder machines; the box routes those here.
func (b *Builder) Open(id string) (string, error) {
	if !strings.HasPrefix(id, Prefix) {
		return "", fmt.Errorf("loopbuild: %s is not a builder machine", id)
	}
	return b.open(id)
}

func (b *Builder) Close(id string) {
	if strings.HasPrefix(id, Prefix) {
		b.closeSocket(id)
	}
}

// open starts serving builder machine id. It is idempotent while the job
// runs, so a preempted machine resumes on the same socket.
func (b *Builder) open(id string) (string, error) {
	b.mu.Lock()
	s := b.sessions[id]
	b.mu.Unlock()
	if s == nil {
		return "", fmt.Errorf("loopbuild: no job runs machine %s", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return s.dir, nil
	}
	dir := b.socketDir(id)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, Socket))
	if err != nil {
		return "", err
	}
	s.dir, s.slot = dir, make(chan struct{}, maxInFlight)
	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       15 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
	}
	go s.srv.Serve(l)
	return dir, nil
}

func (b *Builder) closeSocket(id string) {
	b.mu.Lock()
	s := b.sessions[id]
	b.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	srv, dir := s.srv, s.dir
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if srv.Shutdown(ctx) != nil {
			srv.Close()
		}
		cancel()
		os.RemoveAll(dir)
	}
}

func (b *Builder) endSession(id string) {
	b.closeSocket(id)
	b.mu.Lock()
	delete(b.sessions, id)
	b.mu.Unlock()
}

// handler is a builder machine's whole surface (C-3c-2): the brief, one
// candidate, and the metered model route. Anything else is 404; in
// particular there is no /mcp (executors, managed_tree) and no /owner.
func (s *session) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/brief", s.serveBrief)
	mux.HandleFunc("/candidate", s.candidate)
	mux.Handle("/model/", http.StripPrefix("/model", s.model()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.slot <- struct{}{}:
			defer func() { <-s.slot }()
		default:
			http.Error(w, "too many requests in flight", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// model is the metered model route, refused once the job has used its
// token cap (C-3c-5).
func (s *session) model() http.Handler {
	b := s.b
	if b.cfg.Model == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no model egress is configured", http.StatusServiceUnavailable)
		})
	}
	next := b.cfg.Meter.Wrap(s.id, b.cfg.Model(s.id))
	// One call at a time, so the cap is checked against every earlier
	// call's metered use and concurrent calls cannot overshoot it
	// (security R3 on #126).
	var one sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		one.Lock()
		defer one.Unlock()
		if b.cfg.Meter.Usage(s.id).Tokens >= b.cfg.JobTokens {
			http.Error(w, "this job's model budget is spent", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *session) serveBrief(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.brief)
}

// Submission is what POST /candidate takes: files by path, as text.
type Submission struct {
	Files map[string]string `json:"files"`
}

// candidate takes the builder's one candidate. A refused one can be fixed
// and sent again until the job's time runs out; an accepted one ends the
// job.
func (s *session) candidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 2*MaxCandidateBytes+1))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if len(data) > 2*MaxCandidateBytes {
		http.Error(w, "candidate too large", http.StatusRequestEntityTooLarge)
		return
	}
	var sub Submission
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sub); err != nil {
		http.Error(w, `candidate is not {"files": {"path": "text"}}`, http.StatusBadRequest)
		return
	}
	files, err := admit(sub, s.ns)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		http.Error(w, "this job is finished", http.StatusConflict)
		return
	}
	s.files, s.finished = files, true
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"accepted":true}`)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	close(s.done)
}

// admit clips a submission (C-3c-4): 1 to MaxFiles files, each valid
// UTF-8 text of at most MaxFileBytes with no NUL, MaxCandidateBytes in all,
// each under ns at a clean relative path.
func admit(sub Submission, ns string) (map[string][]byte, error) {
	if len(sub.Files) == 0 || len(sub.Files) > MaxFiles {
		return nil, fmt.Errorf("a candidate has 1 to %d files", MaxFiles)
	}
	out := make(map[string][]byte, len(sub.Files))
	total := 0
	for p, text := range sub.Files {
		if len(p) > maxPath || path.Clean(p) != p || path.IsAbs(p) || strings.Contains(p, "\\") {
			return nil, fmt.Errorf("%q is not a clean relative path", p)
		}
		first, rest, _ := strings.Cut(p, "/")
		if first != ns || rest == "" {
			return nil, fmt.Errorf("%q is outside %s/", p, ns)
		}
		if len(text) > MaxFileBytes || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return nil, fmt.Errorf("%q is not text of at most %d bytes", p, MaxFileBytes)
		}
		if total += len(text); total > MaxCandidateBytes {
			return nil, fmt.Errorf("a candidate is at most %d bytes", MaxCandidateBytes)
		}
		out[p] = []byte(text)
	}
	return out, nil
}
