package cleanroom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/vm"
)

// Socket is the file name of a clean room's broker socket, as for every
// agent machine (guest G1).
const Socket = "broker.sock"

// maxInFlight bounds one clean room's concurrent requests.
const maxInFlight = 4

// session is one job's clean room as the broker serves it.
type session struct {
	b       *Builder
	id      string
	job     *job
	kind    string
	embargo bool

	mu       sync.Mutex
	dir      string
	srv      *http.Server
	slot     chan struct{}
	done     chan struct{}
	finished bool
	storing  bool
	artifact string
	failure  string
}

func (s *session) fail(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished {
		s.finished, s.failure = true, reason
		close(s.done)
	}
}

// Services returns the vm.Services every machine's start goes through. A
// machine whose ID has the clean-room prefix gets its clean room's socket
// if a job is running it, and nothing otherwise: it is never handed to
// next, the guest plane, so a clean room cannot reach executors or the
// owner channel, even when created, forked, or resumed by something other
// than the builder. Every other machine goes to next; nil next serves them
// nothing.
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

// open starts serving clean room id. It is idempotent while the job runs,
// so a preempted clean room resumes on the same socket.
func (b *Builder) open(id string) (string, error) {
	b.mu.Lock()
	s := b.sessions[id]
	b.mu.Unlock()
	if s == nil {
		return "", fmt.Errorf("cleanroom: no clean-room job runs machine %s", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return s.dir, nil
	}
	dir := filepath.Join(b.cfg.Dir, "sockets", id)
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
		ReadTimeout:       time.Minute,
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
	defer s.mu.Unlock()
	if s.srv != nil {
		s.srv.Close()
		os.RemoveAll(s.dir)
		s.srv = nil
	}
}

func (b *Builder) endSession(id string) {
	b.closeSocket(id)
	b.mu.Lock()
	delete(b.sessions, id)
	b.mu.Unlock()
}

// handler is a clean room's whole surface: the hint, the result, and the
// metered model route. Anything else is 404; in particular there is no
// /mcp (executors) and no /owner (the owner channel).
func (s *session) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cleanroom/hint", s.hint)
	mux.HandleFunc("/cleanroom/result", s.result)
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

func (s *session) model() http.Handler {
	if s.b.cfg.Model == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no model egress is configured", http.StatusServiceUnavailable)
		})
	}
	return s.b.cfg.Meter.Wrap(s.id, s.b.cfg.Model(s.id))
}

func (s *session) hint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, s.job.Hint)
}

// result takes the clean room's output. A refused result can be fixed and
// sent again until the job's time runs out; an accepted one ends the job.
func (s *session) result(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxResultBytes+1))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if len(data) > MaxResultBytes {
		http.Error(w, "result too large", http.StatusRequestEntityTooLarge)
		return
	}
	var res Result
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		http.Error(w, "result is not {\"files\": {...}, \"fixtures\": {...}}", http.StatusBadRequest)
		return
	}
	if err := res.check(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// One result is stored at a time, without holding s.mu: the vm
	// manager calls open with the machine locked, and Get below takes
	// that lock.
	s.mu.Lock()
	busy := s.finished || s.storing
	s.storing = !busy
	s.mu.Unlock()
	if busy {
		http.Error(w, "this clean room's job is finished", http.StatusConflict)
		return
	}
	m, err := s.b.cfg.Machines.Get(s.id)
	if err == nil {
		err = s.b.isClean(m)
	}
	if err != nil {
		// A clean room that is not clean any more publishes nothing.
		s.fail("result refused: " + err.Error())
		http.Error(w, "result refused", http.StatusForbidden)
		return
	}
	a, err := s.b.store.put(Manifest{
		ID: artifactID(s.job), Job: s.job.ID, Hint: json.RawMessage(s.job.Hint),
		Output: Output[s.kind], Embargo: s.embargo,
		Image: m.Spec.Image, Machine: s.id, Day: s.b.cfg.Now().UTC().Format("2006-01-02"),
		Fixtures: res.Fixtures,
	}, res.Files)
	s.mu.Lock()
	s.storing = false
	if err == nil && !s.finished {
		s.finished, s.artifact = true, a.m.ID
		close(s.done)
	}
	s.mu.Unlock()
	if err != nil {
		s.b.cfg.Logf("cleanroom: storing %s: %v", s.id, err)
		http.Error(w, "could not store the result", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"artifact": a.m.ID})
}

// artifactID is the one artifact a job can produce.
func artifactID(j *job) string { return "a-" + j.ID }
