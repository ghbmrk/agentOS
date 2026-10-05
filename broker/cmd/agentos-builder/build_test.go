package main

// REQ: LOOP-2, LOOP-6, CHG-5

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/skill/format"
)

// fakeBroker is a builder machine's socket as loopbuild serves it.
type fakeBroker struct {
	mu        sync.Mutex
	brief     string
	replies   []string // model answers, in order
	modelCode int      // when set, the model route answers this
	refuse    int      // candidates to refuse with 422 first
	asked     [][]message
	submitted []map[string]string
	done      int
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/brief":
		io.WriteString(w, f.brief)
	case "/model/v1/chat/completions":
		if f.modelCode != 0 {
			http.Error(w, "this job's model budget is spent", f.modelCode)
			return
		}
		var req struct {
			Messages []message `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.asked = append(f.asked, req.Messages)
		reply := "no more answers"
		if len(f.replies) > 0 {
			reply, f.replies = f.replies[0], f.replies[1:]
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	case "/candidate":
		var sub struct {
			Files map[string]string `json:"files"`
		}
		json.NewDecoder(r.Body).Decode(&sub)
		f.submitted = append(f.submitted, sub.Files)
		if f.refuse > 0 {
			f.refuse--
			http.Error(w, "procedures/p0123456789ab: CANARY-refusal", http.StatusUnprocessableEntity)
			return
		}
		io.WriteString(w, `{"accepted":true}`)
	case "/done":
		f.done++
		io.WriteString(w, `{"done":true}`)
	default:
		http.NotFound(w, r)
	}
}

func serve(t *testing.T, f *fakeBroker) *builder {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	return &builder{hc: hc, model: "broker-default", rounds: defaultRounds, maxTokens: 100, logf: t.Logf}
}

const procBrief = `{"signal":"failure","class":"procedure","key":"failure:mail/send","writes":"procedures",
"steps":[{"task":"goal:g1","account":"mail","action":"send","state":"not_applied","params":{"to":"dee@example.test"}}],
"cases":[{"id":"c1","input":{"q":1},"expect":"sent","outcome":"accepted"}],
"limits":{"files":32,"file_bytes":65536,"bytes":524288}}`

// A procedure as a model might write it: fenced, keys in any order, id
// missing (the path gives it).
const procAnswer = "Here it is:\n```json\n" + `{"files": {"procedures/p0123456789ab.json": {
 "steps": [{"action": "send", "account": "mail", "params": {"to": {"slot": "to"}}}],
 "slots": [{"type": "email", "name": "to", "max": 320}],
 "runs": 1, "kind": "procedure", "version": 1}}}` + "\n```"

// W3-builder-image: the brief client sends the brief to the model route,
// turns the answer into the canonical file the runner accepts, checked
// with the runner's own validator, and submits it once.
func TestTheBuilderTurnsTheBriefIntoACandidate(t *testing.T) {
	f := &fakeBroker{brief: procBrief, replies: []string{procAnswer}}
	if err := serve(t, f).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 1 || f.asked[0][0].Role != "system" || !strings.Contains(f.asked[0][0].Content, "procedures/") ||
		f.asked[0][1].Content != procBrief {
		t.Fatalf("asked %+v", f.asked)
	}
	if len(f.submitted) != 1 || f.done != 0 {
		t.Fatalf("submitted %v, done %d", f.submitted, f.done)
	}
	if len(f.submitted[0]) != 1 {
		t.Fatalf("submitted %v", f.submitted[0])
	}
	var name, text string
	for name, text = range f.submitted[0] {
	}
	s, err := format.DecodeFile(name, []byte(text))
	if err != nil || s.Kind != format.KindProcedure || s.Steps[0].Account != "mail" {
		t.Fatalf("submitted %q: %v", text, err)
	}
}

// A refusal, the local check's or the broker's 422, goes back to the
// model, which answers again; the broker's refusal text reaches it.
func TestRefusalsGoBackToTheModel(t *testing.T) {
	bad := `{"files": {"security/x.json": "{}"}}`
	f := &fakeBroker{brief: procBrief, replies: []string{bad, procAnswer, procAnswer}, refuse: 1}
	if err := serve(t, f).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 3 || len(f.submitted) != 2 {
		t.Fatalf("%d model calls, %d submissions", len(f.asked), len(f.submitted))
	}
	second, third := f.asked[1], f.asked[2]
	if !strings.Contains(second[len(second)-1].Content, "under procedures/") ||
		!strings.Contains(third[len(third)-1].Content, "CANARY-refusal") {
		t.Fatalf("refusals not passed on: %q / %q", second[len(second)-1].Content, third[len(third)-1].Content)
	}
}

// With nothing to submit after its rounds, or once the model route
// refuses (the job's cap), the builder says so on /done and stops.
func TestTheBuilderGivesUpOnDone(t *testing.T) {
	f := &fakeBroker{brief: procBrief, replies: []string{"no", "still no", "{}", `{"files": {}}`}}
	if err := serve(t, f).run(context.Background()); err == nil {
		t.Fatal("no candidate, no error")
	}
	if len(f.asked) != defaultRounds || len(f.submitted) != 0 || f.done != 1 {
		t.Fatalf("%d model calls, %d submissions, %d done", len(f.asked), len(f.submitted), f.done)
	}

	capped := &fakeBroker{brief: procBrief, modelCode: http.StatusTooManyRequests}
	if err := serve(t, capped).run(context.Background()); err == nil || capped.done != 1 {
		t.Fatalf("capped: %v, %d done", err, capped.done)
	}
}

// The local check refuses what the broker would: other namespaces,
// escaping paths, bad file names, invalid skills and limits.
func TestPrepareChecksWhatTheBrokerChecks(t *testing.T) {
	var br Brief
	if err := json.Unmarshal([]byte(procBrief), &br); err != nil {
		t.Fatal(err)
	}
	for name, answer := range map[string]string{
		"other namespace": `{"files": {"skills/k0123456789ab.json": {}}}`,
		"escape":          `{"files": {"procedures/../security/p0123456789ab.json": {}}}`,
		"not json":        `{"files": {"procedures/mail.txt": {}}}`,
		"nested":          `{"files": {"procedures/a/p.json": {}}}`,
		"literal":         `{"files": {"procedures/p0123456789ab.json": {"version":1,"kind":"procedure","runs":1,"slots":[],"steps":[{"account":"mail","action":"send","params":{"to":{"lit":"x@example.test"}}}]}}}`,
		"broker step":     `{"files": {"procedures/p0123456789ab.json": {"version":1,"kind":"procedure","runs":1,"slots":[],"steps":[{"account":"broker","action":"x"}]}}}`,
		"no files":        `{"files": {}}`,
		"no json":         `sorry`,
	} {
		if _, err := prepare(br, answer); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	br.Writes, br.Limits.Files = "context", 1
	if _, err := prepare(br, `{"files": {"context/agent.json": {"select": ["mail"]}, "context/b.json": {"select": ["mail"]}}}`); err == nil {
		t.Error("too many files: accepted")
	}
	got, err := prepare(br, `{"files": {"context/agent.json": "{\"select\": [\"mail\"]}"}}`)
	if err != nil || got["context/agent.json"] != `{"select":["mail"]}` {
		t.Fatalf("context rule %v %v", got, err)
	}
	if _, err := prepare(br, `{"files": {"context/agent.json": {"select": ["mail"], "grant": "all"}}}`); err == nil {
		t.Error("a context rule with other fields: accepted")
	}
}
