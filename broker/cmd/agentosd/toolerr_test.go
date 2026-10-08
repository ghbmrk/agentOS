package main

// REQ: RES-4, CAP-8

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/question"
	"github.com/ghbmrk/agentos/broker/recalltool"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
	"github.com/ghbmrk/agentos/broker/workers"
)

// canaryToken names a synthetic host directory: no real box has it, and
// every failing backend below names a path under it.
const canaryToken = "agentos-canary-7f3a"

// canaryMachines is a machine manager whose every answer is an error
// naming a host path, as the vm package's own errors do.
type canaryMachines struct{ dir string }

var _ workers.Machines = canaryMachines{}

func (c canaryMachines) err(op, id string) error {
	return fmt.Errorf("vm: %s %s: open %s/machines/%s/overlay: input/output error", op, id, c.dir, id)
}

// Get knows the calling machine, so each worker tool reaches the failing
// call behind it.
func (c canaryMachines) Get(id string) (vm.Machine, error) {
	if id == "m1" {
		return vm.Machine{ID: id, Lineage: id, Label: vm.Private}, nil
	}
	return vm.Machine{}, c.err("get", id)
}
func (c canaryMachines) TryGet(string) (vm.Machine, bool) { return vm.Machine{}, false }
func (c canaryMachines) Machines() []string               { return nil }
func (c canaryMachines) Workers(string) []string          { return nil }
func (c canaryMachines) ForkSiblings(id string) (string, []string, error) {
	return "", nil, c.err("siblings", id)
}
func (c canaryMachines) CreateWorker(_ context.Context, id, _ string, _ vm.Spec) (vm.Machine, error) {
	return vm.Machine{}, c.err("create", id)
}
func (c canaryMachines) Exec(_ context.Context, id string, _ vm.Command, _ time.Duration) (vm.ExecResult, error) {
	return vm.ExecResult{}, c.err("exec", id)
}
func (c canaryMachines) Checkpoint(_ context.Context, id string) (vm.Snapshot, error) {
	return vm.Snapshot{}, c.err("checkpoint", id)
}
func (c canaryMachines) Fork(_ context.Context, id string, _ []string) (vm.Snapshot, error) {
	return vm.Snapshot{}, c.err("fork", id)
}
func (c canaryMachines) Snapshot(id string) (vm.Snapshot, error) {
	return vm.Snapshot{}, c.err("snapshot", id)
}
func (c canaryMachines) Diff(_, a, _ string) ([]overlay.Change, error) {
	return nil, c.err("diff", a)
}
func (c canaryMachines) Rollback(_ context.Context, id, _ string) error { return c.err("rollback", id) }
func (c canaryMachines) Destroy(_ context.Context, id string) error     { return c.err("destroy", id) }
func (c canaryMachines) RaiseLabel(id string, _ vm.Label) error         { return c.err("label", id) }
func (c canaryMachines) Park(_ context.Context, id string) (vm.Snapshot, error) {
	return vm.Snapshot{}, c.err("park", id)
}
func (c canaryMachines) DeleteFiles(_ context.Context, id string, _ vm.Deletion) (vm.DeleteReport, error) {
	return vm.DeleteReport{}, c.err("delete", id)
}

// canaryEffects is a journal whose every answer is an error naming its
// file.
type canaryEffects struct{ dir string }

func (c canaryEffects) err() error {
	return fmt.Errorf("journal: write %s/journal.log: no space left on device", c.dir)
}
func (c canaryEffects) Submit(journal.Intent) (journal.Status, error) {
	return journal.Status{}, c.err()
}
func (c canaryEffects) Authorize(context.Context, string) (journal.Status, error) {
	return journal.Status{}, c.err()
}
func (c canaryEffects) Dispatch(context.Context, string) (journal.Status, error) {
	return journal.Status{}, c.err()
}
func (c canaryEffects) Get(string) (journal.Status, error) { return journal.Status{}, c.err() }

type oneLineage struct{}

func (oneLineage) Step(context.Context, string) error { return nil }
func (oneLineage) RaisePrivate(string) error          { return nil }
func (oneLineage) Lineage(id string) (string, error)  { return id, nil }

// TestToolErrorsNameNoHostPath drives every tool agentosd registers on a
// guest socket (registeredTools, and the plane's own effect tools) with
// every backend failing with errors that name a host path under a
// canary directory. The canary reaches the broker's log and appears in
// no tool result or error the guest receives (SR2-3g, security F5 on
// SR2-3f).
func TestToolErrorsNameNoHostPath(t *testing.T) {
	var logBuf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&logBuf)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	work := t.TempDir()
	dir := filepath.Join(work, canaryToken)
	qdir := filepath.Join(dir, "questions")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The question book opens, then its state directory turns into a
	// file, so every write names its path.
	book, err := question.New(question.Config{
		Send:   func(string) error { return fmt.Errorf("write %s/modem.sock: broken pipe", dir) },
		Now:    func(context.Context) (time.Time, error) { return time.Now(), nil },
		Reveal: func(m string) error { return fmt.Errorf("label %s/%s: input/output error", dir, m) },
		Path:   filepath.Join(qdir, "questions.json"),
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(qdir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qdir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	qs := &questions{}
	qs.b.Store(book)

	tree := newLiveTree(func(string, ...any) {})
	tree.label = func(m string) (vm.Label, error) { return 0, fmt.Errorf("stat %s/labels/%s: no such file", dir, m) }
	tree.markReady()

	wt := &workers.Tools{M: canaryMachines{dir: dir}, Image: "base", Argv: []string{"/sbin/init"}, MaxMemMB: 512}
	tools := registeredTools(qs, tree, &recalltool.Late{}, wt)

	plane, err := guest.New(guest.Config{
		Dir:      filepath.Join(work, "g"),
		Machines: oneLineage{},
		Effects:  canaryEffects{dir: dir},
		Route:    func(string) (string, bool) { return "mail", true },
		Tools:    tools,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	mdir, err := plane.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(mdir, guest.Socket)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	id := 0
	rpc := func(method string, params any) string {
		t.Helper()
		id++
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		resp, err := client.Post("http://broker/mcp", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(rpc("tools/list", nil)), &list); err != nil {
		t.Fatal(err)
	}
	served := map[string]bool{}
	for _, tl := range list.Result.Tools {
		served[tl.Name] = true
	}
	// Every family agentosd registers is listed: the effect, question,
	// managed-tree, recall and worker tools.
	for _, n := range []string{"effect_request", "effect_status", question.ToolAsk, question.ToolStatus, toolTree, "recall_search", "recall_note", "owner_preferences", "worker_create", "worker_exec", "worker_destroy"} {
		if !served[n] {
			t.Fatalf("%s not listed: %v", n, served)
		}
	}

	refRE := regexp.MustCompile(`failed \(ref [0-9a-f]{8}\); the broker's log has the detail`)
	refs := 0
	check := func(name string, args any) {
		t.Helper()
		body := rpc("tools/call", map[string]any{"name": name, "arguments": args})
		if strings.Contains(body, canaryToken) || strings.Contains(body, work) {
			t.Errorf("%s(%v): the guest saw a host path: %s", name, args, body)
		}
		if refRE.MatchString(body) {
			refs++
		}
	}
	wait := 5.0
	for _, tl := range list.Result.Tools {
		for _, args := range []any{nil, map[string]any{}, "not an object", sample(tl.InputSchema)} {
			check(tl.Name, args)
		}
	}
	// Arguments that pass each family's checks and reach the failing
	// backend.
	check(question.ToolAsk, map[string]any{"request_id": "q1", "question": "Ship the draft today?", "default": "wait", "choices": []string{"go ahead", "wait"}, "wait_minutes": wait})
	check(question.ToolStatus, map[string]any{"request_id": "q1"})
	check("effect_request", map[string]any{"request_id": "r1", "account": "owner-mail", "action": "send", "params": map[string]any{"to": "a@example.com"}})
	check("effect_status", map[string]any{"request_id": "r1"})
	check("worker_create", map[string]any{"name": "w1"})
	check("worker_exec", map[string]any{"worker": "w1", "argv": []string{"true"}})

	// The failures were real: the canary reached the broker's log, under
	// the refs the guest was given.
	if refs == 0 || !strings.Contains(logBuf.String(), canaryToken) {
		t.Fatalf("no failure carried the canary to the log (refs %d): %q", refs, logBuf.String())
	}
}

// sample is arguments that fit schema: each property a value of its type.
func sample(schema map[string]any) map[string]any {
	out := map[string]any{}
	props, _ := schema["properties"].(map[string]any)
	for k, v := range props {
		p, _ := v.(map[string]any)
		switch p["type"] {
		case "string":
			out[k] = "w1"
		case "number", "integer":
			out[k] = 1
		case "boolean":
			out[k] = true
		case "array":
			out[k] = []string{"w1"}
		case "object":
			out[k] = map[string]any{}
		}
	}
	return out
}
