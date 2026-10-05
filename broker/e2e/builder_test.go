package e2e

// REQ: LOOP-2, LOOP-6, REV-5, OP-8

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/skill/format"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// W3-builder-image under gVisor: Loop 1's builder runs a job in a real
// private lb- machine from the minimal builder image
// (guest/builder/build-rootfs.sh). The brief client inside reads the
// brief, calls the metered model route (a scripted model stands in for a
// provider), and posts a procedure the runner's own decoder accepts. A
// model that never answers usefully ends the job early with no result.
func TestIntegrationBuilderImage(t *testing.T) {
	runsc, rootfs := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_BUILDER_ROOTFS")
	if runsc == "" || rootfs == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC and AGENTOS_BUILDER_ROOTFS (guest/builder/build-rootfs.sh) and run as root")
	}
	var launch struct{ Argv, Env []string }
	b, err := os.ReadFile("../../guest/builder/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &launch); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(dir, "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var answer atomic.Value
	var calls atomic.Int32
	model := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		content := "nothing useful"
		if len(req.Messages) == 2 && strings.Contains(req.Messages[1].Content, `"failure:mail/send"`) {
			content = answer.Load().(string)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}},
			"usage":   map[string]any{"prompt_tokens": 100, "completion_tokens": 50},
		})
	})
	answer.Store(`{"files": {"procedures/fix.json": {"version": 1, "kind": "procedure", "runs": 1,
		"slots": [{"name": "to", "type": "email", "max": 320}],
		"steps": [{"account": "mail", "action": "send", "params": {"to": {"slot": "to"}}}]}}}`)

	ctx := context.Background()
	adm, err := admission.New(admission.Config{CapacityMB: 4096}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := &builderRef{}
	m, err := vm.Open(ctx, vm.Config{
		StateDir:  filepath.Join(dir, "machines"),
		Images:    map[string]string{"builder": rootfs},
		Runtime:   &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(dir, "runsc")},
		Admit:     adm,
		NoCgroups: true,
		NoQuota:   true,
		Services:  ref,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Unmount(filepath.Join(dir, "runsc", "null-netns"), syscall.MNT_DETACH) })
	bld, err := loopbuild.New(loopbuild.Config{
		Dir: filepath.Join(dir, "build"), Machines: m, Image: "builder", MemMB: loopbuild.DefaultMemMB,
		Argv: launch.Argv, Env: launch.Env, Meter: mtr, Timeout: 2 * time.Minute, Poll: 100 * time.Millisecond,
		Model: func(string) http.Handler { return http.StripPrefix("/v1/chat/completions", model) },
		Logf:  t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref.s = bld.Services(nil)
	br := loops.Brief{Hypothesis: loops.Hypothesis{Signal: loops.SignalFailure, Class: change.ClassProcedure, Key: "failure:mail/send",
		Evidence: []journal.Status{{Intent: journal.Intent{ID: "t1", GoalID: "g1", Account: "mail", Action: "send"}, State: journal.NotApplied}}}}

	start := time.Now()
	cand, err := bld.Build(ctx, br)
	if err != nil {
		t.Fatalf("build: %v (after %v)", err, time.Since(start))
	}
	t.Logf("builder job: %v, %d model calls", time.Since(start), calls.Load())
	if len(cand.Files) != 1 || cand.Public || cand.Origin != "loop1" {
		t.Fatalf("candidate %+v", cand)
	}
	for p, text := range cand.Files {
		s, err := format.DecodeFile(p, text)
		if err != nil || s.Kind != format.KindProcedure {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if len(m.Machines()) != 0 {
		t.Fatalf("machines left: %v", m.Machines())
	}

	// A model that never helps: the client gives up on /done and the job
	// ends long before its time.
	answer.Store("I cannot help with that.")
	start = time.Now()
	if _, err := bld.Build(ctx, br); err == nil {
		t.Fatal("a useless model made a candidate")
	}
	if d := time.Since(start); d > time.Minute {
		t.Fatalf("the job waited %v after the builder gave up", d)
	}
}

// builderRef hands the vm manager the builder's services once both exist.
type builderRef struct{ s vm.Services }

func (r *builderRef) Open(id string) (string, error) { return r.s.Open(id) }
func (r *builderRef) Close(id string)                { r.s.Close(id) }
