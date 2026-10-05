// Package workers serves the worker-machine tools to guests (CAP-8): a
// guest creates machines with no agent runtime from a base image, runs
// commands and moves files in them, and checkpoints, forks, diffs, rolls
// back and destroys them.
//
// A worker inherits its creator's isolation (a gVisor machine with no
// network and no broker socket), snapshot custody (it joins the creator's
// lineage, so deletion reach takes it back with the rest, CAP-3), budget
// reservation (the creator's admission class, a declared memory budget
// RES-2 admits or refuses) and data label (REV-5). Only machines of the
// lineage that made a worker can name it; a public machine cannot read a
// private worker, and a private machine writing into a public worker
// raises it to private first (A14).
package workers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// Machines is the part of the machine manager (vm.Manager) the tools use.
type Machines interface {
	Get(id string) (vm.Machine, error)
	TryGet(id string) (vm.Machine, bool)
	Machines() []string
	Workers(lineage string) []string
	ForkSiblings(id string) (string, []string, error)
	CreateWorker(ctx context.Context, id, lineage string, s vm.Spec) (vm.Machine, error)
	Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error)
	Checkpoint(ctx context.Context, id string) (vm.Snapshot, error)
	Fork(ctx context.Context, id string, ids []string) (vm.Snapshot, error)
	Snapshot(id string) (vm.Snapshot, error)
	Diff(requester, a, b string) ([]overlay.Change, error)
	Rollback(ctx context.Context, id, snapID string) error
	Destroy(ctx context.Context, id string) error
	RaiseLabel(id string, l vm.Label) error
	Park(ctx context.Context, id string) (vm.Snapshot, error)
}

// Limits bound what one lineage may ask for.
const (
	MaxWorkers     = 16        // live workers per lineage; A15 needs 8
	DefaultMemMB   = 256       // a worker's budget when none is asked; on the floor host 7 fit beside the agent, 8 at 192 MiB (K16)
	MinMemMB       = 64        // below this a base image does not start
	SmallMemMB     = 192       // the smaller size worker_fit offers when it fits more (K16)
	MaxArgs        = 64        // arguments in one command
	MaxArgBytes    = 16 << 10  // all arguments together
	MaxStdin       = 512 << 10 // stdin or a written file; under the guest plane's 1 MiB body
	MaxOutput      = 64 << 10  // each of stdout and stderr
	DefaultTimeout = time.Minute
	MaxTimeout     = 10 * time.Minute
	MaxChanges     = 500     // diff entries returned
	MaxOffset      = 1 << 50 // read offsets (1 PiB): offset+1 cannot overflow
	// IdleAfter parks a worker no tool has named for this long (UX-146-1).
	IdleAfter = time.Hour
)

// Tools serves the worker tools. Image and Argv build every worker; MaxMemMB
// caps one worker's budget.
type Tools struct {
	M        Machines
	Image    string
	Argv     []string
	MaxMemMB int64
	Now      func() time.Time // nil is time.Now
	// Stopped reports the owner's STOP: while it holds, no worker command
	// starts (security R2 on #146). Nil is never stopped.
	Stopped func() bool
	// Free, if set, is admission's declared room for a class (RoomFor);
	// Avail, if set, is measured free memory for new machines in MiB.
	// How many workers fit is the smaller of the two (CAP-1); admission
	// still decides each start.
	Free  func(admission.Class) int64
	Avail func() (int64, error)

	// mu guards used and pending. Creating workers reserves their IDs in
	// pending under it, so the per-lineage count cannot be raced past
	// (security R1 on #146), but the machines are made without it, so a
	// fork waiting on a busy worker holds up no other call (L3 MUST-4).
	mu      sync.Mutex
	used    map[string]time.Time // worker ID -> last named by a tool
	pending map[string]string    // worker ID being made -> its lineage
	calls   map[string]int       // calling machine -> its worker tool calls in flight
	rooms   map[string]fitRoom   // lineage -> its rounded room (CAP-1)
}

// Busy reports whether machine has a worker tool call in flight, such as
// a running worker_exec: it has work in hand, so the agent sleeper does
// not stop it (PE7 condition 2, L3 on #149).
func (t *Tools) Busy(machine string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls[machine] > 0
}

func (t *Tools) called(machine string, d int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.calls == nil {
		t.calls = map[string]int{}
	}
	if t.calls[machine] += d; t.calls[machine] <= 0 {
		delete(t.calls, machine)
	}
}

func (t *Tools) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tools) touch(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used == nil {
		t.used = map[string]time.Time{}
	}
	t.used[id] = t.now()
}

const (
	toolCreate   = "worker_create"
	toolExec     = "worker_exec"
	toolRead     = "worker_read_file"
	toolWrite    = "worker_write_file"
	toolCkpt     = "worker_checkpoint"
	toolFork     = "worker_fork"
	toolDiff     = "worker_diff"
	toolRollback = "worker_rollback"
	toolDestroy  = "worker_destroy"
	toolList     = "worker_list"
	toolFit      = "worker_fit"
	toolKeep     = "worker_keep"
)

func obj(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

var (
	pName   = map[string]any{"type": "string", "description": "The worker's name: lowercase letters, digits and '-'; at most 20."}
	pSnap   = map[string]any{"type": "string", "description": "A snapshot id one of your workers' tools returned."}
	pPath   = map[string]any{"type": "string", "description": "An absolute path inside the worker."}
	strList = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
)

// List is the worker tools' descriptions.
func (t *Tools) List() []map[string]any {
	return []map[string]any{
		{"name": toolCreate, "description": "Start a worker machine: a sandboxed machine with no agent, no network and no broker tools, built from the base image, that you drive with the other worker_ tools. It runs on your admission class and the memory you ask for; the box refuses it when there is no room. It holds your data label: a worker made by a private machine is private. Smaller workers fit more: on the smallest box 7 fit beside you at 256 MiB, 8 at 192 MiB; worker_fit says how many fit now.",
			"inputSchema": obj(map[string]any{"name": pName, "mem_mb": map[string]any{"type": "number", "description": fmt.Sprintf("Memory budget in MiB; default %d, at most %d.", DefaultMemMB, t.MaxMemMB)}}, "name")},
		{"name": toolExec, "description": "Run a command in a worker, as root from /, and wait for it. Returns exit_code, stdout, stderr (each capped), truncated and timed_out. A non-zero exit is a result, not an error. " +
			"To move a directory tree, send a tar archive as stdin_base64 to [\"tar\", \"-x\", \"-C\", \"/dir\"], or read one back with [\"tar\", \"-c\", \"-C\", \"/dir\", \".\"] and output_base64.",
			"inputSchema": obj(map[string]any{"name": pName, "argv": strList,
				"stdin":           map[string]any{"type": "string"},
				"stdin_base64":    map[string]any{"type": "string", "description": "Binary stdin, base64; instead of stdin."},
				"output_base64":   map[string]any{"type": "boolean", "description": "Return stdout and stderr base64-encoded, for binary output."},
				"timeout_seconds": map[string]any{"type": "number", "description": fmt.Sprintf("Default %d, at most %d.", int(DefaultTimeout.Seconds()), int(MaxTimeout.Seconds()))}}, "name", "argv")},
		{"name": toolRead, "description": fmt.Sprintf("Read a file from a worker, or length bytes of it from offset (at most %d at once; its image needs tail). truncated: true means more follows: read again from offset+length.", MaxOutput),
			"inputSchema": obj(map[string]any{"name": pName, "path": pPath,
				"offset": map[string]any{"type": "integer", "description": fmt.Sprintf("Byte offset to start at; default 0, at most %d.", int64(MaxOffset))},
				"length": map[string]any{"type": "integer", "description": fmt.Sprintf("Bytes to read; default and at most %d.", MaxOutput)},
				"base64": map[string]any{"type": "boolean", "description": "Return the content base64-encoded, for binary files."}}, "name", "path")},
		{"name": toolWrite, "description": "Write a file in a worker, replacing it (its image needs tee).",
			"inputSchema": obj(map[string]any{"name": pName, "path": pPath, "content": map[string]any{"type": "string"},
				"content_base64": map[string]any{"type": "string", "description": "Binary content, base64; instead of content."}}, "name", "path")},
		{"name": toolCkpt, "description": "Checkpoint a worker, memory included; returns the snapshot id to roll back to or diff.",
			"inputSchema": obj(map[string]any{"name": pName}, "name")},
		{"name": toolFork, "description": "Checkpoint a worker and start one new worker per name from it, memory included; each is admitted on its own budget, and either all start or none do. With up_to_fit, only as many as fit now start (in the order named) and the rest come back as skipped.",
			"inputSchema": obj(map[string]any{"name": pName, "into": strList,
				"up_to_fit": map[string]any{"type": "boolean", "description": "Start only as many forks as fit (see worker_fit)."}}, "name", "into")},
		{"name": toolFit, "description": "How many more workers of mem_mb fit now, from the box's free memory (measured and as budgeted for your class, rounded down, refreshed every few seconds) and your worker cap. Use it to pick how many approaches to try in parallel; 0 means try them one at a time.",
			"inputSchema": obj(map[string]any{"mem_mb": map[string]any{"type": "integer", "description": fmt.Sprintf("Memory per worker in MiB; default %d.", DefaultMemMB)}})},
		{"name": toolKeep, "description": "Keep the winner of a fork: destroy every other worker forked from the same snapshot as this one. The worker it was forked from, and your other workers, stay.",
			"inputSchema": obj(map[string]any{"name": pName}, "name")},
		{"name": toolDiff, "description": "List the files that differ between two snapshots of your workers.",
			"inputSchema": obj(map[string]any{"a": pSnap, "b": pSnap}, "a", "b")},
		{"name": toolRollback, "description": "Restart a worker from one of its snapshots (or the one it was forked from). This also revives a stopped worker: the broker checkpoints and stops a worker no tool has named for an hour, or whose creator has stopped, and worker_list shows the snapshot to roll back to.",
			"inputSchema": obj(map[string]any{"name": pName, "snapshot": pSnap}, "name", "snapshot")},
		{"name": toolDestroy, "description": "Stop a worker and free its memory. Its snapshots stay in the broker's custody.",
			"inputSchema": obj(map[string]any{"name": pName}, "name")},
		{"name": toolList, "description": "List your workers: name, state, label, memory and newest snapshot.",
			"inputSchema": obj(map[string]any{})},
	}
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)

// workerID names a lineage's worker. The lineage's hash keeps lineages
// apart; ownership is still checked against the manager's record.
func workerID(lineage, name string) string {
	h := sha256.Sum256([]byte(lineage))
	return vm.WorkerPrefix + hex.EncodeToString(h[:4]) + "-" + name
}

func nameOf(lineage, id string) string {
	return strings.TrimPrefix(id, workerID(lineage, ""))
}

// errNoWorker never says whether another lineage has such a worker.
var errNoWorker = errors.New("no such worker")

type caller struct {
	machine, lineage string
	label            vm.Label
	spec             vm.Spec
}

// Call serves one worker tool for machine of lineage; handled is false for
// names it does not serve.
func (t *Tools) Call(ctx context.Context, machine, lineage, name string, raw json.RawMessage) (string, bool, error) {
	if !strings.HasPrefix(name, "worker_") {
		return "", false, nil
	}
	if strings.HasPrefix(machine, vm.WorkerPrefix) {
		return "", true, errors.New("a worker cannot drive workers")
	}
	me, err := t.M.Get(machine)
	if err != nil || me.Lineage != lineage {
		return "", true, errors.New("broker: unknown machine")
	}
	c := caller{machine: machine, lineage: lineage, label: me.Label, spec: me.Spec}
	t.called(machine, 1)
	defer t.called(machine, -1)
	var out any
	switch name {
	case toolCreate:
		out, err = t.create(ctx, c, raw)
	case toolExec:
		out, err = t.exec(ctx, c, raw)
	case toolRead:
		out, err = t.read(ctx, c, raw)
	case toolWrite:
		out, err = t.write(ctx, c, raw)
	case toolCkpt:
		out, err = t.checkpoint(ctx, c, raw)
	case toolFork:
		out, err = t.fork(ctx, c, raw)
	case toolDiff:
		out, err = t.diff(c, raw)
	case toolRollback:
		out, err = t.rollback(ctx, c, raw)
	case toolDestroy:
		out, err = t.destroy(ctx, c, raw)
	case toolList:
		out, err = t.list(c)
	case toolFit:
		out, err = t.fitTool(c, raw)
	case toolKeep:
		out, err = t.keep(ctx, c, raw)
	default:
		return "", true, fmt.Errorf("no tool %q", name)
	}
	if err != nil {
		return "", true, err
	}
	b, err := json.Marshal(out)
	return string(b), true, err
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return errors.New("arguments must be an object of the documented fields")
	}
	return nil
}

// worker resolves name to one of the caller's lineage's workers.
func (t *Tools) worker(c caller, name string) (vm.Machine, error) {
	if !nameRE.MatchString(name) {
		return vm.Machine{}, errors.New("name: lowercase letters, digits and '-', at most 20")
	}
	w, err := t.M.Get(workerID(c.lineage, name))
	if err != nil || w.Lineage != c.lineage {
		return vm.Machine{}, errNoWorker
	}
	t.touch(w.ID)
	return w, nil
}

// owned resolves name to the ID of one of the caller's lineage's workers
// from the machine table alone, never a worker's lock, so destroy and
// keep do not wait behind a command (L3 MUST-1 on #158, K11).
func (t *Tools) owned(c caller, name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", errors.New("name: lowercase letters, digits and '-', at most 20")
	}
	id := workerID(c.lineage, name)
	if !slices.Contains(t.M.Workers(c.lineage), id) {
		return "", errNoWorker
	}
	return id, nil
}

// readable refuses a public machine anything from a private worker or
// snapshot (REV-5).
func readable(c caller, l vm.Label) error {
	if l > c.label {
		return errors.New("that worker holds private data; a public machine cannot read it")
	}
	return nil
}

// reserve claims ids for lineage's new workers, refusing past
// MaxWorkers; settle hands them back. The count reads the machine table
// alone, never a worker's lock.
func (t *Tools) reserve(lineage string, ids []string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.heldLocked(lineage)
	for _, id := range ids {
		if n[id] {
			return false
		}
		n[id] = true
	}
	if len(n) > MaxWorkers {
		return false
	}
	if t.pending == nil {
		t.pending = map[string]string{}
	}
	for _, id := range ids {
		t.pending[id] = lineage
	}
	return true
}

// heldLocked is the set of lineage's workers, made or being made: a
// worker the manager is still making is in both its table and pending,
// and counts once (L3 SHOULD-4 on #158).
func (t *Tools) heldLocked(lineage string) map[string]bool {
	n := map[string]bool{}
	for _, id := range t.M.Workers(lineage) {
		n[id] = true
	}
	for id, l := range t.pending {
		if l == lineage {
			n[id] = true
		}
	}
	return n
}

// workerClass is the admission class a caller's workers run on: its own,
// but never above accepted work, so workers yield to memory pressure and
// never outrank the owner's foreground machines (L3 SHOULD-1 on #158,
// K3).
func workerClass(c caller) admission.Class {
	if c.spec.Class.Outranks(admission.Accepted) {
		return admission.Accepted
	}
	return c.spec.Class
}

// settle ends a reservation; made says the workers now exist.
func (t *Tools) settle(ids []string, made bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used == nil {
		t.used = map[string]time.Time{}
	}
	for _, id := range ids {
		delete(t.pending, id)
		if made {
			t.used[id] = t.now()
		}
	}
}

func (t *Tools) create(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Name  string `json:"name"`
		MemMB int64  `json:"mem_mb"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(a.Name) {
		return nil, errors.New("name: lowercase letters, digits and '-', at most 20")
	}
	if a.MemMB == 0 {
		a.MemMB = DefaultMemMB
	}
	if a.MemMB < MinMemMB || a.MemMB > t.MaxMemMB {
		return nil, fmt.Errorf("mem_mb must be between %d and %d", MinMemMB, t.MaxMemMB)
	}
	id := workerID(c.lineage, a.Name)
	if !t.reserve(c.lineage, []string{id}) {
		return nil, fmt.Errorf("at most %d workers at once, each with its own name; destroy one first", MaxWorkers)
	}
	s := vm.Spec{Image: t.Image, Class: workerClass(c), MemMB: a.MemMB, Argv: t.Argv, Label: c.label}
	w, err := t.M.CreateWorker(ctx, id, c.lineage, s)
	t.settle([]string{id}, err == nil)
	if err != nil {
		return nil, startErr(a.Name, err)
	}
	return map[string]any{"name": a.Name, "label": w.Label.String(), "mem_mb": w.Spec.MemMB}, nil
}

type execOut struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
	TimedOut  bool   `json:"timed_out"`
}

var errStopped = errors.New("the owner sent STOP: worker commands wait until RESUME")

func (t *Tools) run(ctx context.Context, c caller, name string, cmd vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	if t.Stopped != nil && t.Stopped() {
		return vm.ExecResult{}, errStopped
	}
	w, err := t.worker(c, name)
	if err != nil {
		return vm.ExecResult{}, err
	}
	// A command both writes into the worker and returns what it sees:
	// Exec raises the worker to the caller's label and checks the caller
	// may read it under the worker's lock, so no other machine's raise
	// lands between the check and the command (A14, REV-5).
	cmd.As = c.label
	// Checked again under the worker's lock, so a command queued behind
	// another cannot start after STOP (OP-6).
	cmd.Hold = t.Stopped
	if cmd.MaxOutput == 0 {
		cmd.MaxOutput = MaxOutput
	}
	r, err := t.M.Exec(ctx, w.ID, cmd, timeout)
	if errors.Is(err, vm.ErrHeld) {
		return vm.ExecResult{}, errStopped
	}
	if errors.Is(err, vm.ErrPreempted) {
		// A speculative branch cut short is not a failing test (potency
		// R1 on #158).
		return vm.ExecResult{}, fmt.Errorf("preempted, retry: worker %s was stopped for higher-priority work, so the command has no result (it did not fail); roll the worker back to a snapshot with worker_rollback, or destroy and recreate it, and run it again", name)
	}
	if err != nil {
		return vm.ExecResult{}, workerErr(name, err)
	}
	return r, nil
}

// text renders output as a string, or base64 for binary.
func text(b []byte, b64 bool) string {
	if b64 {
		return base64.StdEncoding.EncodeToString(b)
	}
	return string(b)
}

// input picks the plain or base64 form of an input.
func input(plain, b64 string) ([]byte, error) {
	if b64 == "" {
		return []byte(plain), nil
	}
	if plain != "" {
		return nil, errors.New("give the text or the base64 form, not both")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("base64 input does not decode")
	}
	return b, nil
}

func checkArgv(argv []string) error {
	if len(argv) == 0 || len(argv) > MaxArgs {
		return fmt.Errorf("argv needs 1 to %d entries", MaxArgs)
	}
	n := 0
	for _, s := range argv {
		n += len(s)
	}
	if n > MaxArgBytes || argv[0] == "" {
		return fmt.Errorf("argv must name a command and total at most %d bytes", MaxArgBytes)
	}
	return nil
}

func (t *Tools) exec(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Name    string   `json:"name"`
		Argv    []string `json:"argv"`
		Stdin   string   `json:"stdin"`
		Stdin64 string   `json:"stdin_base64"`
		Out64   bool     `json:"output_base64"`
		Timeout float64  `json:"timeout_seconds"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if err := checkArgv(a.Argv); err != nil {
		return nil, err
	}
	stdin, err := input(a.Stdin, a.Stdin64)
	if err != nil {
		return nil, err
	}
	if len(stdin) > MaxStdin {
		return nil, fmt.Errorf("stdin is larger than %d bytes", MaxStdin)
	}
	timeout := DefaultTimeout
	if a.Timeout > 0 {
		// Clamped as a float: a huge value would overflow the conversion.
		timeout = MaxTimeout
		if a.Timeout < MaxTimeout.Seconds() {
			timeout = time.Duration(a.Timeout * float64(time.Second))
		}
	}
	r, err := t.run(ctx, c, a.Name, vm.Command{Argv: a.Argv, Stdin: stdin}, timeout)
	if err != nil {
		return nil, err
	}
	return execOut{r.ExitCode, text(r.Stdout, a.Out64), text(r.Stderr, a.Out64), r.Truncated, r.TimedOut}, nil
}

func checkPath(p string) error {
	if !strings.HasPrefix(p, "/") || len(p) > 4096 || strings.ContainsRune(p, 0) {
		return errors.New("path must be absolute")
	}
	return nil
}

func (t *Tools) read(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Name   string `json:"name"`
		Path   string `json:"path"`
		Offset int64  `json:"offset"`
		Length int    `json:"length"`
		B64    bool   `json:"base64"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if err := checkPath(a.Path); err != nil {
		return nil, err
	}
	if a.Offset < 0 || a.Offset > MaxOffset || a.Length < 0 || a.Length > MaxOutput {
		return nil, fmt.Errorf("offset must be 0 to %d and length 0 to %d", int64(MaxOffset), MaxOutput)
	}
	if a.Length == 0 {
		a.Length = MaxOutput
	}
	// tail -c +N prints from byte N (1-based); the output cap is the length.
	argv := []string{"tail", "-c", fmt.Sprintf("+%d", a.Offset+1), "--", a.Path}
	r, err := t.run(ctx, c, a.Name, vm.Command{Argv: argv, MaxOutput: a.Length}, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("cannot read %s: %s", a.Path, strings.TrimSpace(string(r.Stderr)))
	}
	// truncated: the file goes on past offset+length; read on from there.
	return map[string]any{"content": text(r.Stdout, a.B64), "truncated": r.Truncated}, nil
}

func (t *Tools) write(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		Content   string `json:"content"`
		Content64 string `json:"content_base64"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if err := checkPath(a.Path); err != nil {
		return nil, err
	}
	content, err := input(a.Content, a.Content64)
	if err != nil {
		return nil, err
	}
	if len(content) > MaxStdin {
		return nil, fmt.Errorf("content is larger than %d bytes", MaxStdin)
	}
	// tee echoes what it writes; keep one byte of it.
	r, err := t.run(ctx, c, a.Name, vm.Command{Argv: []string{"tee", "--", a.Path}, Stdin: content, MaxOutput: 1}, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("cannot write %s: %s", a.Path, strings.TrimSpace(string(r.Stderr)))
	}
	return map[string]any{"written": len(content)}, nil
}

func (t *Tools) checkpoint(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct{ Name string }
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	w, err := t.worker(c, a.Name)
	if err != nil {
		return nil, err
	}
	s, err := t.M.Checkpoint(ctx, w.ID)
	if err != nil {
		return nil, workerErr(a.Name, err)
	}
	return map[string]any{"snapshot": s.ID}, nil
}

func (t *Tools) fork(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Name    string   `json:"name"`
		Into    []string `json:"into"`
		UpToFit bool     `json:"up_to_fit"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	w, err := t.worker(c, a.Name)
	if err != nil {
		return nil, err
	}
	// The forks carry the worker's memory to the caller's lineage again.
	if err := readable(c, w.Label); err != nil {
		return nil, err
	}
	for _, n := range a.Into {
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("into: bad name %q", n)
		}
	}
	var skipped []string
	if a.UpToFit && len(a.Into) > 0 {
		f := t.fit(c, w.Spec.MemMB, w.Spec.Class)
		if f.Fit == 0 {
			return nil, fmt.Errorf("no fork fits now: %s", f.Why)
		}
		if f.Fit < len(a.Into) {
			a.Into, skipped = a.Into[:f.Fit], a.Into[f.Fit:]
		}
	}
	ids := make([]string, len(a.Into))
	for i, n := range a.Into {
		ids[i] = workerID(c.lineage, n)
	}
	if len(ids) == 0 || !t.reserve(c.lineage, ids) {
		return nil, fmt.Errorf("into needs 1 or more new names, with at most %d workers at once", MaxWorkers)
	}
	s, err := t.M.Fork(ctx, w.ID, ids)
	t.settle(ids, err == nil)
	if err != nil {
		return nil, startErr(a.Name, err)
	}
	out := map[string]any{"snapshot": s.ID, "workers": a.Into}
	if a.UpToFit {
		out["skipped"] = append([]string{}, skipped...)
	}
	return out, nil
}

// snapshot resolves a snapshot id to one of the lineage's workers' that the
// caller may read.
func (t *Tools) snapshot(c caller, id string) (vm.Snapshot, error) {
	s, err := t.M.Snapshot(id)
	if err != nil || s.Lineage != c.lineage || !strings.HasPrefix(s.Machine, workerID(c.lineage, "")) {
		return vm.Snapshot{}, fmt.Errorf("no snapshot %q of your workers", id)
	}
	return s, readable(c, s.Label)
}

func (t *Tools) diff(c caller, raw json.RawMessage) (any, error) {
	var a struct{ A, B string }
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	sa, err := t.snapshot(c, a.A)
	if err != nil {
		return nil, err
	}
	if _, err := t.snapshot(c, a.B); err != nil {
		return nil, err
	}
	changes, err := t.M.Diff(sa.Machine, a.A, a.B)
	if err != nil {
		return nil, err
	}
	type change struct{ Path, Op string }
	out := make([]change, 0, min(len(changes), MaxChanges))
	for i, ch := range changes {
		if i == MaxChanges {
			break
		}
		out = append(out, change{ch.Path, ch.Op()})
	}
	return map[string]any{"changes": out, "total": len(changes)}, nil
}

func (t *Tools) rollback(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct{ Name, Snapshot string }
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	w, err := t.worker(c, a.Name)
	if err != nil {
		return nil, err
	}
	if _, err := t.snapshot(c, a.Snapshot); err != nil {
		return nil, err
	}
	if err := t.M.Rollback(ctx, w.ID, a.Snapshot); err != nil {
		return nil, startErr(a.Name, err)
	}
	return map[string]any{"name": a.Name, "snapshot": a.Snapshot}, nil
}

// startErr says what to do when admission has no room (UX-146-2).
func startErr(name string, err error) error {
	if errors.Is(err, admission.ErrNoRoom) || errors.Is(err, admission.ErrPressure) {
		return fmt.Errorf("no room for worker %s now: destroy a worker, or ask for less memory with mem_mb", name)
	}
	return workerErr(name, err)
}

// workerErr names the worker in err. Over its layer cap every command is
// refused, deletions included, so the way out it names is a rollback or
// destroy (UX-150-1).
func workerErr(name string, err error) error {
	var full *vm.WorkerFull
	if errors.As(err, &full) {
		return fmt.Errorf("worker %s holds more files than its %d MB cap; roll it back to a snapshot or destroy it", name, (full.Cap+1<<20-1)>>20)
	}
	return fmt.Errorf("worker %s: %w", name, err)
}

// Reap checkpoints and stops (parks) each running worker that no tool has
// named for IdleAfter, or whose lineage has no running machine other than
// workers, so idle workers never hold memory the owner's work needs
// (UX-146-1). A parked worker revives by worker_rollback to its newest
// snapshot. agentosd runs it every minute.
func (t *Tools) Reap(ctx context.Context) []string {
	ids := t.M.Machines()
	live := map[string]bool{} // lineages with a running non-worker machine
	var workers []vm.Machine
	for _, id := range ids {
		if strings.HasPrefix(id, vm.WorkerPrefix) {
			// A busy worker is in use, not idle: skip it rather than
			// wait out its command.
			if w, ok := t.M.TryGet(id); ok && w.State == vm.Running {
				workers = append(workers, w)
			}
			continue
		}
		if mc, err := t.M.Get(id); err == nil && mc.State == vm.Running {
			live[mc.Lineage] = true
		}
	}
	now := t.now()
	var parked []string
	for _, w := range workers {
		t.mu.Lock()
		if t.used == nil {
			t.used = map[string]time.Time{}
		}
		last, seen := t.used[w.ID]
		if !seen {
			// First seen after a broker restart: the hour starts now.
			t.used[w.ID], last = now, now
		}
		t.mu.Unlock()
		if live[w.Lineage] && now.Sub(last) < IdleAfter {
			continue
		}
		if _, err := t.M.Park(ctx, w.ID); err == nil {
			parked = append(parked, w.ID)
		}
	}
	return parked
}

func (t *Tools) destroy(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct{ Name string }
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	id, err := t.owned(c, a.Name)
	if err != nil {
		return nil, err
	}
	if err := t.M.Destroy(ctx, id); err != nil {
		return nil, workerErr(a.Name, err)
	}
	t.mu.Lock()
	delete(t.used, id)
	t.mu.Unlock()
	return map[string]any{"destroyed": a.Name}, nil
}

func (t *Tools) list(c caller) (any, error) {
	type row struct {
		Name     string `json:"name"`
		State    string `json:"state"`
		Label    string `json:"label"`
		MemMB    int64  `json:"mem_mb"`
		Snapshot string `json:"snapshot,omitempty"`
	}
	out := []row{}
	prefix := workerID(c.lineage, "")
	for _, id := range t.M.Machines() {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		w, err := t.M.Get(id)
		if err != nil || w.Lineage != c.lineage {
			continue
		}
		out = append(out, row{nameOf(c.lineage, id), string(w.State), w.Label.String(), w.Spec.MemMB, w.Last})
	}
	return map[string]any{"workers": out}, nil
}

// fitAnswer is how many more workers of MemMB fit now (CAP-1). It
// carries no memory figure: free memory tracks the owner's activity and
// other labels' machines, so a guest learns only the count (security F1
// on #158).
type fitAnswer struct {
	Fit         int    `json:"fit"`
	MemMB       int64  `json:"mem_mb"`
	WorkersLeft int    `json:"workers_left"`
	Why         string `json:"why,omitempty"`
}

const (
	// FitStepMB is the step free memory is rounded down to before it
	// sizes forks, and FitFor how long one lineage's rounded figure is
	// reused: together they bound what worker_fit says about the box's
	// memory to one step per 10 s, whatever mem_mb is asked (security F1
	// on #158).
	FitStepMB = 512
	FitFor    = 10 * time.Second
)

// fitRoom is a lineage's rounded room, computed at most once per FitFor.
type fitRoom struct {
	mb  int64 // -1: unbounded (neither source set)
	at  time.Time
	why string
}

// room is the smaller of admission's declared room for the caller's class
// and measured free memory, rounded down to FitStepMB and reused for
// FitFor per lineage. Unreadable measurement falls back to the declared
// budget, which admission enforces anyway.
func (t *Tools) room(c caller, class admission.Class) (int64, string) {
	now := t.now()
	key := fmt.Sprint(c.lineage, "/", class)
	t.mu.Lock()
	if r, ok := t.rooms[key]; ok && now.Sub(r.at) < FitFor && !now.Before(r.at) {
		t.mu.Unlock()
		return r.mb, r.why
	}
	t.mu.Unlock()
	mb, why := int64(-1), ""
	if t.Free != nil {
		mb = max(t.Free(class), 0)
	}
	if t.Avail != nil {
		if m, err := t.Avail(); err != nil {
			why = "free memory could not be measured, so this uses the declared budget"
		} else if mb < 0 || m < mb {
			mb = max(m, 0)
		}
	}
	if mb >= 0 {
		mb = mb / FitStepMB * FitStepMB
	}
	t.mu.Lock()
	if t.rooms == nil || len(t.rooms) > 4*MaxWorkers {
		t.rooms = map[string]fitRoom{}
	}
	t.rooms[key] = fitRoom{mb, now, why}
	t.mu.Unlock()
	return mb, why
}

// fit counts the workers of memMB the caller could start now, from its
// lineage's rounded room and what its worker cap leaves. It is advice:
// each start is still admitted on its own.
func (t *Tools) fit(c caller, memMB int64, class admission.Class) fitAnswer {
	a := fitAnswer{MemMB: memMB}
	t.mu.Lock()
	n := len(t.heldLocked(c.lineage))
	t.mu.Unlock()
	a.WorkersLeft = max(MaxWorkers-n, 0)
	room, why := t.room(c, class)
	whys := []string{}
	if why != "" {
		whys = append(whys, why)
	}
	a.Fit = a.WorkersLeft
	if room >= 0 {
		a.Fit = min(a.Fit, int(room/memMB))
	}
	switch {
	case a.Fit > 0:
	case a.WorkersLeft == 0:
		whys = append(whys, fmt.Sprintf("you hold %d workers, the most at once; destroy one first", MaxWorkers))
	default:
		whys = append(whys, fmt.Sprintf("not enough free memory for one %d MB worker now; work sequentially in one worker, ask for less memory, or destroy a worker", memMB))
	}
	// The same rounded room sizes the smaller count, so it says nothing
	// finer about memory than fit does (potency on #158, security F1).
	if room >= 0 && memMB > SmallMemMB {
		if n := min(a.WorkersLeft, int(room/SmallMemMB)); n > a.Fit {
			whys = append(whys, fmt.Sprintf("smaller workers fit more: %d at %d MB", n, SmallMemMB))
		}
	}
	a.Why = strings.Join(whys, "; ")
	return a
}

func (t *Tools) fitTool(c caller, raw json.RawMessage) (any, error) {
	var a struct {
		MemMB int64 `json:"mem_mb"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if a.MemMB == 0 {
		a.MemMB = DefaultMemMB
	}
	if a.MemMB < MinMemMB || a.MemMB > t.MaxMemMB {
		return nil, fmt.Errorf("mem_mb must be between %d and %d", MinMemMB, t.MaxMemMB)
	}
	return t.fit(c, a.MemMB, workerClass(c)), nil
}

// keep destroys the winner's fork siblings: the caller's other workers
// forked from the same snapshot (CAP-1).
func (t *Tools) keep(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct{ Name string }
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	id, err := t.owned(c, a.Name)
	if err != nil {
		return nil, err
	}
	// A fork still starting has no ForkBase yet, so keep would miss it
	// (L3 SHOULD-5 on #158). The siblings are read under the same lock
	// that reserves new workers, so none can start between the check and
	// the read (L3 nit 3 on #158).
	t.mu.Lock()
	starting := false
	for _, l := range t.pending {
		starting = starting || l == c.lineage
	}
	var base string
	var sibs []string
	if !starting {
		base, sibs, err = t.M.ForkSiblings(id)
	}
	t.mu.Unlock()
	if starting {
		return nil, errors.New("some of your workers are still starting; keep the winner once worker_create or worker_fork returns")
	}
	if err != nil {
		return nil, errNoWorker
	}
	if base == "" {
		return nil, fmt.Errorf("worker %s is not a fork: nothing to discard", a.Name)
	}
	t.touch(id)
	destroyed := []string{}
	for _, sid := range sibs {
		if err := t.M.Destroy(ctx, sid); errors.Is(err, vm.ErrUnknown) {
			continue // already gone (L3 nit 2 on #158)
		} else if err != nil {
			// Call returns no answer with an error, so the error says what
			// went (L3 SHOULD-8 on #158).
			err = workerErr(nameOf(c.lineage, sid), err)
			if len(destroyed) > 0 {
				err = fmt.Errorf("%w (already destroyed: %s)", err, strings.Join(destroyed, ", "))
			}
			return nil, err
		}
		t.mu.Lock()
		delete(t.used, sid)
		t.mu.Unlock()
		destroyed = append(destroyed, nameOf(c.lineage, sid))
	}
	return map[string]any{"kept": a.Name, "destroyed": destroyed}, nil
}
