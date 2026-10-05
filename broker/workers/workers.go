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
	DefaultMemMB   = 256       // a worker's budget when none is asked; 8 fit beside the N95's agent (potency R1 on #146)
	MinMemMB       = 64        // below this a base image does not start
	MaxArgs        = 64        // arguments in one command
	MaxArgBytes    = 16 << 10  // all arguments together
	MaxStdin       = 512 << 10 // stdin or a written file; under the guest plane's 1 MiB body
	MaxOutput      = 64 << 10  // each of stdout and stderr
	DefaultTimeout = time.Minute
	MaxTimeout     = 10 * time.Minute
	MaxChanges     = 500 // diff entries returned
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

	// mu guards used and pending. Creating workers reserves their IDs in
	// pending under it, so the per-lineage count cannot be raced past
	// (security R1 on #146), but the machines are made without it, so a
	// fork waiting on a busy worker holds up no other call (L3 MUST-4).
	mu      sync.Mutex
	used    map[string]time.Time // worker ID -> last named by a tool
	pending map[string]string    // worker ID being made -> its lineage
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
		{"name": toolCreate, "description": "Start a worker machine: a sandboxed machine with no agent, no network and no broker tools, built from the base image, that you drive with the other worker_ tools. It runs on your admission class and the memory you ask for; the box refuses it when there is no room. It holds your data label: a worker made by a private machine is private.",
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
				"offset": map[string]any{"type": "number", "description": "Byte offset to start at; default 0."},
				"length": map[string]any{"type": "number", "description": fmt.Sprintf("Bytes to read; default and at most %d.", MaxOutput)},
				"base64": map[string]any{"type": "boolean", "description": "Return the content base64-encoded, for binary files."}}, "name", "path")},
		{"name": toolWrite, "description": "Write a file in a worker, replacing it (its image needs tee).",
			"inputSchema": obj(map[string]any{"name": pName, "path": pPath, "content": map[string]any{"type": "string"},
				"content_base64": map[string]any{"type": "string", "description": "Binary content, base64; instead of content."}}, "name", "path")},
		{"name": toolCkpt, "description": "Checkpoint a worker, memory included; returns the snapshot id to roll back to or diff.",
			"inputSchema": obj(map[string]any{"name": pName}, "name")},
		{"name": toolFork, "description": "Checkpoint a worker and start one new worker per name from it, memory included; each is admitted on its own budget, and either all start or none do.",
			"inputSchema": obj(map[string]any{"name": pName, "into": strList}, "name", "into")},
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
	n := map[string]bool{}
	for _, id := range t.M.Workers(lineage) {
		n[id] = true
	}
	for id, l := range t.pending {
		if l == lineage {
			n[id] = true
		}
	}
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
	s := vm.Spec{Image: t.Image, Class: c.spec.Class, MemMB: a.MemMB, Argv: t.Argv, Label: c.label}
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

func (t *Tools) run(ctx context.Context, c caller, name string, cmd vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	if t.Stopped != nil && t.Stopped() {
		return vm.ExecResult{}, errors.New("the owner sent STOP: worker commands wait until RESUME")
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
	if cmd.MaxOutput == 0 {
		cmd.MaxOutput = MaxOutput
	}
	r, err := t.M.Exec(ctx, w.ID, cmd, timeout)
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
	if a.Offset < 0 || a.Length < 0 || a.Length > MaxOutput {
		return nil, fmt.Errorf("offset must be 0 or more and length at most %d", MaxOutput)
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
		Name string   `json:"name"`
		Into []string `json:"into"`
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
	ids := make([]string, len(a.Into))
	for i, n := range a.Into {
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("into: bad name %q", n)
		}
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
	return map[string]any{"snapshot": s.ID, "workers": a.Into}, nil
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
	w, err := t.worker(c, a.Name)
	if err != nil {
		return nil, err
	}
	if err := t.M.Destroy(ctx, w.ID); err != nil {
		return nil, workerErr(a.Name, err)
	}
	t.mu.Lock()
	delete(t.used, w.ID)
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
