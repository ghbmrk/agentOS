package kernel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Tasks (KRN-5, CLK-3, D-147). Only the kernel opens a task, as a log entry.
// A key serves a task through its task caveat (key.LimitTask), added in the
// narrowing that binds a key to its plan, so every plan and re-plan for the
// task carries it, and a key moves to no other task. Admit refuses a plan
// whose key's task is not live. A task ends at its final result, or when the
// planner's run ends without one (EndTask), at STOP, and at its timeout; an
// ended task never comes back. A rejected plan or a failed step does not end
// it, since re-plans follow them, and reconciliation and RETRY of an
// admitted plan outlive it.
//
// What is bound to a task lives inside it and ends with it, such as its task
// approvals (CLK-3): each an enrolled passkey's co-signature over the task,
// one site and the held request. A task holds one approval per site, and a
// later one for the same site replaces it, as after a card fill the clerk
// asks again. Cutting a passkey off ends the approvals it signed at once,
// and the clerk key's own expiry still stops each request.

// Task entry types.
const (
	TTaskOpened   = "task.opened"
	TTaskApproved = "task.approved"
	TTaskEnded    = "task.ended"
)

// TaskTimeout is how long a task lives after the log opens it (KRN-5's
// default; the owner's setting of it is a later row).
const TaskTimeout = key.DayMS

// CTask refuses a plan whose key's task is not live.
const CTask = "task"

// TaskApproval is the owner's approval of a task's requests on one site: the
// site, the held request it was given over, and the passkey's co-signature
// over TaskHash.
type TaskApproval struct {
	Site  string     `json:"site"`
	First string     `json:"first"`
	By    key.Cosign `json:"by"`
	// At is when the log recorded the approval, set by the fold: the clerk
	// orders its own fills against it (CLK-3).
	At int64 `json:"at"`
}

// Task is a live task as View.Task answers it. At and Until are the fold's:
// when the log opened it, and when it times out. Approvals holds its live
// approvals by site.
type Task struct {
	ID        string                  `json:"id"`
	At        int64                   `json:"at"`
	Until     int64                   `json:"until"`
	Approvals map[string]TaskApproval `json:"approvals,omitempty"`
}

type (
	taskApproved struct {
		Task     string       `json:"task"`
		Approval TaskApproval `json:"approval"`
	}
	taskEnded struct {
		Task string `json:"task"`
	}
	taskState struct {
		Task
		ended bool
	}
)

// TaskHash names a task's approval for its co-signature.
func TaskHash(task, site, first string) [32]byte {
	b, _ := json.Marshal([]string{task, site, first})
	return sha256.Sum256(append([]byte("agentos.task.v1\x00"), b...))
}

var (
	ErrTask         = errors.New("kernel: no live task by that id")
	ErrTaskOpen     = errors.New("kernel: a task opens once, outside STOP")
	ErrTaskApproval = errors.New("kernel: a task's approval is an enrolled passkey's, over TaskHash")
)

// OpenTask opens task id, for TaskTimeout.
func (k *Kernel) OpenTask(now int64, id string) error {
	t := Task{ID: id}
	if err := k.s.openOK(t); err != nil {
		return err
	}
	_, err := k.emit(now, TTaskOpened, t)
	return err
}

// ApproveTask records the owner's approval of a live task's requests on
// a.Site, in place of any earlier one for that site. It widens what the
// task's requests may do, so it anchors (KRN-7).
func (k *Kernel) ApproveTask(now int64, id string, a TaskApproval) error {
	b := taskApproved{id, a}
	if err := k.s.approveOK(b, now); err != nil {
		return err
	}
	return k.owner(now, TTaskApproved, b)
}

// EndTask ends a live task at its final result, or when the planner's run
// ends without one.
func (k *Kernel) EndTask(now int64, id string) error {
	if _, ok := k.s.Task(id, now); !ok {
		return ErrTask
	}
	_, err := k.emit(now, TTaskEnded, taskEnded{id})
	return err
}

// Task is task id while it is live at now: not ended and before its timeout.
func (s *State) Task(id string, now int64) (Task, bool) {
	t := s.tasks[id]
	if t == nil || t.ended || now >= t.Until {
		return Task{}, false
	}
	out := t.Task
	out.Approvals = maps.Clone(t.Approvals)
	return out, true
}

// TaskApproved is the approval on site of the task ver's key serves, for a
// clerk to cover a request with: only while the task is live on the clerk's
// clock, and only when a passkey of the clerk's own set, from its own
// anchors, signed it over TaskHash for that site (CLK-2, CLK-3). The clerk
// reads site from the request, never from the planner.
func TaskApproved(v View, anchors []ed25519.PublicKey, ver *key.Verified, site string, now int64) (TaskApproval, bool) {
	t, ok := v.Task(ver.Limits.Task, now)
	a, has := t.Approvals[site]
	if !ok || !has || t.ID != ver.Limits.Task {
		return TaskApproval{}, false
	}
	es, un := v.Enrollments()
	if !key.In(key.Passkeys(anchors, es, un), a.By.By) || !a.By.Over(TaskHash(t.ID, site, a.First)) {
		return TaskApproval{}, false
	}
	return a, true
}

func (s *State) openOK(t Task) error {
	if t.ID == "" || !utf8.ValidString(t.ID) || s.tasks[t.ID] != nil || s.Stopped {
		return ErrTaskOpen
	}
	return nil
}

func (s *State) approveOK(b taskApproved, at int64) error {
	t, ok := s.Task(b.Task, at)
	if !ok {
		return ErrTask
	}
	a := b.Approval
	if !utf8.ValidString(a.Site) || !utf8.ValidString(a.First) ||
		!key.In(s.Passkeys(), a.By.By) || !a.By.Over(TaskHash(t.ID, a.Site, a.First)) {
		return ErrTaskApproval
	}
	return nil
}

// dropApprovals ends the task approvals passkey pk signed, now cut off.
func (s *State) dropApprovals(pk ed25519.PublicKey) {
	for _, t := range s.tasks {
		maps.DeleteFunc(t.Approvals, func(_ string, a TaskApproval) bool { return bytes.Equal(a.By.By, pk) })
	}
}

func (s *State) applyTask(e Entry) error {
	switch e.Type {
	case TTaskOpened:
		b, err := body[Task](e)
		if err != nil {
			return err
		}
		b.At, b.Until, b.Approvals = e.At, e.At+TaskTimeout, nil
		if s.openOK(b) == nil {
			s.tasks[b.ID] = &taskState{Task: b}
		}
	case TTaskApproved:
		b, err := body[taskApproved](e)
		if err != nil {
			return err
		}
		if s.approveOK(b, e.At) == nil {
			a := b.Approval
			a.At = e.At
			t := s.tasks[b.Task]
			if t.Approvals == nil {
				t.Approvals = map[string]TaskApproval{}
			}
			t.Approvals[a.Site] = a
		}
	case TTaskEnded:
		b, err := body[taskEnded](e)
		if err != nil {
			return err
		}
		if t := s.tasks[b.Task]; t != nil {
			t.ended = true
		}
	}
	return nil
}
