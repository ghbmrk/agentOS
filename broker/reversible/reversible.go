// Package reversible declares how an irreversible operation is converted
// into a reversible one (SPEC REV-3): held for an undo window after the
// owner approves it, and optionally staged first as a draft, a scheduled
// send, or a staging copy that an UNDO removes. An adapter declares a Form
// next to the operation; the grants gate applies it. The package holds no
// state and makes no calls: it validates forms and builds the derived
// intents the gate journals.
package reversible

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/verb"
)

// Window bounds. DefaultWindow matches the owner channel's ADP-11 undo
// window, so every UNDO the owner sees runs on the same clock.
const (
	DefaultWindow = 10 * time.Minute
	MinWindow     = time.Minute
	MaxWindow     = 24 * time.Hour
)

// Origin marks the intents the gate derives from an approved effect. Only
// the gate submits it, and only for an intent it is holding.
const Origin = "broker:reversible"

// Params the derived intents carry, for the adapter to find the staged
// copy: the parent intent's ID, for an inverse or an edited send the
// stage's evidence, and for an edited send ParamEdited (true).
const (
	ParamParent = "reversible_parent"
	ParamStaged = "reversible_staged"
	ParamEdited = "reversible_edited"
)

// Evidence an adapter returns, with a not-applied result, when the
// effect is released but its staged copy is not what the stage made
// (arbitrator on #76). Gone: the owner deleted it in their own app, which
// is a cancel. Edited: the owner changed it, so it is not sent as
// approved; the owner is asked about the edited copy instead.
const (
	EvidenceGone   = "reversible: the staged copy is gone"
	EvidenceEdited = "reversible: the staged copy was edited"
)

// Form is an irreversible operation's reversible form.
type Form struct {
	// Window is how long the effect is held after the owner approves it,
	// during which UNDO cancels it (CH-16). Zero takes DefaultWindow.
	Window time.Duration `json:"window,omitempty"`
	// Stage, if set, is a reversible operation the gate runs as soon as the
	// owner approves, on the same params: an inert copy in the owner's
	// account, such as a draft. It must never complete on its own (a
	// provider-side scheduled send would go out while the box is down and
	// skip the recheck; arbitrator on #76). When the window passes and the
	// recheck passes, the original operation runs, and the adapter makes
	// it complete the staged copy, found by the stage intent's ID, only if
	// that copy is still exactly what the stage made; otherwise it returns
	// not applied with EvidenceGone or EvidenceEdited.
	Stage string `json:"stage,omitempty"`
	// Inverse is the reversible operation that removes what Stage made,
	// run on UNDO. Required with Stage.
	Inverse string `json:"inverse,omitempty"`
}

// Check validates f as the form of op among one executor's declared
// operations (operation to verb, ADP-2) and returns it with the window
// defaulted. A form never widens what runs without asking: the operation
// is irreversible but not a secret (CRED-6 keeps per-action approval), and
// its stage and inverse are operations the verb list already lets run
// without asking.
func Check(declared map[string]string, op string, f Form) (Form, error) {
	v, ok := declared[op]
	if !ok {
		return Form{}, fmt.Errorf("reversible: %s is not declared", op)
	}
	switch cls, _ := verb.ClassOf(v); cls {
	case verb.Reversible:
		return Form{}, fmt.Errorf("reversible: %s is already reversible", op)
	case verb.Secret:
		return Form{}, fmt.Errorf("reversible: %s reveals or creates a secret", op)
	}
	if f.Window == 0 {
		f.Window = DefaultWindow
	}
	if f.Window < MinWindow || f.Window > MaxWindow {
		return Form{}, fmt.Errorf("reversible: the window must be %s to %s", MinWindow, MaxWindow)
	}
	if (f.Stage == "") != (f.Inverse == "") {
		return Form{}, errors.New("reversible: a stage needs an inverse, and an inverse a stage")
	}
	if f.Stage == "" {
		return f, nil
	}
	if f.Stage == f.Inverse {
		return Form{}, errors.New("reversible: the stage and its inverse must differ")
	}
	for _, x := range []string{f.Stage, f.Inverse} {
		xv, ok := declared[x]
		if !ok {
			return Form{}, fmt.Errorf("reversible: %s is not declared", x)
		}
		if cls, _ := verb.ClassOf(xv); cls != verb.Reversible {
			return Form{}, fmt.Errorf("reversible: %s is not reversible", x)
		}
	}
	return f, nil
}

// Prefix starts every derived intent ID. No guest intent ID starts with
// '~' (guest IDs start with their lineage, [a-z0-9]), so a guest cannot
// take a derived ID first and block it (arbitrator C1 on #76).
const Prefix = "~reversible/"

// StageID, InverseID, and EditedID name the derived intents of the n-th
// hold of parent (from 1), so a retry is the same intent (OP-1) and a
// parent held again after a restart is staged afresh.
func StageID(parent string, n int) string   { return derivedID("stage", parent, n) }
func InverseID(parent string, n int) string { return derivedID("unstage", parent, n) }
func EditedID(parent string, n int) string  { return derivedID("edited", parent, n) }

func derivedID(kind, parent string, n int) string {
	return Prefix + kind + "/" + strconv.Itoa(n) + "/" + parent
}

// Stage is the intent that stages p's n-th hold.
func Stage(p journal.Intent, f Form, n int) journal.Intent {
	return derive(p, StageID(p.ID, n), f.Stage, nil)
}

// Inverse is the intent that removes what p's n-th stage made; staged is
// the stage's evidence.
func Inverse(p journal.Intent, f Form, n int, staged string) journal.Intent {
	return derive(p, InverseID(p.ID, n), f.Inverse, map[string]any{ParamStaged: staged})
}

// Edited is the intent that sends the owner's edited copy of p's stage,
// asked of the owner at the normal tier; staged is the stage's evidence.
func Edited(p journal.Intent, n int, staged string) journal.Intent {
	return derive(p, EditedID(p.ID, n), p.Action, map[string]any{ParamStaged: staged, ParamEdited: true})
}

func derive(p journal.Intent, id, op string, extra map[string]any) journal.Intent {
	params := maps.Clone(p.Params)
	if params == nil {
		params = map[string]any{}
	}
	maps.Copy(params, extra)
	params[ParamParent] = p.ID
	return journal.Intent{ID: id, GoalID: p.GoalID, Origin: Origin, Account: p.Account, Action: op, Params: params,
		Recipients: append([]string(nil), p.Recipients...), Visibility: p.Visibility, Executor: p.Executor,
		Machine: p.Machine, Label: p.Label}
}

// Parent returns the parent ID and hold number of an intent the gate
// derived; false for any other intent, whatever its params claim.
func Parent(in journal.Intent) (string, int, bool) {
	p, _ := in.Params[ParamParent].(string)
	if in.Origin != Origin || p == "" || !strings.HasPrefix(in.ID, Prefix) || !strings.HasSuffix(in.ID, "/"+p) {
		return "", 0, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(in.ID, Prefix), "/"+p) // kind/n
	kind, num, ok := strings.Cut(mid, "/")
	n, err := strconv.Atoi(num)
	if !ok || err != nil || n < 1 || derivedID(kind, p, n) != in.ID || (kind != "stage" && kind != "unstage" && kind != "edited") {
		return "", 0, false
	}
	return p, n, true
}
