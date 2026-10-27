package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-4, HW-1
// Acceptance: A8 (plaintext scan)
//
// A rotation's new parts are shown on card.Display, the same
// confirm-then-erase as the first-boot card: Commit runs only from the
// display's provisioner, after the owner types values back from the new
// card, and the display erases its copy once it returns.

// rotWire joins a Pending rotation to a card.Display as the rotation page
// does: the display generates and shows the new parts, its provisioner
// commits them, a lapsed rotation discards the display, and a partial
// write erases it as a full confirm does (the owner has just confirmed
// from their copy, and the used-up Pending cannot be retried), mapped to
// card.ErrInEffect so the page refuses cancel and says how to finish.
type rotWire struct {
	t    *testing.T
	x    *box
	p    *Pending
	d    *card.Display
	gen  *card.Card // the generated card, as the owner reads it
	now  time.Time
	done *Done
	log  []string
}

func (x *box) rotateOnDisplay(parts []Part, proof Proof) *rotWire {
	x.t.Helper()
	p, err := BeginRotate(x.b, parts, Auth{Code: true, Local: true}, proof, t0)
	must(x.t, err)
	w := &rotWire{t: x.t, x: x, p: p, now: t0}
	rot := cardParts(p.Parts())
	w.d, err = card.NewDisplay(card.DisplayConfig{
		Rotate:   &rot,
		WiFiName: p.WiFiName(),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				cp.GridSeed = bytes.Clone(c.GridSeed)
				w.gen = &cp
			}
			return c, err
		},
		Provision: w.provision,
		Journal:   func(e string) { w.log = append(w.log, e) },
	})
	must(x.t, err)
	return w
}

func cardParts(ps []Part) card.Parts {
	var out card.Parts
	for _, q := range ps {
		switch q {
		case PartWiFi:
			out.WiFi = true
		case PartSetup:
			out.Setup = true
		case PartPassphrase:
			out.Passphrase = true
		case PartGrid:
			out.Grid = true
		case PartRecovery:
			out.Recovery = true
		}
	}
	return out
}

func (w *rotWire) provision(c *card.Card) error {
	next := Card{WiFiName: c.WiFiName, WiFiPassword: c.WiFiPassword, SetupSecret: c.SetupSecret, SetupCode: c.SetupCode,
		VaultPassphrase: c.VaultPassphrase, GridSeed: bytes.Clone(c.GridSeed), RecoveryKey: c.RecoveryKey}
	d, err := w.p.Commit(w.x.b, next, w.now)
	switch {
	case err == nil:
		w.done = &d
		return nil
	case errors.Is(err, ErrPendingLapsed):
		return fmt.Errorf("%w: %w", card.ErrDiscard, err)
	case errors.Is(err, ErrCardNotStored):
		w.done = &d
		return fmt.Errorf("%w: %w", card.ErrInEffect, err)
	}
	return err
}

// cancel is the page's cancel: the display erases its copy and the
// rotation is dropped.
func (w *rotWire) cancel() error {
	if err := w.d.Discard(); err != nil {
		return err
	}
	w.p.Cancel()
	return nil
}

// answers are what the display asks for, read from the generated card.
func (w *rotWire) answers(right bool) card.Answers {
	var a card.Answers
	wd, g := w.d.Asks()
	if wd > 0 {
		a.Word = strings.Fields(w.gen.VaultPassphrase)[wd-1]
	}
	if g > 0 {
		a.Group = strings.Split(w.gen.RecoveryKey, "-")[g-1]
	}
	if wd == 0 && g == 0 {
		switch {
		case w.gen.WiFiPassword != "":
			n := card.Normalize(w.gen.WiFiPassword)
			a.Check = n[len(n)-4:]
		case w.gen.SetupCode != "":
			a.Check = w.gen.SetupCode
		default:
			a.Check = card.GridCheck(w.gen.GridSeed)
		}
	}
	if !right {
		a.Group = flipFirst(a.Group)
		a.Word = a.Word + "x"
		a.Check = flipFirst(a.Check)
	}
	return a
}

func flipFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(card.Normalize(s))
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func (w *rotWire) newKey() RecoveryKey {
	w.t.Helper()
	k, err := ParseRecoveryKey(w.gen.RecoveryKey)
	must(w.t, err)
	return k
}

// opens reports whether the drive on disk opens with rk.
func (x *box) opens(rk RecoveryKey) bool {
	v, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(rk))
	if err != nil {
		return false
	}
	v.Close()
	return true
}

// noKeyText scans the whole drive (A8) for either recovery key, as raw
// bytes and as printed text in every encoding the scanner knows.
func (x *box) noKeyText(keys ...string) {
	x.t.Helper()
	var ns []Needle
	for i, k := range keys {
		rk, err := ParseRecoveryKey(k)
		must(x.t, err)
		ns = append(ns, Needle{Name: fmt.Sprintf("recovery key %d", i), Value: rk.b[:]},
			Needle{Name: fmt.Sprintf("recovery key text %d", i), Value: []byte(k), Text: true})
	}
	s, err := NewScanner(ns)
	must(x.t, err)
	got, skipped, err := s.Tree(x.dir)
	must(x.t, err)
	if len(got) != 0 || len(skipped) != 0 {
		x.t.Fatalf("key text on the drive: %v, skipped %v", got, skipped)
	}
}

func TestRotationShowsAFreshKeyAndErasesItOnceConfirmed(t *testing.T) {
	x := newBox(t)
	w := x.rotateOnDisplay([]Part{PartRecovery}, Proof{Recovery: x.rk})
	page, err := w.d.Page()
	must(t, err)
	nk := w.newKey()
	if nk == x.rk || !bytes.Contains(page, []byte(w.gen.RecoveryKey)) {
		t.Fatal("the page does not show a fresh recovery key")
	}
	if bytes.Contains(page, []byte(x.card.RecoveryKey)) {
		t.Fatal("the page shows the current recovery key")
	}
	// Nothing is written while the card is on display.
	if !x.opens(x.rk) || x.opens(nk) {
		t.Fatal("the drive changed before the owner confirmed")
	}

	// A wrong confirm keeps the display and the old key.
	if err := w.d.ConfirmAnswers(w.answers(false)); !errors.Is(err, card.ErrNotConfirmed) {
		t.Fatalf("wrong confirm: %v", err)
	}
	if _, err := w.d.Page(); err != nil {
		t.Fatalf("display gone after a wrong confirm: %v", err)
	}
	if w.done != nil || !x.opens(x.rk) || x.opens(nk) {
		t.Fatal("a wrong confirm changed the drive")
	}

	// A right confirm commits, then erases: the page is gone, the old
	// key is rejected and the new one opens.
	must(t, w.d.ConfirmAnswers(w.answers(true)))
	if !w.d.Confirmed() || w.done == nil || w.done.RecoveryKey != w.gen.RecoveryKey {
		t.Fatal("confirm did not commit the shown card")
	}
	if _, err := w.d.Page(); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("page after confirm: %v", err)
	}
	if err := w.d.ConfirmAnswers(w.answers(true)); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("confirm after erase: %v", err)
	}
	if x.opens(x.rk) || !x.opens(nk) {
		t.Fatal("after rotation the old key opens or the new one does not")
	}
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("rotation left unfinished")
	}
	x.noKeyText(x.card.RecoveryKey, w.gen.RecoveryKey)
	for _, e := range w.log {
		if strings.Contains(e, card.Normalize(w.gen.RecoveryKey)[:8]) {
			t.Fatal("key text in the journal")
		}
	}
}

func TestAnAbortedRotationKeepsTheOldKey(t *testing.T) {
	for _, how := range []string{"cancel", "lapse", "restart"} {
		t.Run(how, func(t *testing.T) {
			x := newBox(t)
			w := x.rotateOnDisplay([]Part{PartRecovery, PartWiFi}, Proof{Recovery: x.rk})
			nk := w.newKey()
			switch how {
			case "cancel":
				must(t, w.cancel())
				if _, err := w.d.Page(); !errors.Is(err, card.ErrDisplayGone) {
					t.Fatalf("page after cancel: %v", err)
				}
				// The rotation is gone too: a commit cannot follow.
				if _, err := w.p.Commit(x.b, newParts(w.p), t0); !errors.Is(err, ErrPendingLapsed) {
					t.Fatalf("commit after cancel: %v", err)
				}
			case "lapse":
				// Confirmed after the time limit: the display discards.
				w.now = t0.Add(PendingTTL + time.Second)
				err := w.d.ConfirmAnswers(w.answers(true))
				if !errors.Is(err, card.ErrDiscard) || w.done != nil {
					t.Fatalf("confirm after the time limit: %v", err)
				}
				if _, err := w.d.Page(); !errors.Is(err, card.ErrDisplayGone) {
					t.Fatalf("page after a lapse: %v", err)
				}
			case "restart":
				// The process stops with the card on display: the display
				// lived only in memory, and nothing was written.
				w.d, w.p = nil, nil
			}
			if !x.opens(x.rk) || x.opens(nk) {
				t.Fatal("an aborted rotation changed the key")
			}
			if _, ok := RotationUnfinished(x.b); ok {
				t.Fatal("an aborted rotation is marked unfinished")
			}
			cur, err := x.b.LoadCard()
			must(t, err)
			if cur.WiFiPassword != x.card.WiFiPassword {
				t.Fatal("an aborted rotation changed the Wi-Fi password")
			}
			x.noKeyText(x.card.RecoveryKey, w.gen.RecoveryKey)
			// The old card still rotates.
			if _, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A crash after the new recovery slot is written leaves exactly one
// valid key (the new one) and no key text on disk. The owner confirmed
// from their copy, which now opens the drive, so the display erases its
// copy and refuses cancel; a retry cannot revive it, and the next
// rotation, made with the new key, finishes the owed parts.
func TestACrashMidRotationLeavesOneValidKey(t *testing.T) {
	x := newBox(t)
	w := x.rotateOnDisplay([]Part{PartRecovery}, Proof{Recovery: x.rk})
	nk := w.newKey()
	crashed := errors.New("crash")
	crashPoint = func(step string) error {
		if step == "enroll-marked" {
			return crashed
		}
		return nil
	}
	t.Cleanup(func() { crashPoint = func(string) error { return nil } })

	err := w.d.ConfirmAnswers(w.answers(true))
	if !errors.Is(err, card.ErrInEffect) || !errors.Is(err, ErrCardNotStored) || !errors.Is(err, crashed) {
		t.Fatalf("confirm through a crash: %v", err)
	}
	if w.done == nil || w.done.RecoveryKey != w.gen.RecoveryKey {
		t.Fatal("the key in effect was not reported")
	}
	if _, err := w.d.Page(); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("display kept after a confirmed partial write: %v", err)
	}
	if err := w.cancel(); !errors.Is(err, card.ErrInEffect) {
		t.Fatalf("cancel with the key in effect: %v", err)
	}
	if x.opens(x.rk) || !x.opens(nk) {
		t.Fatal("after the crash, not exactly the new key opens")
	}
	// The marker owes the recovery slot and the re-encryption: backups
	// wait, and the next rotation must replace the key again.
	if parts, ok := RotationUnfinished(x.b); !ok || fmt.Sprint(parts) != "[recovery refresh]" {
		t.Fatalf("owed after the crash: %v %v", parts, ok)
	}
	x.noKeyText(x.card.RecoveryKey, w.gen.RecoveryKey)

	// The fault clears and the owner confirms again: the real Pending is
	// used up and the display is erased, so nothing changes.
	crashPoint = func(string) error { return nil }
	if err := w.d.ConfirmAnswers(w.answers(true)); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("retry after a partial write: %v", err)
	}
	if _, err := w.p.Commit(x.b, Card{RecoveryKey: w.gen.RecoveryKey}, w.now); !errors.Is(err, ErrPendingLapsed) {
		t.Fatalf("Pending after a partial write: %v", err)
	}
	if w.d.Confirmed() || x.opens(x.rk) || !x.opens(nk) {
		t.Fatal("a retry changed the outcome of the partial write")
	}

	// The next rotation, with the new key as proof, finishes the owed parts.
	w2 := x.rotateOnDisplay([]Part{PartRecovery}, Proof{Recovery: nk})
	must(t, w2.d.ConfirmAnswers(w2.answers(true)))
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after the finishing rotation")
	}
	nk2 := w2.newKey()
	if x.opens(x.rk) || x.opens(nk) || !x.opens(nk2) {
		t.Fatal("after finishing, not exactly the newest key opens")
	}
	x.noKeyText(x.card.RecoveryKey, w.gen.RecoveryKey, w2.gen.RecoveryKey)
}

// A partial write leaves the Wi-Fi password, setup secret and grid as
// the current card's, since they are stored only after the slots. Every
// rotated part stays owed, so the next rotation must replace them all and
// the new card's Wi-Fi password cannot be dropped by a narrower one
// (#1090 review F3).
func TestAPartialWriteOwesEveryRotatedPart(t *testing.T) {
	x := newBox(t)
	w := x.rotateOnDisplay([]Part{PartWiFi, PartSetup, PartGrid, PartRecovery}, Proof{Recovery: x.rk})
	nk := w.newKey()
	crashed := errors.New("crash")
	crashPoint = func(step string) error {
		if step == "enroll-marked" {
			return crashed
		}
		return nil
	}
	t.Cleanup(func() { crashPoint = func(string) error { return nil } })
	if err := w.d.ConfirmAnswers(w.answers(true)); !errors.Is(err, card.ErrInEffect) || !errors.Is(err, crashed) {
		t.Fatalf("confirm through a crash: %v", err)
	}
	crashPoint = func(string) error { return nil }
	if x.opens(x.rk) || !x.opens(nk) {
		t.Fatal("after the crash, not exactly the new key opens")
	}
	cur, err := x.b.LoadCard()
	must(t, err)
	if cur.WiFiPassword != x.card.WiFiPassword || cur.SetupSecret != x.card.SetupSecret || !bytes.Equal(cur.GridSeed, x.card.GridSeed) {
		t.Fatal("Wi-Fi, setup or grid took effect before the slots finished")
	}
	if parts, ok := RotationUnfinished(x.b); !ok || fmt.Sprint(parts) != "[wifi setup grid recovery refresh]" {
		t.Fatalf("owed after a partial write: %v %v", parts, ok)
	}
	// A rotation that leaves out setup or grid is refused; Wi-Fi is not
	// owed (WIFI-del-a2).
	for _, parts := range [][]Part{
		{PartRecovery},
		{PartGrid, PartRecovery},
		{PartWiFi, PartGrid, PartRecovery},
		{PartWiFi, PartSetup, PartRecovery},
	} {
		if _, err := BeginRotate(x.b, parts, Auth{Code: true, Local: true}, Proof{Recovery: nk}, t0); !errors.Is(err, ErrRotationOwed) {
			t.Fatalf("rotating %v while setup and grid are owed: %v", parts, err)
		}
	}

	// The finishing rotation covers them all, and its new values take
	// effect: the Wi-Fi password the owner now holds is the box's.
	w2 := x.rotateOnDisplay([]Part{PartWiFi, PartSetup, PartGrid, PartRecovery}, Proof{Recovery: nk})
	must(t, w2.d.ConfirmAnswers(w2.answers(true)))
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after the finishing rotation")
	}
	cur, err = x.b.LoadCard()
	must(t, err)
	if cur.WiFiPassword != w2.gen.WiFiPassword || cur.SetupSecret != w2.gen.SetupSecret || cur.SetupCode != w2.gen.SetupCode ||
		!bytes.Equal(cur.GridSeed, w2.gen.GridSeed) {
		t.Fatal("the finishing rotation's Wi-Fi, setup or grid is not in effect")
	}
	if x.opens(nk) || !x.opens(w2.newKey()) {
		t.Fatal("after finishing, not exactly the newest key opens")
	}
}

// The passphrase slot is written, then the recovery-key write fails: the
// new passphrase and the old recovery key open the drive, the new
// recovery key does not. Both stay owed, and the owner finishes with the
// old card's recovery key (#1090 review F3).
func TestAFailedRecoveryWriteKeepsTheOldRecoveryKey(t *testing.T) {
	x := newBox(t)
	w := x.rotateOnDisplay([]Part{PartPassphrase, PartRecovery}, Proof{Recovery: x.rk})
	nk := w.newKey()
	failed := errors.New("recovery slot write failed")
	crashPoint = func(step string) error {
		if step == "passphrase-slot" {
			return failed
		}
		return nil
	}
	t.Cleanup(func() { crashPoint = func(string) error { return nil } })
	if err := w.d.ConfirmAnswers(w.answers(true)); !errors.Is(err, card.ErrInEffect) || !errors.Is(err, failed) {
		t.Fatalf("confirm through a failed recovery write: %v", err)
	}
	crashPoint = func(string) error { return nil }
	if w.done == nil || w.done.VaultPassphrase != w.gen.VaultPassphrase || w.done.RecoveryKey != "" {
		t.Fatal("the parts in effect were not reported")
	}
	if _, err := w.d.Page(); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("display kept after a confirmed partial write: %v", err)
	}
	if !x.opens(x.rk) || x.opens(nk) {
		t.Fatal("after the failed recovery write, the old recovery key does not open or the new one does")
	}
	v, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(w.gen.VaultPassphrase))
	must(t, err)
	v.Close()
	if parts, ok := RotationUnfinished(x.b); !ok || fmt.Sprint(parts) != "[passphrase recovery refresh]" {
		t.Fatalf("owed after the failed recovery write: %v %v", parts, ok)
	}
	// The new card's recovery key proves nothing; the old one does.
	if _, err := BeginRotate(x.b, []Part{PartPassphrase, PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: nk}, t0); err == nil {
		t.Fatal("a rotation started with the new card's unwritten recovery key")
	}
	w2 := x.rotateOnDisplay([]Part{PartPassphrase, PartRecovery}, Proof{Recovery: x.rk})
	must(t, w2.d.ConfirmAnswers(w2.answers(true)))
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after the finishing rotation")
	}
	if x.opens(x.rk) || x.opens(nk) || !x.opens(w2.newKey()) {
		t.Fatal("after finishing, not exactly the newest key opens")
	}
}

// The old display path is gone: Pending no longer makes or holds a card,
// prompts, or checks typed answers; Commit takes the display's card.
func TestPendingHasNoDisplayOfItsOwn(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	must(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		must(t, err)
		file, err := parser.ParseFile(fset, f, src, 0)
		must(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Recv == nil || len(n.Recv.List) != 1 {
					return true
				}
				if recvName(n.Recv.List[0].Type) != "Pending" {
					return true
				}
				switch n.Name.Name {
				case "Card", "Prompt", "Confirm", "Answer":
					t.Errorf("%s: Pending.%s is the old display path", f, n.Name.Name)
				case "Commit":
					p := n.Type.Params.List
					if len(p) < 2 {
						t.Errorf("%s: Commit takes no card", f)
						break
					}
					if id, ok := p[1].Type.(*ast.Ident); !ok || id.Name != "Card" {
						t.Errorf("%s: Commit's second parameter is not the display's Card", f)
					}
				}
			case *ast.TypeSpec:
				if n.Name.Name != "Pending" {
					return true
				}
				st, _ := n.Type.(*ast.StructType)
				for _, fl := range st.Fields.List {
					for _, nm := range fl.Names {
						switch nm.Name {
						case "next", "prompt", "answer", "card":
							t.Errorf("%s: Pending holds %s", f, nm.Name)
						}
					}
				}
			case *ast.ValueSpec:
				for _, nm := range n.Names {
					if nm.Name == "ErrConfirm" {
						t.Errorf("%s: %s is the old display path's error", f, nm.Name)
					}
				}
			}
			return true
		})
	}
}

func recvName(e ast.Expr) string {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
