package main

// More mutant kills for #6000: the enroll survivors of run 45895314565
// (mutgate on 674de391), named here by line at that head. Each runs as a
// subtest of TestFactorFilesMustBePrivate through mutgateKills, so the
// package's top-level test list stays main's.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// REQ: STO-2, HW-15, CH-4, BAK-1

const (
	ccFlushContext = 0x00000165
	ccNVRead       = 0x0000014E
	ccStartSession = 0x00000176
	ccNVUndefine   = 0x00000122
)

// errOnce is the refusal faultTPM and defineTPM answer with: a type, not a
// package var, so this file declares no package state.
type errOnce struct{}

func (errOnce) Error() string { return "test: the TPM refused this one command" }

// faultTPM refuses the k-th command it is sent, once, without passing it
// on, and forwards every other: one failed TPM call, then a TPM that works.
// phase is the last step the run named (config.stop), so a rule can tell
// which part of the run a command belongs to.
type faultTPM struct {
	tpm     transport.TPM
	k, n    int
	cc      uint32
	phase   string
	defined bool // an NV_DefineSpace was forwarded in this phase
	failed  string
	after   bool // defined, when the k-th command was refused
}

func (f *faultTPM) Send(cmd []byte) ([]byte, error) {
	f.n++
	cc := binary.BigEndian.Uint32(cmd[6:10])
	if f.n == f.k {
		f.cc, f.failed, f.after = cc, f.phase, f.defined
		return nil, errOnce{}
	}
	if cc == ccNVDefineSpace {
		f.defined = true
	}
	return f.tpm.Send(cmd)
}

func (f *faultTPM) step(s string) bool { f.phase, f.defined = s, false; return false }

// tpmFaultSweep runs op on a fresh box once for each of its TPM commands,
// refusing that one command. The refusal must come back as op's error
// (errors.Is), unless tolerated says the code is built to absorb it, and
// then op must leave a whole box; within the first lenient commands (the
// store's unlock, whose TPM refusals read as a wrong factor and then fall
// back to the passphrase) a wrong-factor error passes too. After a
// refusal the rerun on a working TPM must finish. A deleted error check
// either drops the refusal (op succeeds, or fails with another error) or
// goes on with a zero value, and fails one of these.
func tpmFaultSweep(t *testing.T, prep func(b *box), op func(c config, tp transport.TPM) error, whole func(b *box), lenient int, tolerated func(f *faultTPM) bool) {
	probe := newBox(t)
	prep(probe)
	ct := &countTPM{tpm: probe.sw.TPM()}
	noErr(t, op(probe.c, ct))
	for k := 1; k <= ct.n; k++ {
		b := newBox(t)
		prep(b)
		f := &faultTPM{tpm: b.sw.TPM(), k: k}
		c := b.c
		c.stop = f.step
		err := op(c, f)
		switch {
		case errors.Is(err, errOnce{}):
		case err == nil && (f.cc == ccFlushContext || tolerated(f)):
			b.reboot()
			whole(b)
			continue
		case k <= lenient && (err == nil || errors.Is(err, seal.ErrWrongFactor)):
			continue
		default:
			t.Fatalf("command %d (%#x, after step %q) refused: got %v, want that refusal", k, f.cc, f.failed, err)
		}
		b.reboot()
		if err := op(b.c, b.sw.TPM()); err != nil {
			t.Fatalf("rerun after command %d (%#x) was refused: %v", k, f.cc, err)
		}
		b.reboot()
		whole(b)
	}
}

func enrolledBox(b *box) { noErr(b.t, enroll(b.c, b.sw.TPM())) }

func wholeBox(b *box) { b.enrolled() }

// deletedBox is a box whose store is gone and whose TPM holds nothing of it.
func deletedBox(b *box) {
	absent(b.t, b.c.storePath())
	if n := nv(b.t, b.sw.TPM()); len(n) != 0 {
		b.t.Fatalf("the TPM still holds %d of the store's indexes", len(n))
	}
}

// One refused TPM command in enrollment comes back as its error: the SRK
// (main.go:362), the other-pins scan (:374), the policy's signing
// (:419), the counter (:468, and newCounter's :828 when the define made
// nothing) and the anchor's first counter read (:717). Only a flush,
// whose error nothing reads, and the counter's first increment, which
// newCounter adopts (#2905), are absorbed.
func enrollRefusedTPMCommand(t *testing.T) {
	tpmFaultSweep(t, func(*box) {}, enroll, wholeBox, 0, func(f *faultTPM) bool { return f.failed == "slots" && f.after })
}

// The same for a rotation once its store is open: the SRK (main.go:886),
// the new slot's seal (:943), the pins' read (:951), free (:955) and
// rewrite (:965). The pins' policy read, which ReadPins reads as no pins
// so the rotation frees and rewrites them, is absorbed.
func rotateRefusedTPMCommand(t *testing.T) {
	tpmFaultSweep(t, enrolledBox, rotate, wholeBox, openCommands(t), func(f *faultTPM) bool {
		return f.failed == "new-slot" && (f.cc == ccStartSession || f.cc == ccNVRead)
	})
}

// And for a delete: the SRK (main.go:1045) and the frees.
func deleteRefusedTPMCommand(t *testing.T) {
	tpmFaultSweep(t, enrolledBox, deleteStore, deletedBox, openCommands(t), func(*faultTPM) bool { return false })
}

// openCommands is the number of TPM commands open sends on an enrolled box.
func openCommands(t *testing.T) int {
	b := newBox(t)
	enrolledBox(b)
	ct := &countTPM{tpm: b.sw.TPM()}
	st := get(open(b.c, ct))
	st.Close()
	return ct.n
}

// A crash once the pins are locked leaves only the rename: the rerun
// commits the staged store as it is, the same ID, rather than freeing it
// and enrolling afresh (main.go:380, :381).
func enrollRerunCommitsLockedPins(t *testing.T) {
	b := newBox(t)
	c := b.c
	c.stop = func(s string) bool { return s == "pins" }
	if err := enroll(c, b.sw.TPM()); !errors.Is(err, errCrash) {
		t.Fatalf("got %v, want the crash", err)
	}
	id := get(seal.ReadID(b.c.stagedPath()))
	noErr(t, enroll(b.c, b.sw.TPM()))
	if got := b.enrolled().ID(); !bytes.Equal(got, id) {
		t.Fatalf("the rerun committed store %x, not the staged %x", got, id)
	}
}

// An anchor directory whose parent is missing, or that is a symlink, is
// refused at its own open, before the factors or the TPM (main.go:393,
// :400, :687).
func enrollRefusesTheAnchorDirAtItsOpen(t *testing.T) {
	b := newBox(t)
	before := nv(t, b.sw.TPM())
	c := b.c
	c.anchorDir = filepath.Join(t.TempDir(), "missing", "anchor")
	var pe *fs.PathError
	if err := enroll(c, b.sw.TPM()); !errors.As(err, &pe) || pe.Op != "open" || pe.Path != filepath.Dir(c.anchorDir) {
		t.Fatalf("a missing parent: got %v, want its open error", err)
	}
	noErr(t, os.Symlink(t.TempDir(), b.c.anchorDir))
	if err := enroll(b.c, b.sw.TPM()); !errors.As(err, &pe) || pe.Op != "open" || pe.Path != filepath.Base(b.c.anchorDir) {
		t.Fatalf("a symlinked anchor directory: got %v, want its open error", err)
	}
	if !sameMap(before, nv(t, b.sw.TPM())) {
		t.Fatal("a refused enrollment changed the TPM")
	}
	absent(t, b.c.stagedPath())
}

// An enrollment, a rotation and a busy lock close every descriptor they
// open: the anchor's parent and directory (main.go:396, :689, :715), the
// capture (:575), the state directory's sync (:667), the lock (:1292).
func enrollClosesItsDescriptors(t *testing.T) {
	b := newBox(t)
	b.writeCapture(3)
	noErr(t, os.Mkdir(b.c.anchorDir, 0o700)) // a dead enrollment's, which removeAnchor opens
	runtime.GC()
	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	before := enrollFDs(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	unlock := get(lockStore(b.c, false))
	for range 4 {
		if _, err := lockStore(b.c, false); !errors.Is(err, errBusy) {
			t.Fatalf("a held lock: got %v, want errBusy", err)
		}
	}
	unlock()
	if after := enrollFDs(t); after != before {
		t.Fatalf("open descriptors went from %d to %d", before, after)
	}
}

// The anchor directory and its head file go to the kernel's user and group
// (main.go:722, :725). As root any IDs do; otherwise only a group of this
// user's other than its own can show the change.
func enrollHandsTheAnchorToTheKernel(t *testing.T) {
	b := newBox(t)
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() == 0 {
		uid, gid = 4242, 4243
	} else {
		gs, _ := os.Getgroups()
		gid = -1
		for _, g := range gs {
			if g != os.Getgid() {
				gid = g
				break
			}
		}
		if gid < 0 {
			t.Skip("not root, and in no other group to hand the anchor to")
		}
	}
	b.c.kernelUID, b.c.kernelGID = uid, gid
	noErr(t, enroll(b.c, b.sw.TPM()))
	for _, p := range []string{b.c.anchorDir, filepath.Join(b.c.anchorDir, anchorFile)} {
		fi := get(os.Lstat(p))
		st := fi.Sys().(*syscall.Stat_t)
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Fatalf("%s is %d:%d, want %d:%d", p, st.Uid, st.Gid, uid, gid)
		}
	}
}

// A missing passphrase file, or a recovery file that is not 32 bytes of
// hex, stops enrollment before the TPM (main.go:747, :753).
// A missing recovery file is its read error, not a bad key (:747).
func enrollNeedsBothFactors(t *testing.T) {
	b := newBox(t)
	c := b.c
	c.passphrase = filepath.Join(t.TempDir(), "none")
	if err := enroll(c, b.sw.TPM()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no passphrase file: got %v", err)
	}
	c = b.c
	c.recovery = filepath.Join(t.TempDir(), "none")
	if err := enroll(c, b.sw.TPM()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no recovery file: got %v", err)
	}
	c = b.c
	c.recovery = filepath.Join(t.TempDir(), "recovery")
	noErr(t, os.WriteFile(c.recovery, []byte(hex.EncodeToString(make([]byte, seal.RecoveryLen-1))+"\n"), 0o600))
	if err := enroll(c, b.sw.TPM()); err == nil || !strings.Contains(err.Error(), "is not 32 bytes of hex") {
		t.Fatalf("a short recovery key: got %v", err)
	}
	absent(t, b.c.stagedPath())
}

// stderr runs f and returns what it wrote to os.Stderr.
func stderr(t *testing.T, f func()) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stderr")
	w := get(os.Create(p))
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old; w.Close() }()
	f()
	return string(get(os.ReadFile(p)))
}

// No capture file is no first edge and no message; a capture that does
// not read is named on stderr and enrollment goes on (main.go:544, :548,
// :569). readCapture reports a missing file as missing (:569).
func enrollFirstEdgeMessages(t *testing.T) {
	b := newBox(t)
	b.c.firstEdge = filepath.Join(t.TempDir(), "none")
	if _, err := readCapture(b.c.firstEdge, os.Geteuid()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("readCapture of no file: got %v", err)
	}
	if s := stderr(t, func() { noErr(t, enroll(b.c, b.sw.TPM())) }); s != "" {
		t.Fatalf("no capture wrote %q", s)
	}
	b = newBox(t)
	b.writeCapture(4)
	noErr(t, os.WriteFile(b.c.firstEdge, []byte("short"), 0o600))
	if s := stderr(t, func() { noErr(t, enroll(b.c, b.sw.TPM())) }); !strings.Contains(s, "I take no first edge key") {
		t.Fatalf("a capture that does not read wrote %q", s)
	}
}

// A staged code seed that does not read is that error, not an unconfirmed
// one (codes.go:248).
func enrollWithAnUnreadableSeed(t *testing.T) {
	b := newBox(t)
	b.c.codeSeed = filepath.Join(t.TempDir(), codeSeedFile)
	noErr(t, os.WriteFile(b.c.codeSeed, []byte("c\x00not a seed"), 0o600))
	if err := enroll(b.c, b.sw.TPM()); !errors.Is(err, errCodesStaged) {
		t.Fatalf("got %v, want errCodesStaged", err)
	}
}

// The staged seed's form: a state byte u or c, fewer than maxConfirmWrong
// wrong codes, then a seed (codes.go:109, :113).
func parseStagedRefuses(t *testing.T) {
	v := get(handoff.EncodeCodeSeed(handoff.CodeSeed{Seed: secret.Hide(bytes.Repeat([]byte{7}, codeSeedLen))}))
	if _, err := parseStaged(append([]byte{'u', 0}, v...)); err != nil {
		t.Fatalf("a good staged seed: %v", err)
	}
	for _, b := range [][]byte{
		append([]byte{'x', 0}, v...),
		append([]byte{'u', maxConfirmWrong}, v...),
		{'u'},
		append([]byte{'c', 0}, "not a seed"...),
	} {
		if _, err := parseStaged(b); !errors.Is(err, errCodesStaged) {
			t.Fatalf("%q: got %v, want errCodesStaged", b, err)
		}
	}
}

// -codes: a refusal exits 1 and its reason goes to the journal
// (codes.go:156-158); an oversized request, or one with an unknown field,
// is bad (:166, :171); a staged seed that does not read is its error
// (:187); the link names the generator's settings (:234-237).
func codesRefusalsAndLink(t *testing.T) {
	c := codesConfig(t)
	now := time.Now()
	var out, errw bytes.Buffer
	if code := codesMain(c, strings.NewReader(`{"op":"x"}`), &out, &errw, now); code != 1 || !strings.Contains(errw.String(), errCodesBad.Error()) {
		t.Fatalf("a bad request: exit %d, journal %q", code, errw.String())
	}
	big := `{"op":"enrol"}` + strings.Repeat(" ", maxCodesRequest)
	for _, req := range []string{big, `{"op":"enrol","x":1}`} {
		if _, err := codes(c, strings.NewReader(req), now); !errors.Is(err, errCodesBad) {
			t.Fatalf("%.20q: got %v, want errCodesBad", req, err)
		}
	}
	absent(t, filepath.Join(c.setupDir, codeSeedFile))
	uri := get(codes(c, strings.NewReader(`{"op":"enrol"}`), now))
	q := get(url.Parse(uri)).Query()
	for k, v := range map[string]string{"issuer": "agentOS", "algorithm": "SHA1", "digits": "6", "period": "30"} {
		if q.Get(k) != v {
			t.Fatalf("the link's %s is %q, want %q", k, q.Get(k), v)
		}
	}
	noErr(t, os.WriteFile(filepath.Join(c.setupDir, codeSeedFile), []byte("u\x00junk"), 0o600))
	if _, err := codes(c, strings.NewReader(`{"op":"confirm","code":"123456"}`), now); !errors.Is(err, errCodesStaged) {
		t.Fatalf("an unreadable staged seed: got %v, want errCodesStaged", err)
	}
}

// A staged pair that does not read is errPageCARead, and a missing one is
// that read's error too (stage.go:114).
func stagedPairThatDoesNotRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "staged")
	if _, err := readStagedAuthority(p); !errors.Is(err, errPageCARead) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no staged pair: got %v, want errPageCARead for the missing file", err)
	}
	noErr(t, os.WriteFile(p, []byte("not a pair"), 0o600))
	if _, err := readStagedAuthority(p); !errors.Is(err, errPageCARead) {
		t.Fatalf("got %v, want errPageCARead", err)
	}
}

// open: pins that unlock need no passphrase file (main.go:848); with no
// pins, no -passphrase-file is ErrNoPins (:855) and a missing one is its
// read error (:858).
func openWithAndWithoutPins(t *testing.T) {
	b := newBox(t)
	enrolledBox(b)
	c := b.c
	c.passphrase = filepath.Join(t.TempDir(), "none")
	get(open(c, b.sw.TPM())).Close()
	st := b.enrolled()
	noErr(t, tpmseal.FreePins(b.sw.TPM(), b.srk(), st.ID()))
	if _, err := open(c, b.sw.TPM()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no pins, no passphrase file: got %v", err)
	}
	c.passphrase = ""
	if _, err := open(c, b.sw.TPM()); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("no pins, no -passphrase-file: got %v", err)
	}
}

// putEntry sets one entry of b's store, through the passphrase.
func (b *box) putEntry(name string, v []byte) {
	st := get(seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: secret.Hide(b.pass)}))
	defer st.Close()
	if v == nil {
		noErr(b.t, st.Delete(name))
		return
	}
	noErr(b.t, st.Put(name, v))
}

// rotate refuses a state directory it cannot lock (main.go:876), a store
// with no policy key (:890) or one that does not parse (:894); delete
// refuses a store that does not open (:1039).
func rotateAndDeleteRefusals(t *testing.T) {
	b := newBox(t)
	enrolledBox(b)
	c := b.c
	c.state = filepath.Join(t.TempDir(), "none")
	if err := rotate(c, b.sw.TPM()); !errors.Is(err, errStoreOpen) {
		t.Fatalf("no state directory: got %v, want errStoreOpen", err)
	}
	if err := deleteStore(c, b.sw.TPM()); err == nil {
		t.Fatal("a delete with no store passed")
	}
	b.putEntry(policyKeyEntry, nil)
	if err := rotate(b.c, b.sw.TPM()); err == nil || !strings.Contains(err.Error(), "holds no policy key") {
		t.Fatalf("no policy key: got %v", err)
	}
	b.putEntry(policyKeyEntry, []byte("not a key"))
	if err := rotate(b.c, b.sw.TPM()); err == nil {
		t.Fatal("a policy key that does not parse was rotated")
	}
}

// slotPolicies takes only the tpm slot under key (main.go:1006), refuses
// a key no slot has (:1018), and two selections with no -pcrs (:1022).
func slotPoliciesChoices(t *testing.T) {
	b := newBox(t)
	enrolledBox(b)
	c := b.c
	c.stop = func(s string) bool { return s == "new-slot" }
	if err := rotate(c, b.sw.TPM()); !errors.Is(err, errCrash) {
		t.Fatalf("got %v, want the crash", err)
	}
	st := get(seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: secret.Hide(b.pass)}))
	defer st.Close()
	key := parseKey(t, st)
	if ps, err := slotPolicies(st, &key.PublicKey, nil); err != nil || len(ps) != 1 {
		t.Fatalf("the old slot's boot paths: %d, %v", len(ps), err)
	}
	other := get(tpmseal.NewPolicyKey())
	if _, err := slotPolicies(st, &other.PublicKey, nil); err == nil || !strings.Contains(err.Error(), "no tpm slot under its policy key") {
		t.Fatal("a key with no slot has boot paths")
	}
	var id string
	var pols []tpmseal.Policy
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindTPM && sl.PolicyKey.Equal(&key.PublicKey) {
			id, pols = sl.ID, sl.Policies
		}
	}
	nine := get(tpmseal.Sign(key, []uint{9}, [][]byte{swtpm.Predict("initrd-A")}))
	noErr(t, st.SetPolicies(id, append(pols, nine)))
	if _, err := slotPolicies(st, &key.PublicKey, nil); err == nil || !strings.Contains(err.Error(), "name one with -pcrs") {
		t.Fatalf("two selections and no -pcrs: got %v", err)
	}
}

// hexKey refuses what is not one JSON string of hex (main.go:1112,
// :1118): a number whose inner digits are 64 hex digits, and 64 letters
// that are not hex. wipe zeroes both secrets (:1124, :1125).
func rotateRequestNextAndWipe(t *testing.T) {
	b := newRotBox(t)
	next := newKey(t)
	good := approve(b.head, handoff.RouteCard, b.old, recipientID(next))
	for _, n := range []string{"1" + strings.Repeat("2", 64) + "1", `"` + strings.Repeat("z", 64) + `"`} {
		req := get(json.Marshal(map[string]any{"factor": "passphrase", "secret": b.pass, "approval": good}))
		req = append(req[:len(req)-1], `,"next":`+n+`}`...)
		if w := b.ask(req); w != "request" {
			t.Fatalf("next %.8s...: answered %q", n, w)
		}
	}
	r := rotateRequest{Secret: []byte("secret"), Next: hexKey("next")}
	s, n := r.Secret, r.Next
	r.wipe()
	if bytes.ContainsFunc(s, func(c rune) bool { return c != 0 }) || bytes.ContainsFunc(n, func(c rune) bool { return c != 0 }) {
		t.Fatalf("after wipe: %q, %q", s, n)
	}
}

// logged runs f with the standard logger writing to a buffer.
func logged(f func()) string {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	f()
	return buf.String()
}

// -rotate-recovery: a refusal's reason goes to the journal (main.go:1135),
// as does a retry of a done rotation (:1222); a store whose recipient does
// not read (:1210, :1269) or that holds two recovery slots (:1244) is the
// store's refusal; and a write that fails before its rename is too
// (:1252).
func rotateRecoveryStoreRefusals(t *testing.T) {
	b := newRotBox(t)
	next := newKey(t)
	req := request("passphrase", b.pass, next, approve(b.head, handoff.RouteCard, b.old, recipientID(next)))
	if s := logged(func() { b.ask([]byte("{")) }); !strings.Contains(s, errRequest.Error()) {
		t.Fatalf("a refusal logged %q", s)
	}
	if w := b.ask(req); w != "ok" {
		t.Fatalf("the rotation answered %q", w)
	}
	if s := logged(func() { b.ask(req) }); !strings.Contains(s, "nothing to write") {
		t.Fatalf("a done rotation's retry logged %q", s)
	}
	// A short recovery key is the factor's refusal before any unlock, even
	// where next would open the store and answer the retry ok (:1162).
	short := request("recovery", newKey(t)[:16], next, approve(b.head, handoff.RouteCard, b.old, recipientID(next)))
	if w := b.ask(short); w != "factor" {
		t.Fatalf("a short recovery key on a done rotation answered %q", w)
	}

	b = newRotBox(t)
	req = request("passphrase", b.pass, next, approve(b.head, handoff.RouteCard, b.old, recipientID(next)))
	good := get(os.ReadFile(b.c.storePath()))
	b.putEntry(handoff.RecipientEntry, []byte("not a recipient"))
	if w := b.ask(req); w != "store" {
		t.Fatalf("a recipient that does not read answered %q", w)
	}
	noErr(t, os.WriteFile(b.c.storePath(), good, 0o600))
	st := get(seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: secret.Hide(b.pass)}))
	get(st.AddSlot(seal.Recovery{Key: secret.Hide(newKey(t))}))
	st.Close()
	if w := b.ask(req); w != "store" {
		t.Fatalf("two recovery slots answered %q", w)
	}
	noErr(t, os.WriteFile(b.c.storePath(), good, 0o600))
	state := b.c.state
	b.c.now = func() time.Time {
		noErr(t, os.Rename(state, state+".gone"))
		return testNow
	}
	if w := b.ask(req); w != "store" {
		t.Fatalf("a failed write answered %q", w)
	}
}

// lockStore's refusal to open the state directory is that open's error
// (main.go:1284).
func lockStoreOpenError(t *testing.T) {
	_, err := lockStore(config{state: filepath.Join(t.TempDir(), "none")}, false)
	var pe *fs.PathError
	if !errors.Is(err, errStoreOpen) || !errors.As(err, &pe) || pe.Op != "open" {
		t.Fatalf("got %v, want the open's error", err)
	}
}

// newCounter: a define refused before the TPM made anything returns that
// error and records no counter (main.go:828); one whose answer was lost and
// whose finishing define is then refused returns that refusal (:832).
func newCounterRefusals(t *testing.T) {
	b := newBox(t)
	srk, id := b.srk(), make([]byte, 16)
	get(rand.Read(id))
	f := &defineTPM{tpm: b.sw.TPM(), refuse: 1}
	if _, err := newCounter(f, srk, id); !errors.Is(err, errOnce{}) {
		t.Fatalf("a refused define: got %v", err)
	}
	if found, err := tpmseal.FindCounter(b.sw.TPM(), id); err != nil || found {
		t.Fatalf("a refused define left a counter: %v %v", found, err)
	}
	f = &defineTPM{tpm: b.sw.TPM(), lose: 1, refuseInc: 1}
	if _, err := newCounter(f, srk, id); !errors.Is(err, errOnce{}) {
		t.Fatalf("a refused finishing define: got %v", err)
	}
}

// defineTPM loses the answer to the lose-th NV_DefineSpace (the TPM ran
// it), refuses the refuse-th without running it, and refuses the
// refuseInc-th NV_Increment, the finishing define's.
type defineTPM struct {
	tpm                     transport.TPM
	n, inc                  int
	lose, refuse, refuseInc int
}

func (d *defineTPM) Send(cmd []byte) ([]byte, error) {
	switch binary.BigEndian.Uint32(cmd[6:10]) {
	case ccNVIncrement:
		if d.inc++; d.inc == d.refuseInc {
			return nil, errOnce{}
		}
		return d.tpm.Send(cmd)
	case ccNVDefineSpace:
	default:
		return d.tpm.Send(cmd)
	}
	d.n++
	if d.n == d.refuse {
		return nil, errOnce{}
	}
	rsp, err := d.tpm.Send(cmd)
	if d.n == d.lose {
		return nil, errors.New("test: the answer was lost")
	}
	return rsp, err
}

func mutgateKills2(t *testing.T) {
	t.Run("EnrollRefusedTPMCommand", enrollRefusedTPMCommand)
	t.Run("RotateRefusedTPMCommand", rotateRefusedTPMCommand)
	t.Run("DeleteRefusedTPMCommand", deleteRefusedTPMCommand)
	t.Run("EnrollRerunCommitsLockedPins", enrollRerunCommitsLockedPins)
	t.Run("EnrollRefusesTheAnchorDirAtItsOpen", enrollRefusesTheAnchorDirAtItsOpen)
	t.Run("EnrollClosesItsDescriptors", enrollClosesItsDescriptors)
	t.Run("EnrollHandsTheAnchorToTheKernel", enrollHandsTheAnchorToTheKernel)
	t.Run("EnrollNeedsBothFactors", enrollNeedsBothFactors)
	t.Run("EnrollFirstEdgeMessages", enrollFirstEdgeMessages)
	t.Run("EnrollWithAnUnreadableSeed", enrollWithAnUnreadableSeed)
	t.Run("ParseStagedRefuses", parseStagedRefuses)
	t.Run("CodesRefusalsAndLink", codesRefusalsAndLink)
	t.Run("StagedPairThatDoesNotRead", stagedPairThatDoesNotRead)
	t.Run("OpenWithAndWithoutPins", openWithAndWithoutPins)
	t.Run("RotateAndDeleteRefusals", rotateAndDeleteRefusals)
	t.Run("SlotPoliciesChoices", slotPoliciesChoices)
	t.Run("RotateRequestNextAndWipe", rotateRequestNextAndWipe)
	t.Run("RotateRecoveryStoreRefusals", rotateRecoveryStoreRefusals)
	t.Run("LockStoreOpenError", lockStoreOpenError)
	t.Run("NewCounterRefusals", newCounterRefusals)
}
