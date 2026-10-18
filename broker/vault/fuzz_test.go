package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fuzzT is the part of testing.T the oracle reports through, so a control
// can hand it a recorder and show that a planted defect is reported.
type fuzzT interface {
	Helper()
	Fatalf(format string, args ...any)
}

type stopRun struct{}

type recorder struct{ msgs []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
	panic(stopRun{})
}

func (r *recorder) run(f func(fuzzT)) (msgs []string) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(stopRun); !ok {
				panic(p)
			}
		}
		msgs = r.msgs
	}()
	f(r)
	return r.msgs
}

// reports runs f and says whether the oracle reported a failure containing
// want, so a control fails when only an unrelated oracle fires.
func (r *recorder) reports(f func(fuzzT), want string) bool {
	for _, m := range r.run(f) {
		if strings.Contains(m, want) {
			return true
		}
	}
	return false
}

// slotsDefect is a planted defect: it runs after each operation and may
// change the files the vault wrote or the vault itself.
type slotsDefect func(op int, host string, v *Vault, vp, kp string)

// leaksKey lists where the data key could show in a file: raw, hex and base64.
func leaksKey(key []byte) [][]byte {
	return [][]byte{
		key,
		[]byte(hex.EncodeToString(key)),
		[]byte(base64.StdEncoding.EncodeToString(key)),
		[]byte(base64.RawStdEncoding.EncodeToString(key)),
		[]byte(base64.URLEncoding.EncodeToString(key)),
		[]byte(base64.RawURLEncoding.EncodeToString(key)),
	}
}

// REQ: CRED-8

// FuzzSlots (FUZZ-4): over any sequence of host-slot adds and removals,
// rekeys with an enrolled or unenrolled factor, and reopenings, the vault
// opens with a factor exactly when the model says it is enrolled, its
// canary reads back, a refused rekey leaves the keys file as it was, and no
// data key the vault has held, raw or encoded, appears in a file it wrote.
func FuzzSlots(f *testing.F) {
	f.Add([]byte{0, 0, 2, 3, 3, 0})                    // add a host, rekey the passphrase, reopen
	f.Add([]byte{0, 1, 2, 4, 2, 1})                    // wrong passphrase, then an unenrolled host
	f.Add([]byte{0, 0, 0, 1, 2, 8, 1, 0, 2, 0})        // rekey to a host, remove it, prove with it
	f.Add([]byte{2, 3, 2, 24, 3, 0, 2, 3, 2, 4})       // passphrase moves and back
	f.Add([]byte{0, 0, 0, 0, 1, 2, 3, 0, 2, 16, 1, 1}) // duplicate adds and a no-op removal
	f.Fuzz(func(t *testing.T, b []byte) { fuzzSlots(t, t, b, nil) })
}

func fuzzSlots(t *testing.T, rep fuzzT, b []byte, defect slotsDefect) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	hosts := []string{"alpha", "bravo", "charlie"}
	passes := []string{testPass, "harbor violet canary second passphrase"}
	pass := testPass
	enrolled := map[string]bool{} // hosts with a slot
	val := canary(t)
	v, err := CreateSealed(vp, kp, Passphrase(pass))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { v.Close() }()
	if err := v.Put("canary", KindAPIKey, val); err != nil {
		t.Fatal(err)
	}
	// keys are the data keys the vault has held, copied as they appear.
	var keys [][]byte
	hold := func(w *Vault) {
		for _, k := range keys {
			if bytes.Equal(k, w.key) {
				return
			}
		}
		keys = append(keys, append([]byte(nil), w.key...))
	}
	hold(v)
	// factor i is host i for i < 3, then passphrase i-3; its name and
	// whether the model says it opens the vault.
	factor := func(i int) (Factor, string, bool) {
		if i < len(hosts) {
			return newHost(hosts[i]), hosts[i], enrolled[hosts[i]]
		}
		p := passes[i-len(hosts)]
		return Passphrase(p), fmt.Sprintf("passphrase %d", i-len(hosts)), p == pass
	}
	nf := len(hosts) + len(passes)
	at := func(i int) byte {
		if i < len(b) {
			return b[i]
		}
		return 0
	}
	for i, ops := 0, 0; i < len(b) && ops < 64; ops++ {
		op, arg := at(i)%4, at(i+1)
		i += 2
		h := hosts[int(arg)%len(hosts)]
		switch op {
		case 0:
			if err := v.AddSlot(newHost(h), sameHost(newHost(h))); err != nil {
				rep.Fatalf("op %d: add %s: %v", ops, h, err)
			}
			enrolled[h] = true
		case 1:
			if _, err := v.RemoveSlots(SlotTPM, sameHost(newHost(h))); err != nil {
				rep.Fatalf("op %d: remove %s: %v", ops, h, err)
			}
			delete(enrolled, h)
		case 2:
			have, hname, ok := factor(int(arg) % nf)
			nx := int(arg>>3) % nf
			next, nname, _ := factor(nx)
			before, err := os.ReadFile(kp)
			if err != nil {
				t.Fatal(err)
			}
			err = v.Rekey(have, next)
			if !ok {
				if !errors.Is(err, ErrNoSlotOpens) {
					rep.Fatalf("op %d: rekey with unenrolled %s: %v", ops, hname, err)
				}
				after, rerr := os.ReadFile(kp)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(before, after) {
					rep.Fatalf("op %d: a refused rekey with %s changed the keys file", ops, hname)
				}
				break
			}
			if err != nil {
				rep.Fatalf("op %d: rekey %s to %s: %v", ops, hname, nname, err)
			}
			if nx < len(hosts) {
				enrolled = map[string]bool{hosts[nx]: true}
			} else {
				pass = passes[nx-len(hosts)]
			}
		case 3:
			if err := v.Close(); err != nil {
				rep.Fatalf("op %d: close: %v", ops, err)
			}
			if v, err = OpenSealed(vp, kp, Passphrase(pass)); err != nil {
				rep.Fatalf("op %d: reopen with the current passphrase: %v", ops, err)
			}
		}
		if defect != nil {
			defect(int(op), h, v, vp, kp)
		}
		hold(v)
		for _, path := range []string{vp, kp} {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range keys {
				for _, enc := range leaksKey(k) {
					if bytes.Contains(data, enc) {
						rep.Fatalf("op %d: the data key is in %s", ops, path)
					}
				}
			}
		}
		for j := 0; j < nf; j++ {
			fac, name, want := factor(j)
			w, err := OpenSealed(vp, kp, fac)
			if (err == nil) != want {
				rep.Fatalf("op %d: %s opens %v, want %v (%v)", ops, name, err == nil, want, err)
			}
			if err != nil {
				continue
			}
			hold(w)
			s, ok := w.Secret("canary")
			if !ok || s.Reveal() != string(val) {
				rep.Fatalf("op %d: %s opened a vault without its canary", ops, name)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Each control plants a defect after the operations and shows the oracle
// reports it, then shows the real vault passes the same inputs.
func TestFuzzSlotsReportsAPlantedDefect(t *testing.T) {
	leak := func(op int, _ string, v *Vault, _, kp string) {
		f, err := os.OpenFile(kp, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		f.WriteString("\n" + base64.StdEncoding.EncodeToString(v.key))
	}
	staleSlot := func(op int, h string, v *Vault, _, _ string) {
		if op == 1 {
			if err := v.AddSlot(newHost(h), sameHost(newHost(h))); err != nil {
				t.Fatal(err)
			}
		}
	}
	in := []byte{0, 0, 1, 0, 2, 3, 3, 0}
	for name, c := range map[string]struct {
		d    slotsDefect
		want string
	}{
		"leaks the data key":     {leak, "the data key is in"},
		"removal keeps the slot": {staleSlot, "opens true, want false"},
	} {
		var rec recorder
		if !rec.reports(func(ft fuzzT) { fuzzSlots(t, ft, in, c.d) }, c.want) {
			t.Errorf("%s: the oracle did not report %q: %v", name, c.want, rec.msgs)
		}
	}
	var rec recorder
	if msgs := rec.run(func(ft fuzzT) { fuzzSlots(t, ft, in, nil) }); len(msgs) != 0 {
		t.Errorf("the real vault reported: %v", msgs)
	}
}
