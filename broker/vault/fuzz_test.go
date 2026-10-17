package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
)

// REQ: CRED-8

// FuzzSlots (FUZZ-6): over any sequence of host-slot adds and removals,
// rekeys with an enrolled or unenrolled factor, and reopenings, the vault
// opens with a factor exactly when the model says it is enrolled, its
// canary reads back, and a refused rekey leaves the keys file as it was.
func FuzzSlots(f *testing.F) {
	f.Add([]byte{0, 0, 2, 3, 3, 0})                    // add a host, rekey the passphrase, reopen
	f.Add([]byte{0, 1, 2, 4, 2, 1})                    // wrong passphrase, then an unenrolled host
	f.Add([]byte{0, 0, 0, 1, 2, 8, 1, 0, 2, 0})        // rekey to a host, remove it, prove with it
	f.Add([]byte{2, 3, 2, 24, 3, 0, 2, 3, 2, 4})       // passphrase moves and back
	f.Add([]byte{0, 0, 0, 0, 1, 2, 3, 0, 2, 16, 1, 1}) // duplicate adds and a no-op removal
	f.Fuzz(func(t *testing.T, b []byte) {
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
					t.Fatalf("op %d: add %s: %v", ops, h, err)
				}
				enrolled[h] = true
			case 1:
				if _, err := v.RemoveSlots(SlotTPM, sameHost(newHost(h))); err != nil {
					t.Fatalf("op %d: remove %s: %v", ops, h, err)
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
						t.Fatalf("op %d: rekey with unenrolled %s: %v", ops, hname, err)
					}
					after, rerr := os.ReadFile(kp)
					if rerr != nil {
						t.Fatal(rerr)
					}
					if !bytes.Equal(before, after) {
						t.Fatalf("op %d: a refused rekey with %s changed the keys file", ops, hname)
					}
					break
				}
				if err != nil {
					t.Fatalf("op %d: rekey %s to %s: %v", ops, hname, nname, err)
				}
				if nx < len(hosts) {
					enrolled = map[string]bool{hosts[nx]: true}
				} else {
					pass = passes[nx-len(hosts)]
				}
			case 3:
				if err := v.Close(); err != nil {
					t.Fatalf("op %d: close: %v", ops, err)
				}
				if v, err = OpenSealed(vp, kp, Passphrase(pass)); err != nil {
					t.Fatalf("op %d: reopen with the current passphrase: %v", ops, err)
				}
			}
			for j := 0; j < nf; j++ {
				fac, name, want := factor(j)
				w, err := OpenSealed(vp, kp, fac)
				if (err == nil) != want {
					t.Fatalf("op %d: %s opens %v, want %v (%v)", ops, name, err == nil, want, err)
				}
				if err != nil {
					continue
				}
				s, ok := w.Secret("canary")
				if !ok || s.Reveal() != string(val) {
					t.Fatalf("op %d: %s opened a vault without its canary", ops, name)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
