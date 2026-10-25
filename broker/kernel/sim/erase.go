package sim

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// SIM-erase (docs/migration/cases.md §4): a forget reaches every derived
// view exactly once. RunErase opens subjects, seals their items into two
// stores, then erases some of them with a crash at the nth durable write of
// the erase phase (the log, the key table or a store), reboots, lets the
// owner erase again whatever the crash left unlogged, and ticks until done.
// Stores also fail deletes now and then, for a while.

// machine counts durable writes and crashes at the armed one: that write
// does not land, and none does until the reboot.
type machine struct {
	left    int // writes until the crash; 0 is disarmed
	crashed bool
	hit     string // the kind of write the crash fell on
	flaky   bool   // stores fail deletes
	rng     *rand.Rand
}

func (m *machine) write(kind string) error {
	if m.crashed {
		return errCrash
	}
	if m.left > 0 {
		m.left--
		if m.left == 0 {
			m.crashed, m.hit = true, kind
			return errCrash
		}
	}
	return nil
}

type crashLog struct {
	*Disk
	m *machine
}

func (c crashLog) Append(b []byte) error {
	if !c.m.crashed && c.m.left == 1 {
		c.m.left, c.m.crashed, c.m.hit = 0, true, "log"
		c.Disk.Arm(1) // the frame is torn
	} else if c.m.crashed {
		return errCrash
	} else if c.m.left > 0 {
		c.m.left--
	}
	return c.Disk.Append(b)
}

type crashKeys struct {
	*kernel.MemKeys
	m *machine
}

func (c crashKeys) Put(s string, k kernel.SubjectKey) error {
	if err := c.m.write("key"); err != nil {
		return err
	}
	return c.MemKeys.Put(s, k)
}

func (c crashKeys) Delete(s string) error {
	if err := c.m.write("key"); err != nil {
		return err
	}
	return c.MemKeys.Delete(s)
}

type crashStore struct {
	*kernel.MemContent
	m *machine
}

var errStoreDown = errors.New("sim: store down")

func (c crashStore) Put(h kernel.Hash, ct []byte) error {
	if err := c.m.write("store"); err != nil {
		return err
	}
	return c.MemContent.Put(h, ct)
}

func (c crashStore) Delete(h kernel.Hash) error {
	if c.m.flaky && c.m.rng.IntN(3) == 0 {
		return errStoreDown
	}
	if err := c.m.write("store"); err != nil {
		return err
	}
	return c.MemContent.Delete(h)
}

// EraseResult is one erase run.
type EraseResult struct {
	Crashed bool   // the armed write was reached
	Hit     string // what it fell on: log, key or store
}

// RunErase runs seed with a crash at the crashAt-th write of the erase
// phase (0: none) and judges the end state.
func RunErase(seed uint64, crashAt int) (EraseResult, error) {
	rng := rand.New(rand.NewPCG(seed, 0xe7a5e))
	var nseed [32]byte
	for i := range nseed {
		nseed[i] = byte(rng.IntN(256))
	}
	head := gen(rng)
	m := &machine{rng: rng}
	disk := &Disk{rng: rng}
	cfg := kernel.Config{Store: crashLog{disk, m}, Anchor: &kernel.MemAnchor{}, Pub: head.pub, Sign: head.priv, Rand: rand.NewChaCha8(nseed)}
	keys := crashKeys{kernel.NewMemKeys(), m}
	stores := map[string]kernel.ContentStore{"mail": crashStore{kernel.NewMemContent(), m}, "notes": crashStore{kernel.NewMemContent(), m}}
	names := []string{"mail", "notes"}
	var k *kernel.Kernel
	now := int64(0)
	boot := func() error {
		disk.Reboot()
		m.crashed, m.left = false, 0
		l, err := kernel.Open(cfg)
		if err == nil {
			k, err = kernel.Boot(l, nil, nil, now)
		}
		if err == nil {
			_, err = k.OpenContent(keys, stores, now)
		}
		return err
	}
	if err := boot(); err != nil {
		return EraseResult{}, err
	}

	subs := make([]string, 2+rng.IntN(3))
	items := map[kernel.Hash]simItem{}
	for i := range subs {
		now++
		s, err := k.OpenSubject(now)
		if err != nil {
			return EraseResult{}, err
		}
		subs[i] = s
		for j := rng.IntN(4); j >= 0; j-- {
			text := fmt.Sprintf("item %d of %d", j, i)
			store := names[rng.IntN(2)]
			h, err := k.Seal(now, s, store, "message", []byte(text))
			if err != nil {
				return EraseResult{}, err
			}
			items[h] = simItem{text, s, store}
		}
	}
	gone := map[string]bool{}
	for _, s := range subs {
		if rng.IntN(2) == 0 {
			gone[s] = true
		}
	}
	gone[subs[0]] = true

	// The erase phase: the owner erases, the box ticks, stores flake.
	m.left, m.flaky = crashAt, true
	var res EraseResult
	settle := func() error {
		for range 8 {
			now++
			for _, s := range subs {
				if rc, _ := k.State().Recall(s); gone[s] && !rc.Erased {
					k.Erase(now, s) // the owner asks again: the first did not land
				}
			}
			if err := k.Tick(now); err != nil && !errors.Is(err, errCrash) {
				return err
			}
			if m.crashed {
				res.Crashed, res.Hit = true, m.hit
				if err := boot(); err != nil {
					return fmt.Errorf("reboot: %w", err)
				}
			}
		}
		return nil
	}
	if err := settle(); err != nil {
		return res, err
	}
	m.flaky = false
	if err := settle(); err != nil {
		return res, err
	}
	return res, judgeErase(k, keys, stores, subs, gone, items)
}

// judgeErase checks the end state against the log and the stores, without
// trusting the kernel's account of them.
func judgeErase(k *kernel.Kernel, keys crashKeys, stores map[string]kernel.ContentStore,
	subs []string, gone map[string]bool, items map[kernel.Hash]simItem) error {
	es := k.Log().Entries()
	re, err := kernel.Replay(nil, es)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(re, k.State()) {
		return errors.New("invariant: replay differs from the live state")
	}
	erased := map[string]int{}
	confirmed := map[[2]string]int{}
	for _, e := range es {
		var b struct{ Subject, Store string }
		switch e.Type {
		case kernel.TSubjectErased:
			json.Unmarshal(e.Body, &b)
			erased[b.Subject]++
		case kernel.TEraseConfirmed:
			json.Unmarshal(e.Body, &b)
			confirmed[[2]string{b.Subject, b.Store}]++
		}
	}
	if u := k.State().Unerased(); u != nil {
		return fmt.Errorf("invariant: still unerased %+v", u)
	}
	for _, s := range subs {
		_, has, _ := keys.Get(s)
		rc, _ := k.State().Recall(s)
		switch {
		case gone[s] && erased[s] != 1:
			return fmt.Errorf("invariant: %d subject.erased for one erase", erased[s])
		case !gone[s] && erased[s] != 0:
			return errors.New("invariant: a subject the owner kept was erased")
		case gone[s] && has:
			return errors.New("invariant: an erased subject's key is in the table")
		case !gone[s] && !has:
			return errors.New("invariant: a kept subject lost its key")
		case gone[s] && !rc.Erased:
			return errors.New("invariant: recall does not show the erase")
		}
	}
	for c, n := range confirmed {
		if n != 1 || !gone[c[0]] {
			return fmt.Errorf("invariant: %d erase.confirmed for one store", n)
		}
	}
	held := map[[2]string]bool{}
	for h, it := range items {
		s, text := it.subject, it.text
		held[[2]string{s, it.store}] = true
		pt, rerr := k.Read(h)
		inStore := false
		for _, cs := range stores {
			if _, err := cs.Get(h); err == nil {
				inStore = true
			}
		}
		switch {
		case gone[s] && (rerr == nil || inStore):
			return errors.New("invariant: an erased item is still readable or stored")
		case !gone[s] && (rerr != nil || string(pt) != text):
			return fmt.Errorf("invariant: a kept item does not read: %v", rerr)
		}
	}
	for c := range held {
		if gone[c[0]] && confirmed[c] != 1 {
			return errors.New("invariant: a store that held an erased item never confirmed")
		}
	}
	for s := range gone {
		if rc, _ := k.State().Recall(s); len(rc.Unconfirmed) != 0 {
			return errors.New("invariant: recall lists an unconfirmed store at the end")
		}
	}
	return nil
}

type simItem struct{ text, subject, store string }
