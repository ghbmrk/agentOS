package kernel

// Reading is the kernel's time for one decision, Unix ms: true time is no
// earlier than Earliest and no later than Latest (TIM-1). A move that time
// widens (a hold's end, a grant going live, a window resetting, a use ageing
// out of a day) waits until Earliest reaches its due; a check that time
// narrows (a key's expiry, a task's timeout, an ask lapsing) fails once
// Latest reaches it. While the TIM-1 guard's sources disagree the interval is
// wide, so widenings wait and narrowings fire: the guard's restricted mode.
type Reading struct{ Earliest, Latest int64 }

// Clock reads the TIM-1 guard: the earliest and latest credible times
// (clock.Guard.Earliest, clock.Guard.Latest). The kernel takes a fresh
// reading for each decision.
type Clock func() Reading

// At is a reading at one time, as a caller with one clock gives it.
func At(ms int64) Reading { return Reading{ms, ms} }

// UseClock makes k read c at each decision in place of the caller's now.
func (k *Kernel) UseClock(c Clock) { k.clock = c }

// read is the reading for one decision: a fresh reading of the kernel's
// clock, or the caller's now for a kernel without one, floored at the last
// entry's time. So the kernel's time never runs backward, the log's times
// stay ordered, and a clock stepped back cannot revive what an earlier entry
// saw expire (KEY-7). The floor holds Latest too.
func (k *Kernel) read(now int64) Reading {
	r := At(now)
	if k.clock != nil {
		r = k.clock()
	}
	r.Latest = max(r.Latest, r.Earliest) // a malformed reading is read as its Earliest
	last := k.log.lastAt()
	return Reading{max(r.Earliest, last), max(r.Latest, last)}
}

// reading is e's: the time it was logged at and the latest its decision
// allowed (Entry.Late).
func (e Entry) reading() Reading {
	if e.Late == nil {
		return At(e.At)
	}
	return Reading{e.At, max(e.At, *e.Late)}
}
