package clock

import "time"

// MaxPlainFloorRaise is how far an unauthenticated (plain NTP or carrier)
// sync may advance the floor in one step (HOST-1b Security O2 on #177).
// An on-path attacker who blocks NTS-KE and forges pool sources can only
// push the floor this far per verified plain check; SyncedNTS is uncapped.
const MaxPlainFloorRaise = 24 * time.Hour

// plainFloorRaise returns the floor after a verified sync at now.
// nts true: floor becomes now when ahead (uncapped). Otherwise the raise
// is capped at MaxPlainFloorRaise above the prior floor.
func plainFloorRaise(floor, now time.Time, nts bool) time.Time {
	if floor.IsZero() || !now.After(floor) {
		return now
	}
	if nts {
		return now
	}
	cap := floor.Add(MaxPlainFloorRaise)
	if now.After(cap) {
		return cap
	}
	return now
}
