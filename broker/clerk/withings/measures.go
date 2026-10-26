package withings

import (
	"math"
	"sort"
)

// Measure is a measurement kind from the closed table below. The codes are
// the public Withings API's, as the source maps them.
type Measure string

var measures = map[uint16]Measure{
	1:   "weight_kg",
	5:   "fat_free_mass_kg",
	6:   "fat_ratio_pct",
	8:   "fat_mass_kg",
	11:  "heart_rate_bpm",
	76:  "muscle_mass_kg",
	77:  "hydration_kg",
	88:  "bone_mass_kg",
	170: "visceral_fat_index",
	226: "basal_metabolic_rate_kcal",
	227: "metabolic_age_years",
}

// Reading is one value of one weigh-in. It carries no text from the scale:
// a time, a measure from the closed table, a decimal value (Value ×
// 10^Exp), and the scale's user slot (0 when the scale did not know whose
// weigh-in it was). Every reading is private (PLN-3) and unverified (DEV-3):
// the scale has no cryptographic identity beyond the shared kl.
type Reading struct {
	Time       int64 // UTC epoch seconds
	User       uint32
	Measure    Measure
	Value      int32
	Exp        int16
	Unverified bool
}

// Float is the reading's value.
func (r Reading) Float() float64 { return float64(r.Value) * math.Pow10(int(r.Exp)) }

// maxIDs bounds a record's user array.
const maxIDs = 16

// parseRecords reads STORED_MEASURE records in order: each META starts a
// group and the values after it are its own. A value after a bad or missing
// META is dropped with it rather than given to the previous group, which may
// be someone else's weigh-in. Readings come back merged, one per (time,
// user, measure), the later winning, oldest first: the scale returns its
// whole store each time, and one weigh-in arrives as several groups.
func parseRecords(ms []message) ([]Reading, int) {
	type key struct {
		t int64
		u uint32
		m Measure
	}
	merged := map[key]Reading{}
	dropped := 0
	var cur *struct {
		t int64
		u uint32
	}
	for _, m := range ms {
		for _, x := range m.tlvs {
			switch x.typ {
			case tMeasureMeta:
				cur = nil
				t, u, ok := parseMeta(x.val)
				if !ok {
					dropped++
					continue
				}
				cur = &struct {
					t int64
					u uint32
				}{t, u}
			case tMeasureData:
				r := reader{b: x.val}
				v, typ, exp := r.i32(), r.u16(), r.i16()
				name, known := measures[typ]
				if cur == nil || !r.done() || !known || exp < -9 || exp > 9 {
					dropped++
					continue
				}
				merged[key{cur.t, cur.u, name}] = Reading{cur.t, cur.u, name, v, exp, true}
			}
		}
	}
	out := make([]Reading, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Time != b.Time {
			return a.Time < b.Time
		}
		if a.User != b.User {
			return a.User < b.User
		}
		return a.Measure < b.Measure
	})
	return out, dropped
}

// parseMeta reads STORED_MEASURE_META: uid u32, valid u8, ids (u8 count of
// u32), attrib u8, time u32. Only the first valid IDs mean anything; the
// user is the first nonzero one.
func parseMeta(v []byte) (int64, uint32, bool) {
	r := reader{b: v}
	r.u32()
	valid := int(r.u8())
	n := int(r.u8())
	if n > maxIDs {
		return 0, 0, false
	}
	ids := make([]uint32, n)
	for i := range ids {
		ids[i] = r.u32()
	}
	r.u8()
	t := r.u32()
	if !r.done() {
		return 0, 0, false
	}
	var user uint32
	for i := 0; i < valid && i < n; i++ {
		if ids[i] != 0 {
			user = ids[i]
			break
		}
	}
	return int64(t), user, true
}
