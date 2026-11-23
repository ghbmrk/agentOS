package main

// REQ: DEV-7

import "testing"

// TestEncodeFacesBestFirstOnEveryRun: past maxFaces the weakest faces are
// the ones left unknown, whatever order the faces were matched in. The
// matching is a map, which Go ranges in a new order each time, so the
// check runs many times: without the best-first sort some run leaves a
// strong face unencoded.
func TestEncodeFacesBestFirstOnEveryRun(t *testing.T) {
	const n = maxFaces + 4
	for run := 0; run < 64; run++ {
		var seen []Seen
		var fs []face
		for i := 0; i < n; i++ {
			x := 100 * i
			seen = append(seen, person(x, 0, x+90, 300))
			fs = append(fs, faceAt(float64(x+20), 20, 40, 0.5+0.03*float64(i))) // the last is the best
		}
		if err := encodeFaces(seen, fs, func(f face) ([]float32, error) {
			return []float32{float32(f.score)}, nil
		}); err != nil {
			t.Fatal(err)
		}
		for i, d := range seen {
			if weak := i < n-maxFaces; weak != (len(d.Face) == 0) {
				t.Fatalf("run %d: person %d (score %.2f) has %v; only the %d weakest are left unknown", run, i, fs[i].score, d.Face, n-maxFaces)
			}
		}
	}
}
