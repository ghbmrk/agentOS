//go:build linux

package main

// REQ: DEV-7

import (
	"bufio"
	"encoding/binary"
	"math/rand"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// TestThermalLeavesNoFrameCopy (#3779, VIS-A7): once heatBlobs has
// returned and the caller has zeroed its frame, no run of the frame's
// bytes is anywhere in the process's memory, so heatBlobs zeroed its own
// copy. The garbage collector is off, so freed memory is not reused and
// keeps whatever was left in it; the scanner is checked to find the run
// while the frame still holds it.
func TestThermalLeavesNoFrameCopy(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	f := thermalScene(rng, 160, 120, 27315, []vision.Box{{X0: 40, Y0: 30, X1: 64, Y1: 90}})
	// 64 bytes of the body, whose samples are noisy, so the run is in
	// memory only where the frame's bytes were copied. The test keeps it
	// masked by a random key, so the run it looks for is not itself one.
	const at, n = 2 * (60*160 + 44), 64
	key := make([]byte, n)
	rng.Read(key)
	masked := make([]byte, n)
	for i := range masked {
		masked[i] = f.Data[at+i] ^ key[i]
	}
	if found := scanMemory(t, masked, key); found == 0 {
		t.Fatal("the scanner did not find the run in the frame itself")
	}
	if ds := heatBlobs(f); len(ds) != 1 {
		t.Fatalf("heatBlobs: %+v, want one body", ds)
	}
	clear(f.Data)
	if found := scanMemory(t, masked, key); found != 0 {
		t.Fatalf("%d copies of the frame's bytes are left after heatBlobs", found)
	}
}

// TestThermalLeavesNoOutline (#3792, VIS-A7): once heatBlobs has
// returned, neither its fill stack, which held the places of a body's
// samples, nor its labels, which marked them, is left in memory: no 16
// int32s in a row are each a place inside the body, and no 16 in a row
// are the body's label. The frame's top rows hold 159 lone warm samples
// first, each its own region too small to be a body, so the body's label
// is 160, a value no other run of the process holds 16 times over. The
// scanner is checked to find each pattern in a slice the test fills.
func TestThermalLeavesNoOutline(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	const w, h = 160, 120
	body := vision.Box{X0: 40, Y0: 30, X1: 64, Y1: 90}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	f := thermalScene(rng, w, h, 27315, []vision.Box{body})
	lone := 0
	for y := 2; y <= 8; y += 3 {
		for x := 1; x < w; x += 3 {
			binary.LittleEndian.PutUint16(f.Data[2*(y*w+x):], 27315+2400)
			lone++
		}
	}
	id := uint32(lone + 1)
	const run = 16
	inBody := func(v uint32) bool {
		x, y := int(v)%w, int(v)/w
		return v < w*h && x >= body.X0 && x < body.X1 && y >= body.Y0 && y < body.Y1
	}
	places := func(b []byte) bool {
		for i := 0; i < len(b); i += 4 {
			if !inBody(binary.LittleEndian.Uint32(b[i:])) {
				return false
			}
		}
		return true
	}
	labels := func(b []byte) bool {
		for i := 0; i < len(b); i += 4 {
			if binary.LittleEndian.Uint32(b[i:]) != id {
				return false
			}
		}
		return true
	}
	probe := heapInt32s(run)
	for i := range probe {
		probe[i] = int32((body.Y0+10)*w + body.X0 + i)
	}
	if scanMemoryFor(t, 4*run, 4, places) == 0 {
		t.Fatal("the scanner did not find a run of places in the test's own slice")
	}
	for i := range probe {
		probe[i] = int32(id)
	}
	if scanMemoryFor(t, 4*run, 4, labels) == 0 {
		t.Fatal("the scanner did not find a run of labels in the test's own slice")
	}
	clear(probe)
	if ds := heatBlobs(f); len(ds) != 1 {
		t.Fatalf("heatBlobs: %+v, want one body", ds)
	}
	clear(f.Data)
	if n := scanMemoryFor(t, 4*run, 4, places); n != 0 {
		t.Errorf("%d runs of the body's places are left after heatBlobs", n)
	}
	if n := scanMemoryFor(t, 4*run, 4, labels); n != 0 {
		t.Errorf("%d runs of the body's label are left after heatBlobs", n)
	}
}

// probeSink makes heapInt32s' slices escape to the heap: on a goroutine
// stack the test's own probe would be copied, unzeroed, whenever the
// stack grows, and be found once more after it is cleared.
var probeSink []int32

// heapInt32s is n zero int32s on the heap.
func heapInt32s(n int) []int32 {
	probeSink = make([]int32, n)
	s := probeSink
	probeSink = nil
	return s
}

// scanMemory counts the places in the process's readable, writable
// memory holding the run whose bytes XOR key give masked.
func scanMemory(t *testing.T, masked, key []byte) int {
	t.Helper()
	return scanMemoryFor(t, len(masked), 1, func(w []byte) bool {
		for j := range w {
			if w[j]^key[j] != masked[j] {
				return false
			}
		}
		return true
	})
}

// scanMemoryFor counts the places, every step bytes from each region's
// start, in the process's readable, writable memory where the n bytes
// there match.
func scanMemoryFor(t *testing.T, n, step int, match func([]byte) bool) int {
	t.Helper()
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	defer maps.Close()
	type region struct{ lo, hi uint64 }
	var rs []region
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 || !strings.HasPrefix(fs[1], "rw") {
			continue
		}
		if len(fs) >= 6 && strings.HasPrefix(fs[5], "[v") { // [vvar], [vsyscall]
			continue
		}
		lo, hi, _ := strings.Cut(fs[0], "-")
		l, err1 := strconv.ParseUint(lo, 16, 64)
		h, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 == nil && err2 == nil {
			rs = append(rs, region{l, h})
		}
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	buf := make([]byte, 1<<20)
	defer clear(buf)
	// Chunks advance by a whole number of steps and overlap by at least
	// n-1 bytes, so a run across two is seen once.
	adv := (len(buf) - n + 1) / step * step
	found := 0
	for _, r := range rs {
		for off := r.lo; off < r.hi; off += uint64(adv) {
			size := min(uint64(len(buf)), r.hi-off)
			got, _ := mem.ReadAt(buf[:size], int64(off))
			for i := 0; i+n <= got && i < adv; i += step {
				if match(buf[i : i+n]) {
					found++
				}
			}
			clear(buf)
			if size < uint64(len(buf)) {
				break
			}
		}
	}
	return found
}
