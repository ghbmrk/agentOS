//go:build linux

package main

// REQ: DEV-7

import (
	"bufio"
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

// scanMemory counts the places in the process's readable, writable
// memory holding the run whose bytes XOR key give masked.
func scanMemory(t *testing.T, masked, key []byte) int {
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
	n := len(masked)
	buf := make([]byte, 1<<20)
	defer clear(buf)
	found := 0
	for _, r := range rs {
		// Chunks overlap by n-1 bytes, so a run across two is seen.
		for off := r.lo; off < r.hi; off += uint64(len(buf) - n + 1) {
			size := min(uint64(len(buf)), r.hi-off)
			got, _ := mem.ReadAt(buf[:size], int64(off))
			for i := 0; i+n <= got; i++ {
				j := 0
				for j < n && buf[i+j]^key[j] == masked[j] {
					j++
				}
				if j == n {
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
