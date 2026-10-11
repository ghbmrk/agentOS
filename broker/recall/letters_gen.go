//go:build ignore

// letters_gen writes letters.bin, the letter model behind randomLooking's
// letters-only floor (ASSUMPTIONS R11). Run from broker/recall with the
// toolchain broker/go.mod names: go run letters_gen.go "$(go env GOROOT)"
//
// It counts letter bigrams and trigrams over the distinct words (seen at
// least twice) of the English comments in GOROOT/src, outside testdata and
// vendor. Each distinct word counts once, so frequent words do not dominate.
// The bigram estimate is add-one smoothed; the trigram estimate falls back to
// it with weight 26. Each entry is floor(8 * log2(26 * P)), clamped to int8:
// rounding down keeps every context's probabilities summing to at most one,
// which is what bounds the floor's miss rate (TestLetterModelNormalized).
//
// Layout: 26*26 bigram entries [a][b], then 26*26*26 trigram entries [a][b][c].
package main

import (
	"io/fs"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run letters_gen.go GOROOT")
	}
	src := filepath.Join(os.Args[1], "src")
	words := map[string]int{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			i := strings.Index(line, "//")
			if i < 0 {
				continue
			}
			for _, w := range strings.FieldsFunc(line[i+2:], func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
			}) {
				words[strings.ToLower(w)]++
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	var bi [26][26]float64
	var tri [26][26][26]float64
	for w, n := range words {
		if n < 2 || len(w) < 2 {
			continue
		}
		for i := 1; i < len(w); i++ {
			bi[w[i-1]-'a'][w[i]-'a']++
			if i >= 2 {
				tri[w[i-2]-'a'][w[i-1]-'a'][w[i]-'a']++
			}
		}
	}
	var pb [26][26]float64
	for a := range 26 {
		var s float64
		for b := range 26 {
			s += bi[a][b]
		}
		for b := range 26 {
			pb[a][b] = (bi[a][b] + 1) / (s + 26)
		}
	}
	q := func(p float64) byte {
		v := math.Floor(8 * math.Log2(26*p))
		return byte(int8(max(-128, min(127, v))))
	}
	buf := make([]byte, 0, 26*26+26*26*26)
	for a := range 26 {
		for b := range 26 {
			buf = append(buf, q(pb[a][b]))
		}
	}
	for a := range 26 {
		for b := range 26 {
			var s float64
			for c := range 26 {
				s += tri[a][b][c]
			}
			for c := range 26 {
				buf = append(buf, q((tri[a][b][c]+26*pb[b][c])/(s+26)))
			}
		}
	}
	if err := os.WriteFile("letters.bin", buf, 0o644); err != nil {
		log.Fatal(err)
	}
}
