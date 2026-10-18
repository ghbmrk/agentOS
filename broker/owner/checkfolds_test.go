package owner

// REQ: CH-12, CH-19, CH-21

import (
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

func foldsMatch(t *testing.T, s, lit string) bool {
	t.Helper()
	re := regexp.MustCompile(`^` + FoldPattern(lit) + `$`)
	for _, f := range CheckFolds(s) {
		if re.MatchString(f) {
			return true
		}
	}
	return false
}

// The two gaps the #2180 reviews found (#2181): a mark that case folding
// turns into a letter, and capitals whose case fold loses their shape.
func TestCH12CheckFoldsMarksAndCapitals(t *testing.T) {
	for _, c := range []struct{ attack, plain string }{
		{"YͅES A7", "YES A7"},
		{"ΥΕЅ Α7", "YES A7"},
		{"ΝΟ Α7", "NO A7"},
		{"ᎷORE A7", "MORE A7"},
		{"YES⠀A7", "YES A7"},
		{"Y‍ES A7", "YES A7"},
		{"RNORE A7", "MORE A7"},
	} {
		if !foldsMatch(t, c.attack, c.plain) {
			t.Errorf("%+q: no fold of %v matches %q", c.attack, CheckFolds(c.attack), c.plain)
		}
	}
	if !foldsMatch(t, "yes a7", "YES A7") || foldsMatch(t, "yes a7", "NO A7") {
		t.Error("FoldPattern does not tell YES A7 from NO A7")
	}
}

// TestCH12CapitalHomoglyphsCaught: every confusables pair whose two sides
// CH-12's fold keeps apart (380 in Unicode 15.0.0) shares a fold in
// CheckFolds, and every character whose prototype is ASCII has a fold
// FoldPattern's pattern for that prototype matches.
func TestCH12CapitalHomoglyphsCaught(t *testing.T) {
	apart := 0
	for r, p := range skelProto {
		if SkeletonFold(string(r), false) == SkeletonFold(p, false) {
			continue
		}
		apart++
		shared := false
		pf := map[string]bool{}
		for _, f := range CheckFolds(p) {
			pf[f] = true
		}
		for _, f := range CheckFolds(string(r)) {
			shared = shared || pf[f]
		}
		if !shared {
			t.Errorf("%U %q, prototype %q: folds %q and %q share none", r, string(r), p, CheckFolds(string(r)), CheckFolds(p))
		}
	}
	if apart != 380 {
		t.Errorf("%d confusables pairs fold apart, the #2180 review counted 380", apart)
	}
	for r, p := range skelProto {
		if utf8.RuneCountInString(p) == len(p) && strings.TrimSpace(p) == p && p != "" && !foldsMatch(t, string(r), p) {
			t.Errorf("%U %q: no fold of %q matches FoldPattern(%q)", r, string(r), CheckFolds(string(r)), p)
		}
	}
}

// TestCH12MixedHomoglyphWordsCaught: control and vocabulary words with
// each letter replaced by a random character whose prototype is that
// letter, in either case, so one word mixes capitals and small letters
// from several scripts.
func TestCH12MixedHomoglyphWordsCaught(t *testing.T) {
	like := map[string][]rune{}
	for r, p := range skelProto {
		like[p] = append(like[p], r)
	}
	for _, rs := range like {
		sort.Slice(rs, func(i, j int) bool { return rs[i] < rs[j] })
	}
	rng := rand.New(rand.NewSource(2181))
	words := []string{"STOP", "YES", "NO", "RUN", "UNDO", "MORE", "HELP", "STATUS", "RESUME", "UNLOCK", "NAME",
		"code", "passcode", "pin", "otp", "authenticator", "verification", "grid", "cell", "password", "SIGNIN", "MFA"}
	for i := 0; i < 4000; i++ {
		w := words[rng.Intn(len(words))]
		var b strings.Builder
		for _, c := range w {
			cs := []string{strings.ToLower(string(c)), strings.ToUpper(string(c))}
			s := cs[rng.Intn(2)]
			if rs := like[s]; len(rs) > 0 && rng.Intn(4) != 0 {
				b.WriteRune(rs[rng.Intn(len(rs))])
			} else {
				b.WriteString(s)
			}
		}
		if !foldsMatch(t, b.String(), w) {
			t.Fatalf("%+q (%s): no fold of %q matches", b.String(), w, CheckFolds(b.String()))
		}
	}
}

// TestCH12CheckFoldsWindowed: a long text is folded in windows, so no
// fold is longer than a window of the most-growing character's fold, and
// a phrase across a window boundary is still whole in one window.
func TestCH12CheckFoldsWindowed(t *testing.T) {
	grow := SkeletonFold("ﷺ", false)
	long := strings.Repeat("ﷺ", 50*skelWindow)
	for _, f := range CheckFolds(long) {
		if len(f) > skelWindow*len(grow) {
			t.Fatalf("a fold of %d bytes, window bound %d", len(f), skelWindow*len(grow))
		}
	}
	for _, at := range []int{skelWindow - 3, 2*(skelWindow-skelOverlap) - 2, 3*skelWindow + 1} {
		s := strings.Repeat("x ", at/2) + "ΥΕЅ Α7 " + strings.Repeat("x ", 2*skelWindow)
		re := regexp.MustCompile(FoldPattern("YES A7"))
		held := false
		for _, f := range CheckFolds(s) {
			held = held || re.MatchString(f)
		}
		if !held {
			t.Errorf("phrase at rune %d not caught", at)
		}
	}
}
