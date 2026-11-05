package voice

// REQ: CH-21

import "testing"

func TestOrdinaryWordsAreNotTheVocabulary(t *testing.T) {
	for _, s := range []string{
		"I will encode the file names.",
		"The pinned note says lunch at noon.",
		"The cellar door is open.",
		"See you at 3.",
		"The gardener finished the hedge.",
		"Footnote 12 is about the hedge.",
	} {
		if WouldHold(s) {
			t.Fatalf("held ordinary text: %q", s)
		}
	}
}

func TestTheSpecVocabularyAndTheReplyGrammarHold(t *testing.T) {
	for _, s := range []string{
		"I fixed the code.",
		"Use cell B2 of the sheet.",
		"The password is on the card.",
		"The verification of the backup finished.",
		"Meet at the grid south of the park.",
		"The code generator is in the drawer.",
		"That was a one-time exception.",
		"Reply YES K7 482913 or NO K7.",
		"YES 482913",
	} {
		if !WouldHold(s) {
			t.Fatalf("not held: %q", s)
		}
	}
}

// The benign set is ordinary owner-task text. The hold count is the
// measurement: it changes only when the check changes. "I dig it" went
// through once a split needed a letter run or a seam (#4019); "Pass word
// to Sam" is still held by rule (b)'s space seam, which Security
// decides on #4019.
func TestBenignTaskTextIsMeasured(t *testing.T) {
	benign := []string{
		"I fixed the code and pushed the branch.",
		"Put the total in cell B2.",
		"The wifi password is on the card, not in the chat.",
		"Lunch is at noon in the park.",
		"Please encode the attachment as plain text.",
		"I dig it.",
		"Pass word to Sam.",
	}
	held, total := Count(benign)
	if total != 7 || held != 4 {
		t.Fatalf("held %d of %d, want 4 of 7", held, total)
	}
}
