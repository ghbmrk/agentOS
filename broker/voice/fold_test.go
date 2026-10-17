package voice

// REQ: CH-21, CH-12

import "testing"

func TestCH21HoldsOnTheFolds(t *testing.T) {
	for _, s := range []string{
		"ᎷORE A7",
		"YES⠀A7",
		"YͅES A7",
		"ΥΕЅ Α7",
		"ΝΟ Α7",
		"RNORE A7",
		"Send ΥES 4829 now.",
		"The ΡΑЅЅWΟRD is on the card.",
		"Your pass‍code is ready.",
		"rеply yеs to go, оr nо to stop",
	} {
		if !WouldHold(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}

func TestCH21FoldsKeepOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"Naïve café, résumé due Monday.",
		"Καλημέρα, see you in the park.",
		"The pinned note says lunch at noon.",
		"Yes, the hedge is done.",
		"No rush on the hedge.",
	} {
		if WouldHold(s) {
			t.Errorf("held: %+q", s)
		}
	}
}
