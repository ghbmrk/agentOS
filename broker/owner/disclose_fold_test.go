package owner

// REQ: CH-19, CH-12

import "testing"

func TestCH19SecretShapedOnTheFolds(t *testing.T) {
	for _, s := range []string{
		"Your ΡΙΝ is 4829.",
		"ᏟODE 482913",
		"Your cͅode is 4829",
		"Your ΟΤΡ: 739204",
		"Ⲣass​code 4829",
		"ΜFΑ 739204",
		"ᏢIN 4829",
		"ꓑꓲN 4829",
		"ꓔꓳꓗꓰꓠ 739204",
		"ᏚIGN IN 739204",
		"ᎷFA 739204",
	} {
		if !SecretShaped(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}

func TestCH19FoldsKeepOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"The code book is on the shelf.",
		"Καλημέρα, the code review is at noon.",
		"Room 12, pin the note to the door.",
		"Naïve café, résumé due Monday.",
		"Order 4829 ships Monday.",
	} {
		if SecretShaped(s) {
			t.Errorf("held: %+q", s)
		}
	}
}
