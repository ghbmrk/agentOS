package recovery

import (
	"errors"
	"strings"
	"testing"
)

// REQ: BAK-1
func TestBackupDestinationRuneLimitAndSingleScript(t *testing.T) {
	if err := validName(strings.Repeat("a", 201)); err == nil {
		t.Fatal("201 runes accepted")
	}
	if err := validName(strings.Repeat("a", 200)); err != nil {
		t.Fatalf("200 runes: %v", err)
	}
	// Latin letter + Cyrillic look-alike (U+0430)
	if err := validName("nas а"); err == nil {
		t.Fatal("mixed scripts accepted")
	}
	if err := validName("USB stick SANDISK-1"); err != nil {
		t.Fatalf("plain name: %v", err)
	}
	x := newBox(t)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aaaaaaaaaaaaaaaaaa"
	if _, err := ChooseBackup(x.b, BackupChoice{Kind: BackupUpload, Destination: jwt}, tier4, t0); !errors.Is(err, ErrBadBackupChoice) {
		t.Fatalf("JWT destination: %v", err)
	}
}
