package recovery

import (
	"strings"
	"testing"
)

// REQ: BAK-1, ONB-3
func TestBAK1setupDefaultsCarryOnlyCopy(t *testing.T) {
	if AppendSetupBackupClause("") != SetupNoBackupClause {
		t.Fatal(AppendSetupBackupClause(""))
	}
	got := AppendSetupBackupClause("spend cap $20 a day")
	if !strings.Contains(got, "spend cap") || !strings.Contains(got, SetupNoBackupClause) {
		t.Fatalf("got %q", got)
	}
	if AppendSetupBackupClause(got) != got {
		t.Fatal("appended twice")
	}
}
