package recovery

import "testing"

// REQ: BAK-1
func TestBAK1pb2NeedsBackupAfterKeyChange(t *testing.T) {
	if NeedsBackupAfterKeyChange(BackupChoice{}) {
		t.Fatal("unchosen")
	}
	if NeedsBackupAfterKeyChange(BackupChoice{Kind: BackupNone}) {
		t.Fatal("none")
	}
	if NeedsBackupAfterKeyChange(BackupChoice{Kind: BackupDrive}) {
		t.Fatal("drive without destination")
	}
	if !NeedsBackupAfterKeyChange(BackupChoice{Kind: BackupDrive, Destination: "USB stick A"}) {
		t.Fatal("drive with destination")
	}
	if !NeedsBackupAfterKeyChange(BackupChoice{Kind: BackupUpload, Destination: "Home NAS"}) {
		t.Fatal("upload with destination")
	}
}
