package recovery

// NeedsBackupAfterKeyChange reports whether a recovery-key change should
// start a backup at once (BAK-1 potency PB2 on #80): the owner has chosen
// a second drive or upload destination. Wiring calls Backup after the key
// change when this is true. Choosing none or leaving the choice unchosen
// does not start a backup.
func NeedsBackupAfterKeyChange(c BackupChoice) bool {
	switch c.Kind {
	case BackupDrive, BackupUpload:
		return c.Destination != ""
	default:
		return false
	}
}
