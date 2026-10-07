package recovery

import "strings"

// SetupNoBackupClause is the BAK-1 B5 / ONB-3 defaults fragment: setup
// does not ask for a backup choice; its one-line defaults statement
// carries that the drive is the only copy until one is verified.
const SetupNoBackupClause = "No backup yet: this drive is the only copy."

// AppendSetupBackupClause returns defaults with SetupNoBackupClause
// appended once (semicolon-separated), for localui.Config.Defaults.
func AppendSetupBackupClause(defaults string) string {
	defaults = strings.TrimSpace(defaults)
	if strings.Contains(defaults, SetupNoBackupClause) {
		return defaults
	}
	if defaults == "" {
		return SetupNoBackupClause
	}
	return defaults + "; " + SetupNoBackupClause
}
