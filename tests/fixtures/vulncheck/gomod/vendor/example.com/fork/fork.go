// Package fork is a planted directory-replaced module, as broker/third_party/go-imap is:
// govulncheck sees no version for it, so the control's OSV entry against its required
// release (v1.2.1) must be caught by the fork scan.
package fork

// Use does nothing.
func Use() {}
