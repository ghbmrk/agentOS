package pacingfile

// TemporaryState describes observed bytes only, never accounting validity,
// freshness, lineage or permission for removal, recovery or restart.
type TemporaryState string

const (
	TemporaryAbsent    TemporaryState = "absent"
	TemporaryDuplicate TemporaryState = "duplicate"
	TemporaryDifferent TemporaryState = "different"
)

// TemporaryReport contains bounded sizes and hashes, no image bytes or paths.
// The observed temporary digest must never become a ledger trust anchor.
type TemporaryReport struct {
	State                         TemporaryState
	LedgerDigest, TemporaryDigest [32]byte
	LedgerBytes, TemporaryBytes   int
}
