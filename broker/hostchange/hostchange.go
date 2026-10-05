// Package hostchange is HW-8's list of everything an AgentOS session may
// change on the host PC: the firmware-level changes the box cannot avoid
// and discloses. The owner's guide (docs/owners-guide.md) lists each one
// in plain words under ChangesHeading, and the list there is the whole of
// it; HOST-1e's acceptance check diffs a host's UEFI variables and TPM NV
// indices against it.
package hostchange

// Kind is where on the host a change lives.
type Kind string

const (
	UEFI    Kind = "uefi"    // a persistent UEFI variable
	TPM     Kind = "tpm"     // TPM non-volatile state
	Windows Kind = "windows" // what Windows does at its next start
)

// Change is one disclosed change. ID is the marker the guide carries
// (<!-- host-change: ID -->) beside the plain-words item.
type Change struct {
	ID   string
	Kind Kind
}

// All is the whole list (HW-8).
var All = []Change{
	// The boot order, only if the owner changes it; the card's one-time
	// boot key leaves it alone (HW-6).
	{"boot-order", UEFI},
	// systemd-boot's LoaderSystemToken, unless the image turns it off
	// (P2-1 decides).
	{"loader-system-token", UEFI},
	// A persistent storage root key at the standard handle, if the TPM
	// holds none and the image's TPM setup creates one (P2-1). The
	// broker's own SRK is transient.
	{"tpm-srk", TPM},
	// On a trusted PC, one NV counter per vault (V6 rollback counter,
	// tpmseal/counter.go). Nothing undefines them, so they stay after the
	// drive is gone and accumulate with each vault trusted on the PC.
	{"tpm-vault-counter", TPM},
	// When a boot PIN is turned on: the lockout authorization and the
	// dictionary-attack settings, held while the PIN is on; turning it
	// off gives the authorization back (empty) and restores the PC's own
	// settings, kept in the vault (D7, HOST-1f; tpmseal TakeLockout,
	// ReleaseLockout, RestoreDA).
	{"tpm-lockout", TPM},
	// shim's SBAT revocation level (SbatLevel), written when the shim on
	// the drive carries a newer revocation policy than the PC (shim 15.7
	// and later); it can stop older Linux boot media on that PC.
	{"sbat-level", UEFI},
	// A possible Windows recovery-key prompt at the next Windows start.
	{"windows-recovery-prompt", Windows},
}

// Headings of the owner's guide sections this package pins.
const (
	StartHeading          = "Starting AgentOS on your PC"
	ChangesHeading        = "What AgentOS changes on your PC"
	RecoveryPromptHeading = "If Windows asks for a recovery key"
)
