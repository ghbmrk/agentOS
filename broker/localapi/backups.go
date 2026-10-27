package localapi

// Backup ops (BAK-1, BAK-2; MIG-4-recovery-e4b): the Backups page lists
// the destinations the kernel holds with the only-copy notice, adds a
// second local drive on a hardware key's tap, and stops one with no tap.
// agentosd serves them only with -passkey-rp-id, as the passkey ops
// (localsrv Config.Backups), since the tap is a WebAuthn ceremony on the
// page's name. Each needs a session. The page sends only the destination
// the owner typed and what the ceremony returned; agentosd builds the
// cosign, and the kernel decides it.
const (
	// OpBackups (Auth) answers a BackupChoice.
	OpBackups = "page_backups"
	// OpBackupBegin (BackupBegin) takes the destination to add and
	// answers a BackupBegun: the challenge a hardware key signs to add it
	// as the N-th destination. Nothing is kept.
	OpBackupBegin = "page_backup_begin"
	// OpBackupAdd (BackupAdd) takes the same destination, that N and the
	// hardware key's get() assertion over the challenge, and answers
	// Text{} once the kernel has logged it.
	OpBackupAdd = "page_backup_add"
	// OpBackupRemove (BackupRemove) stops new backups to a listed
	// destination and answers Text{}; it narrows, so it needs no tap.
	OpBackupRemove = "page_backup_remove"
)

// BackupOps lists the backup ops, for the disjointness test.
var BackupOps = []string{OpBackups, OpBackupBegin, OpBackupAdd, OpBackupRemove}

// The backup ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs and
// ErrLimited. No kernel text reaches the page: every other failure is
// ErrBackupUnavailable.
const (
	// ErrBackupNotAnchor: the tap was a phone passkey's, and only a
	// hardware key adds a destination (a widening).
	ErrBackupNotAnchor = "backup not anchor"
	// ErrBackupBadAssertion: no listed key made that tap over this add's
	// challenge.
	ErrBackupBadAssertion = "backup bad assertion"
	// ErrBackupPlace: the kernel cannot use that destination: not a
	// directory it can reach, inside its own data, or out of shape.
	ErrBackupPlace = "backup place"
	// ErrBackupNameTaken: a destination of that name exists, or did.
	ErrBackupNameTaken = "backup name taken"
	// ErrBackupStale: the page's list is out of date (a destination was
	// added or removed since it was shown).
	ErrBackupStale = "backup stale"
	// ErrBackupSetup: the kernel is waiting for setup.
	ErrBackupSetup = "backup setup"
	// ErrBackupUnavailable: the kernel could not be reached, or answered
	// something else.
	ErrBackupUnavailable = "backup unavailable"
)

// BackupCodes is the closed set the backup ops refuse with past the
// session and argument checks.
var BackupCodes = []string{ErrBackupNotAnchor, ErrBackupBadAssertion, ErrBackupPlace, ErrBackupNameTaken,
	ErrBackupStale, ErrBackupSetup, ErrBackupUnavailable}

// Bounds on the backup frames: the kernel's (kernel.MaxTargetName,
// kernel.MaxLocator), which localapi does not link.
const (
	MaxBackupName    = 64
	MaxBackupLocator = 1024
	// MaxBackupN bounds the destination count an add names.
	MaxBackupN = 1 << 16
)

// BackupKindDir is a mounted directory, such as a second local drive
// (kernel.KindDir); the storage adapter row adds its kind.
const BackupKindDir = "dir"

// BackupPlace is one destination as the owner adds it and the page lists
// it: what the hardware key signs.
type BackupPlace struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Locator    string `json:"locator"`
	AppendOnly bool   `json:"append_only"`
	// Newest is when its newest backup that counts was taken; zero when
	// none counts. Listed only.
	Newest int64 `json:"newest,omitempty"`
}

// BackupChoice is the Backups page: the notice as STATUS has it, the
// current destinations, and the names of those that keep no old copies
// (not append-only), which a hacked box could wipe (BAK-2).
type BackupChoice struct {
	Lines    []string      `json:"lines"`
	Places   []BackupPlace `json:"places"`
	Wipeable []string      `json:"wipeable"`
	// NoKey: the kernel holds no backup recipient, so no backup can start.
	NoKey bool `json:"no_key,omitempty"`
}

// BackupBegin carries the destination to add.
type BackupBegin struct {
	Token string      `json:"token"`
	Place BackupPlace `json:"place"`
}

// BackupBegun is the challenge for the hardware key's get(), over adding
// the place as destination N (the count the kernel has added so far).
type BackupBegun struct {
	N         int    `json:"n"`
	Challenge []byte `json:"challenge"`
}

// BackupAdd carries the begun destination, its N, and the hardware key's
// get() assertion as the browser returned it.
type BackupAdd struct {
	Token             string      `json:"token"`
	Place             BackupPlace `json:"place"`
	N                 int         `json:"n"`
	AuthenticatorData []byte      `json:"authenticator_data"`
	ClientDataJSON    []byte      `json:"client_data_json"`
	Signature         []byte      `json:"signature"`
}

// BackupRemove names a listed destination.
type BackupRemove struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}
