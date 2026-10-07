package update

// FirstBoot holds AI/account connect steps until a verified stable release
// is active (UPD-3 / UPD-b). Offline first boot runs the preloaded image.
type FirstBoot struct {
	// StableActive is true once a verified stable release is the running image.
	StableActive bool
	// Online is true when the box can reach a mirror.
	Online bool
	// Preloaded is true when the image on the drive is the factory preload.
	Preloaded bool
}

// HoldConnect is true while setup must not connect AI or personal accounts.
func (f FirstBoot) HoldConnect() bool {
	return !f.StableActive
}

// StatusLine is STATUS / local UI wording while updating first.
func (f FirstBoot) StatusLine() string {
	if f.StableActive {
		return ""
	}
	if !f.Online && f.Preloaded {
		return "Updating first: running the preloaded image offline. Will update when next online. AI and accounts stay disconnected until then."
	}
	return "Updating first: waiting for a verified stable release before connecting AI or accounts."
}
