package seal

// StoreKey exposes the store key to the canary test, which must find no
// trace of it on the drive.
func StoreKey(s *Store) []byte { return append([]byte(nil), s.key...) }
