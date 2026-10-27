package seal

// StoreKey exposes the store key to the canary test, which must find no
// trace of it on the drive.
func StoreKey(s *Store) []byte { return append([]byte(nil), s.key...) }

// FailDirSync makes every directory sync fail until the returned func runs.
func FailDirSync(err error) (restore func()) {
	old := syncDir
	syncDir = func(string) error { return err }
	return func() { syncDir = old }
}

// FailWrite makes every write fail before its rename until the returned
// func runs.
func FailWrite(err error) (restore func()) {
	old := writeTemp
	writeTemp = func(string, []byte) (string, error) { return "", err }
	return func() { writeTemp = old }
}
