package vault

// InjectSealFault makes every slot change fail with err just after the
// next keys file is sealed, the point from which the change is decided
// (ErrSlotDecided). It is for tests of callers in other packages, which
// cannot reach the vault's write path. restore removes the fault.
func InjectSealFault(err error) (restore func()) {
	crashPoint = func(step int) error {
		if step == crashKeysSealed {
			return err
		}
		return nil
	}
	return func() { crashPoint = func(int) error { return nil } }
}
