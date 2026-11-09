package kernel

// SendCheck is sendCheck, for the external tests.
var SendCheck = sendCheck

// Emit logs an entry as the kernel would, for the tests that need a log
// shape the kernel no longer writes.
func Emit(k *Kernel, now int64, typ string, body any) error {
	_, err := k.emit(now, typ, body)
	return err
}
