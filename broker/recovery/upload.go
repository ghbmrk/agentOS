package recovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
)

// ErrUploadMismatch means the stream's SHA-256 is not the receipt's sum
// (BAK-1 security W1 on #80): the storage adapter must not accept it.
var ErrUploadMismatch = errors.New("recovery: upload bytes do not match the backup receipt")

// AcceptUpload reports whether r's bytes hash to the receipt from
// BackupSum. The storage adapter's egress-checked upload must call this
// (or an equivalent check) before accepting a stream (security W1 on #80).
func AcceptUpload(rc Receipt, r io.Reader) error {
	if len(rc.sum) != sha256.Size {
		return errors.New("recovery: upload needs BackupSum's receipt")
	}
	if r == nil {
		return ErrUploadMismatch
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), rc.sum) {
		return ErrUploadMismatch
	}
	return nil
}
