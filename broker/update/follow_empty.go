package update

import "bytes"

// EmptyFollowNameOK reports whether FollowRoot may take an empty name
// (switch back to the project's own chain). OSS-10w WF1: only after the
// root's root-role keys match the root the image ships (same key set).
// Byte-identical roots also pass. The caller still passes Options.Now from
// the HOST-1b clock guard (WF2) and a P2-2w L1 session token (WF3).
func EmptyFollowNameOK(root, imageRoot []byte) (bool, error) {
	if len(root) == 0 || len(imageRoot) == 0 {
		return false, nil
	}
	if bytes.Equal(root, imageRoot) {
		return true, nil
	}
	m, err := verifyRoot(root, Options{})
	if err != nil {
		return false, err
	}
	img, err := verifyRoot(imageRoot, Options{})
	if err != nil {
		return false, err
	}
	return rootKeysWithin(m, img) && rootKeysWithin(img, m), nil
}
