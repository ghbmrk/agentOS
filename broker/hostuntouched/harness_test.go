package hostuntouched

import "testing"

// REQ: HOST-1e, HW-8, A1

func TestHOST1eHarnessHashesAgainstAllowList(t *testing.T) {
	disk := Hash([]byte("windows-like-second-disk"))
	before := Snapshot{
		Disk2SHA256: disk,
		RTC:         "2026-10-07T12:00:00Z",
		UEFIVars:    map[string]string{"BootOrder": Hash([]byte("0001,0002")), "LoaderSystemToken": Hash([]byte("tok"))},
		TPMNV:       map[uint32]string{0x1500016: Hash([]byte("other")), 0x1c10100: Hash([]byte("vault"))},
	}
	after := before
	after.Disk2SHA256 = Hash([]byte("tampered"))
	diffs := Check(before, after, AllowList{TPMNVIndices: []uint32{0x1c10100}}, true)
	if len(diffs) != 1 || diffs[0].What != "2nd disk" {
		t.Fatalf("disk: %v", diffs)
	}
	after = before
	after.UEFIVars = map[string]string{"BootOrder": Hash([]byte("changed")), "LoaderSystemToken": before.UEFIVars["LoaderSystemToken"]}
	diffs = Check(before, after, AllowList{}, true)
	if len(diffs) != 1 || diffs[0].What != "UEFI BootOrder" {
		t.Fatalf("uefi: %v", diffs)
	}
	after = before
	after.TPMNV = map[uint32]string{0x1500016: before.TPMNV[0x1500016], 0x1c10100: Hash([]byte("vault-rotated"))}
	diffs = Check(before, after, AllowList{TPMNVIndices: []uint32{0x1c10100}}, true)
	if len(diffs) != 0 {
		t.Fatalf("vault NV should be allowed: %v", diffs)
	}
	after = Snapshot{
		Disk2SHA256: before.Disk2SHA256, RTC: before.RTC,
		UEFIVars: before.UEFIVars,
		TPMNV: map[uint32]string{0x1500016: Hash([]byte("evil")), 0x1c10100: before.TPMNV[0x1c10100]},
	}
	diffs = Check(before, after, AllowList{TPMNVIndices: []uint32{0x1c10100}}, true)
	if len(diffs) != 1 || diffs[0].What != "TPM NV 0x1500016" {
		t.Fatalf("foreign NV: %v", diffs)
	}
}
