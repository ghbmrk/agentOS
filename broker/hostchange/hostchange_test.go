package hostchange

// REQ: HW-8, ONB-7

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const guidePath = "../../docs/owners-guide.md"

func readGuide(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// section returns the text under the "## title" heading, up to the next
// heading of that level.
func section(t *testing.T, guide, title string) string {
	t.Helper()
	_, rest, ok := strings.Cut(guide, "\n## "+title+"\n")
	if !ok {
		t.Fatalf("guide has no section %q", title)
	}
	body, _, _ := strings.Cut(rest, "\n## ")
	return body
}

var marker = regexp.MustCompile(`<!-- host-change: ([a-z0-9-]+) -->`)

// HW-8: the owner's guide lists every change the box may make on the
// host, and that list is the whole of it: each change in All appears once
// in the guide's list, and the guide lists nothing else.
func TestGuideListsEveryHostChange(t *testing.T) {
	guide := readGuide(t)
	list := section(t, guide, ChangesHeading)
	seen := map[string]int{}
	for _, m := range marker.FindAllStringSubmatch(guide, -1) {
		seen[m[1]]++
	}
	inList := map[string]int{}
	for _, m := range marker.FindAllStringSubmatch(list, -1) {
		inList[m[1]]++
	}
	ids := map[string]bool{}
	for _, c := range All {
		if ids[c.ID] {
			t.Fatalf("change %s listed twice in All", c.ID)
		}
		ids[c.ID] = true
		if c.Kind != UEFI && c.Kind != TPM && c.Kind != Windows {
			t.Errorf("change %s has kind %q", c.ID, c.Kind)
		}
		if seen[c.ID] != 1 || inList[c.ID] != 1 {
			t.Errorf("change %s appears %d times in the guide, %d in its list", c.ID, seen[c.ID], inList[c.ID])
		}
	}
	for id := range seen {
		if !ids[id] {
			t.Errorf("guide lists %s, which is not in All", id)
		}
	}
	if len(All) == 0 {
		t.Fatal("no changes")
	}
	if !strings.Contains(list, "This is the whole list.") {
		t.Error("the list does not say it is the whole of what changes")
	}
}

// HW-8: BitLocker is named only where it is the problem: the section the
// box answers from when the owner asks about a recovery-key prompt. That
// answer gives where the key is, for a home and a work PC, and keeps the
// Windows key apart from the box's own recovery key.
func TestBitLockerOnlyInTheRecoveryPromptAnswer(t *testing.T) {
	guide := readGuide(t)
	answer := section(t, guide, RecoveryPromptHeading)
	rest := strings.Replace(guide, answer, "", 1)
	if strings.Contains(strings.ToLower(rest), "bitlocker") {
		t.Error("guide mentions BitLocker outside the recovery-prompt answer")
	}
	for _, want := range []string{"aka.ms/myrecoverykey", "Microsoft account", "IT department",
		"not the recovery key on your AgentOS card", "BitLocker"} {
		if !strings.Contains(answer, want) {
			t.Errorf("recovery-prompt answer lacks %q", want)
		}
	}
}

// HW-8: the box never needs Secure Boot off or a change in firmware
// settings; it starts from the one-time boot menu key.
func TestGuideStartsWithTheOneTimeBootKey(t *testing.T) {
	guide := readGuide(t)
	start := section(t, guide, StartHeading)
	for _, want := range []string{"one-time", "boot key", "never need to turn Secure Boot off",
		"never need to change your PC's settings"} {
		if !strings.Contains(start, want) {
			t.Errorf("start section lacks %q", want)
		}
	}
	low := strings.ToLower(guide)
	for _, bad := range []string{"disable secure boot", "turn off secure boot",
		"change the boot order", "enter the bios", "bios setup", "uefi setup"} {
		if strings.Contains(low, bad) {
			t.Errorf("guide tells the owner to %q", bad)
		}
	}
}
