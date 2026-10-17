package localapi

import (
	"fmt"
	"strings"
	"testing"
)

// REQ: CH-1, CH-12, ONB-6

// REQ: P2-2w-c4c-s2-2
func TestSetupTextAllowsOnlySetupsFixedTexts(t *testing.T) {
	for _, s := range []string{
		"agentOS setup code: 123456. Type it on the setup page.",
		"AgentOS page code: 000001. Type it on the setup page.",
		"agentOS is running on this PC. This is your box's number; save it as agentOS.",
		"agentOS is running on this PC. This is your box's number; save it as agentOS. Page code: 654321.",
		// The PC's name and RAM (P2-2w c4d, §8.1).
		"agentOS is running on Intel(R) Client Systems NUC13ANHi5, 8 GB. This is your box's number; save it as agentOS.",
		"agentOS is running on a PC with 16 GB. This is your box's number; save it as agentOS.",
		"Could not save your number. Try again.",
	} {
		if !SetupText(s) {
			t.Errorf("SetupText(%q) = false", s)
		}
	}
	for _, s := range []string{
		"",
		"agentOS setup code: 12345. Type it on the setup page.",
		"agentOS setup code: 1234567. Type it on the setup page.",
		"agentOS setup code: 123456. Type it on the setup page. Visit http://x.example",
		"hello",
		// A wrong PAIR code gets no reply (P2-2w c4c s2, #1290).
		"That pairing code did not match. Check the setup page.",
		"Could not save your number. Try again.\nhttp://x.example",
		"agentOS is running on evil.example. This is your box's number; save it as agentOS.",
		"agentOS is running on http://x. This is your box's number; save it as agentOS.",
		"agentOS is running on x/y. This is your box's number; save it as agentOS.",
		// Each excluded host character on its own: no '.', '/' or ':'.
		"agentOS is running on tel:5550100. This is your box's number; save it as agentOS.",
		"agentOS is running on -x. This is your box's number; save it as agentOS.",
		"agentOS is running on " + strings.Repeat("a", SetupHostMax+1) + ". This is your box's number; save it as agentOS.",
	} {
		if SetupText(s) {
			t.Errorf("SetupText(%q) = true", s)
		}
	}
}

func TestSetupTextTypesKeepNumbersAndTextsOutOfLogs(t *testing.T) {
	for _, v := range []any{SetupSend{To: "+15550000101", Text: "canary-text"}, SetupInbound{From: "+15550000101", Text: "canary-text"}} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
			s := fmt.Sprintf(f, v)
			if strings.Contains(s, "+1555") || strings.Contains(s, "canary") {
				t.Errorf("%s of %T shows its contents: %q", f, v, s)
			}
		}
	}
}
