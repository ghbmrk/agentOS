package localapi

import (
	"fmt"
	"strings"
	"testing"
)

// REQ: CH-1, CH-12, ONB-6

func TestSetupTextAllowsOnlySetupsFixedTexts(t *testing.T) {
	for _, s := range []string{
		"agentOS setup code: 123456. Type it on the setup page.",
		"AgentOS page code: 000001. Type it on the setup page.",
		"agentOS is running on this PC. This is your box's number; save it as agentOS.",
		"agentOS is running on this PC. This is your box's number; save it as agentOS. Page code: 654321.",
		"That pairing code did not match. Check the setup page.",
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
		"Could not save your number. Try again.\nhttp://x.example",
		"agentOS is running on evil.example. This is your box's number; save it as agentOS.",
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
