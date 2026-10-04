package owner

import "testing"

// REQ: CH-19, CRED-3

// Canary values below are synthetic, built to match each format.
func TestSecretShapedCatchesTokensAndAnchoredCodes(t *testing.T) {
	hits := []string{
		"Your verification code is 482913.",
		"482913 is your Acme code",
		"Use PIN 7319 at the door",
		"OTP: G-482913",
		"login code A1B2C3 expires soon",
		"key AKIA" + "ABCDEFGHIJKLMNOP",
		"token ghp_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sk-" + "ant-api03-canarycanarycanarycanary",
		"xoxb-" + "1234567890-canary",
		"eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"otpauth://totp/x?secret=CANARY",
		"code ⁴⁸²⁹¹³",
		"𝐜𝐨𝐝𝐞 482913",
		"Use 482913 to sign in",
	}
	for _, s := range hits {
		if !SecretShaped(s) {
			t.Errorf("missed: %q", s)
		}
		if Disclose(s) != Hidden {
			t.Errorf("not hidden: %q", s)
		}
	}
	passes := []string{
		"Invoice 482913 paid, $1,250.00 on 2026-10-04.",
		"Order #A1B2C3 ships Friday.",
		"Meeting moved to 14:30 on 10/12.",
		"The code review is done.",
		"Reply with the code from your code generator.",
	}
	for _, s := range passes {
		if SecretShaped(s) {
			t.Errorf("false positive: %q", s)
		}
		if Disclose(s) != s {
			t.Errorf("changed: %q", s)
		}
	}
}
