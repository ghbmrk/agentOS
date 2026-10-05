package owner

import "time"

// MatchTOTP checks a code-generator code the way the channel does (O6): the
// current 30-second step or the one before, never at or before after (the
// last step accepted). It returns the step that matched. The vault process
// uses it to authorize an unknown-host unlock (CRED-8), where the seed is
// readable only once the vault is open.
func MatchTOTP(seed []byte, code string, now time.Time, after int64) (int64, bool) {
	if len(seed) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpStep
	for _, s := range []int64{cur, cur - 1} {
		if s > after && eq(code, hotp(seed, uint64(s))) {
			return s, true
		}
	}
	return 0, false
}
