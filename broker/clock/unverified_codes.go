package clock

// UnverifiedCodesText is what owner-facing code refusals say while the
// box clock is not verified (HOST-1b potency C2 / K15). Codes still count
// toward the day's wrong-code budget. Wire at the code-check reply sites.
const UnverifiedCodesText = "My clock isn't set yet, so codes may not work. Open my Wi-Fi page to set it."

// UnverifiedCodesPrefix returns UnverifiedCodesText plus a space when
// verified is false, or "" when the clock is verified.
func UnverifiedCodesPrefix(verified bool) string {
	if verified {
		return ""
	}
	return UnverifiedCodesText + " "
}
