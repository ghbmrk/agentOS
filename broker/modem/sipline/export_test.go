package sipline

// ParseAnswer exposes parseAnswer's verdict to the external tests.
func ParseAnswer(body []byte, private bool) error {
	_, err := parseAnswer(body, private)
	return err
}
