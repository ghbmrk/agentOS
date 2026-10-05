package sipline

// ParseAnswer exposes parseAnswer's verdict to the external tests.
func ParseAnswer(body []byte, private bool) error {
	_, err := parseAnswer(body, private)
	return err
}

// ParseOffer exposes parseOffer's verdict and the tag to echo.
func ParseOffer(body []byte, private bool) (string, error) {
	a, err := parseOffer(body, private)
	return a.tag, err
}
