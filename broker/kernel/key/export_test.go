package key

// ParseCode is the declared code named n, or the zero Code for "".
func ParseCode(n string) (c Code, err error) {
	err = c.UnmarshalText([]byte(n))
	return c, err
}
