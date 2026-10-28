package loops

// PlainName is the owner's name for f's subject and whether the plain-name
// map has one (P3-4b-3c).
func PlainName(f Finding) (string, bool) { return plainName(f) }
