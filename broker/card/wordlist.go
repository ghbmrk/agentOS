package card

import (
	_ "embed"
	"strings"
)

// effLarge is EFF's large wordlist (7,776 words, five dice per word),
// byte-identical to eff_large_wordlist.txt as EFF publishes it; a test pins
// its SHA-256. Licensed CC BY 3.0 US by the Electronic Frontier Foundation:
// https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
//
//go:embed eff_large_wordlist.txt
var effLarge []byte

var (
	words     []string
	wordIndex = map[string]int{}
)

func init() {
	for _, line := range strings.Split(strings.TrimSpace(string(effLarge)), "\n") {
		if _, w, ok := strings.Cut(line, "\t"); ok {
			wordIndex[w] = len(words)
			words = append(words, w)
		}
	}
}
