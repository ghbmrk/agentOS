//go:build race

package run

// raceScale stretches eventually's deadline under the race detector, which
// runs this package's loopback reads several times slower (#3570).
const raceScale = 4
