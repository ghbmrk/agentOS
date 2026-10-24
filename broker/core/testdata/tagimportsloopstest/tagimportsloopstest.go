// Package tagimportsloopstest imports loopstest only under a build tag,
// as a file built with -tags agentos_e2e would; the host build of the
// check does not see the import, so it must read the file anyway.
package tagimportsloopstest
